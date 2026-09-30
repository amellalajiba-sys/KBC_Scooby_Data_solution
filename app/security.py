"""Authentication, authorisation and cross-cutting protections.

- Passwords: PBKDF2-HMAC-SHA256, 200,000 iterations, random salt, constant-time comparison.
- Session: HS256 JWT signed with SECRET_KEY (environment), short-lived, sent in the Authorization header
  (no cookie -> no CSRF).
- The customer's identity ALWAYS comes from the token, never from a URL parameter or the request body.
- Login attempts are rate-limited per IP and per username.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import settings
from app.db import get_conn

PBKDF2_ITERATIONS = 200_000
_bearer = HTTPBearer(auto_error=False)
# Dummy hash so that verification takes the same time when the user does not exist
_DUMMY_HASH: str | None = None


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return "pbkdf2_sha256${}${}${}".format(
        PBKDF2_ITERATIONS, base64.b64encode(salt).decode(), base64.b64encode(digest).decode()
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iterations, salt_b64, digest_b64 = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), base64.b64decode(salt_b64), int(iterations))
        return hmac.compare_digest(digest, base64.b64decode(digest_b64))
    except (ValueError, TypeError):
        return False


def dummy_verify(password: str) -> None:
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password(secrets.token_urlsafe(16))
    verify_password(password, _DUMMY_HASH)


@dataclass(frozen=True)
class Principal:
    username: str
    role: str
    customer_id: str | None


def create_token(user: Principal) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user.username,
        "role": user.role,
        "cid": user.customer_id,
        "iat": now,
        "exp": now + timedelta(minutes=settings.token_ttl_minutes),
        "jti": secrets.token_hex(8),
    }
    return jwt.encode(payload, settings.secret_key, algorithm="HS256")


def _unauthorized() -> HTTPException:
    return HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required", headers={"WWW-Authenticate": "Bearer"})


def current_principal(creds: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> Principal:
    if creds is None or creds.scheme.lower() != "bearer":
        raise _unauthorized()
    try:
        payload = jwt.decode(creds.credentials, settings.secret_key, algorithms=["HS256"],
                             options={"require": ["exp", "sub", "role"]})
    except jwt.PyJWTError:
        raise _unauthorized()
    # The account must still exist with the same role (deleting the user revokes the token)
    with get_conn() as conn:
        row = conn.execute("SELECT username, role, customer_id FROM users WHERE username = ?", (payload["sub"],)).fetchone()
    if row is None or row["role"] != payload["role"] or row["customer_id"] != payload.get("cid"):
        raise _unauthorized()
    return Principal(row["username"], row["role"], row["customer_id"])


def require_customer(p: Principal = Depends(current_principal)) -> Principal:
    if p.role != "customer" or not p.customer_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Customers only")
    return p


def require_advisor(p: Principal = Depends(current_principal)) -> Principal:
    if p.role != "advisor":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Advisors only")
    return p


class LoginRateLimiter:
    """In-memory sliding window (enough for a single-instance PoC; Redis in production)."""

    def __init__(self, max_attempts: int, window_seconds: int, max_keys: int = 10_000) -> None:
        self.max_attempts = max_attempts
        self.window = window_seconds
        self.max_keys = max_keys
        self._hits: dict[str, deque[float]] = {}
        self._access_order: deque[str] = deque()  # Track key access order for LRU eviction
        self._lock = threading.Lock()

    def _evict_lru_if_needed(self) -> None:
        """Evict least-recently-used keys when max_keys limit is reached."""
        while len(self._hits) >= self.max_keys and self._access_order:
            lru_key = self._access_order.popleft()
            # Key might have been removed already or accessed again
            if lru_key in self._hits:
                # Only evict if this key is not at the end of access_order (not recently used)
                # Check if any timestamps are still within the window
                now = time.monotonic()
                q = self._hits[lru_key]
                while q and now - q[0] > self.window:
                    q.popleft()
                # Remove if empty or evict anyway to enforce limit
                if not q or len(self._hits) >= self.max_keys:
                    self._hits.pop(lru_key, None)

    def _touch_key(self, key: str) -> None:
        """Mark a key as recently accessed for LRU tracking."""
        # Remove key from its current position if present
        try:
            self._access_order.remove(key)
        except ValueError:
            pass
        # Add to end (most recently used)
        self._access_order.append(key)

    def check(self, *keys: str) -> None:
        now = time.monotonic()
        with self._lock:
            for key in keys:
                # Get or create the deque for this key
                if key not in self._hits:
                    self._evict_lru_if_needed()
                    self._hits[key] = deque()
                
                q = self._hits[key]
                self._touch_key(key)
                
                # Prune expired timestamps
                while q and now - q[0] > self.window:
                    q.popleft()
                
                # Remove empty entries to free memory
                if not q:
                    self._hits.pop(key, None)
                    try:
                        self._access_order.remove(key)
                    except ValueError:
                        pass
                elif len(q) >= self.max_attempts:
                    raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts, try again later")

    def fail(self, *keys: str) -> None:
        now = time.monotonic()
        with self._lock:
            for key in keys:
                if key not in self._hits:
                    self._evict_lru_if_needed()
                    self._hits[key] = deque()
                self._hits[key].append(now)
                self._touch_key(key)

    def reset(self, *keys: str) -> None:
        with self._lock:
            for key in keys:
                self._hits.pop(key, None)
                try:
                    self._access_order.remove(key)
                except ValueError:
                    pass


login_limiter = LoginRateLimiter(settings.login_max_attempts, settings.login_window_seconds)


def client_ip(request: Request) -> str:
    # X-Forwarded-For is NOT trusted (it can be forged) unless a reverse proxy is configured
    return request.client.host if request.client else "unknown"
