"""100% synthetic data generator (no real data from KBC or from any customer).

8 demo personas, each built to illustrate one precise decision of the engine, and one per channel:

  emma     Young couple, baby on the way             -> PROPOSE     (family insurance + child savings) · app
  sofia    Same baby signal + financial stress       -> ACCOMPANY   (no sales, advisor)               · human
  jan      Grandparents, low digital                 -> INFORM      (grandchild savings)              · voice
  marcel   Senior, suspicious transfer in progress   -> PROTECT     (10-minute pause, fraud review)   · voice
  lucas    Overdraft likely, does not open the app   -> PROTECT     (overdraft alert)                 · push
  yasmine  First salary                              -> INFORM      (50/30/20 rule)                   · app
  thomas   Stable situation                          -> ABSTAIN     (and say so)                      · app
  nina     Abandoned loan simulation                 -> SIMPLIFY    (resume, credit = human)          · app
  advisor  Advisor account (task queue, appointments, dashboard)

Usage:  python -m data.generate                         (creates / resets moments.db)
        DEMO_PASSWORD in .env or in the environment     (shared password for the demo)
"""
from __future__ import annotations

import os
import random
import secrets
import sys
from datetime import date, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.config import settings  # noqa: E402
from app.db import get_conn, init_db  # noqa: E402
from app.security import hash_password  # noqa: E402

rng = random.Random(42)
NOW: datetime = settings.demo_now
TODAY: date = NOW.date()
ADVISOR = "advisor"


def months_back(n: int) -> list[tuple[int, int]]:
    """The last n complete months + the current month, oldest to newest."""
    y, m = TODAY.year, TODAY.month
    out = [(y, m)]
    for _ in range(n):
        m -= 1
        if m == 0:
            y, m = y - 1, 12
        out.append((y, m))
    return list(reversed(out))


MONTHS = months_back(7)


def d(y: int, m: int, day: int) -> str:
    return date(y, m, min(day, 28)).isoformat()


class Builder:
    def __init__(self) -> None:
        self.customers: list[tuple] = []
        self.tx: list[tuple] = []
        self.events: list[tuple] = []
        self.products: list[tuple] = []
        self.pending: list[tuple] = []
        self.users: list[tuple[str, str, str | None]] = []
        self.slots: list[tuple[str, str]] = []

    def customer(self, cid, display, first, age, status, household, city, digital, opening, persona, username, lang="en"):
        self.customers.append((cid, display, first, age, status, household, city, lang, digital, opening, persona))
        self.users.append((username, "customer", cid))

    def t(self, cid, day: str, amount, category, label, counterparty=""):
        if day <= TODAY.isoformat():
            self.tx.append((cid, day, round(amount, 2), category, label, counterparty))

    def ev(self, cid, ts: datetime, screen, action="view"):
        self.events.append((cid, ts.isoformat(), screen, action))

    def monthly(self, cid, day, amount, category, label, counterparty="", months=MONTHS):
        for (y, m) in months:
            self.t(cid, d(y, m, day), amount, category, label, counterparty)

    def groceries(self, cid, per_week, months=MONTHS):
        for (y, m) in months:
            for wk in (4, 11, 18, 25):
                self.t(cid, d(y, m, wk), -per_week * rng.uniform(0.85, 1.15), "groceries", "Supermarket", "")


def build() -> Builder:
    b = Builder()
    full = MONTHS[:-1]  # complete months

    # ---------------- Emma: baby, healthy finances -> PROPOSE (app) ----------------
    c = "c_001"
    b.customer(c, "Emma Janssens", "Emma", 31, "employed", "couple", "Namur", "high", 4200.0,
               "Young couple, baby on the way", "emma")
    b.monthly(c, 25, 3100, "salary", "Salary", "Employer SA", full)
    b.monthly(c, 3, -1050, "rent", "Rent", "Landlord")
    b.monthly(c, 10, -140, "utilities", "Energy", "Energy supplier")
    b.monthly(c, 15, -45, "telecom", "Telecom", "Operator")
    b.monthly(c, 26, -500, "savings_transfer", "Monthly savings", "Savings account", full)
    b.groceries(c, 95)
    for day, amt in [("2026-08-17", -189.9), ("2026-09-02", -349.0), ("2026-09-14", -72.5), ("2026-09-28", -129.0)]:
        b.t(c, day, amt, "baby", "Little Nest - baby store", "Little Nest")
    b.t(c, "2026-09-05", -23.4, "pharmacy", "Pharmacy", "City pharmacy")        # excluded (art. 9)
    b.t(c, "2026-09-19", -60.0, "medical", "Consultation", "Medical practice")   # excluded (art. 9)
    for i in range(6):
        b.ev(c, NOW - timedelta(days=i, hours=2), "home")
    b.ev(c, NOW - timedelta(days=3), "sim_family_insurance", "start")
    b.ev(c, NOW - timedelta(days=3, minutes=-5), "family_insurance_info")
    b.products += [(c, "current_account", "", None), (c, "savings", "", None),
                   (c, "family_insurance", "Family liability", "2027-03-01"), (c, "home_insurance", "", "2027-01-15")]

    # ---------------- Sofia: same baby signal + stress -> ACCOMPANY (human) ----------------
    c = "c_002"
    b.customer(c, "Sofia Dubois", "Sofia", 34, "employed", "family", "Charleroi", "medium", 2600.0,
               "Family, new baby, budget under pressure", "sofia")
    b.monthly(c, 25, 2300, "salary", "Salary", "Employer SPRL", full)
    b.monthly(c, 3, -950, "rent", "Rent", "Landlord")
    b.monthly(c, 5, -280, "loan_payment", "Car loan", "Car credit")
    b.monthly(c, 10, -175, "utilities", "Energy", "Energy supplier")
    b.monthly(c, 15, -55, "telecom", "Telecom", "Operator")
    b.groceries(c, 120)
    for (y, m), amt in zip(full, [300, 300, 250, 200, 100, 0]):
        if amt:
            b.t(c, d(y, m, 26), -amt, "savings_transfer", "Savings", "Savings account")
    for (y, m), extra in zip(full, [0, 0, 150, 300, 450, 520]):
        if extra:
            b.t(c, d(y, m, 19), -extra, "leisure_other", "Miscellaneous", "")
    for day, amt in [("2026-08-08", -420.0), ("2026-08-21", -265.0), ("2026-09-06", -310.0), ("2026-09-22", -185.0)]:
        b.t(c, day, amt, "baby", "Little Nest - baby store", "Little Nest")
    b.t(c, "2026-08-12", -15.0, "late_fee", "Reminder fee", "Energy supplier")
    b.t(c, "2026-09-14", -15.0, "late_fee", "Reminder fee", "Operator")
    b.t(c, "2026-08-30", -95.0, "hospital", "Maternity - co-payment", "Hospital")  # excluded (art. 9)
    b.ev(c, NOW - timedelta(days=5), "home")
    b.products += [(c, "current_account", "", None), (c, "savings", "", None), (c, "consumer_loan", "Car loan", "2028-05-01")]

    # ---------------- Jan & Monique: grandchild, low digital -> INFORM (voice) ----------------
    c = "c_003"
    b.customer(c, "Jan & Monique Peeters", "Jan", 67, "retired", "couple_senior", "Ghent", "low", 24000.0,
               "Grandparents, low digital", "jan")
    b.monthly(c, 1, 2450, "pension", "Pension", "Pension service")
    b.monthly(c, 8, -190, "utilities", "Energy", "Energy supplier")
    b.monthly(c, 15, -38, "telecom", "Telecom", "Operator")
    b.groceries(c, 85)
    for (y, m) in MONTHS[-4:-1]:
        b.t(c, d(y, m, 12), -150, "family_transfer", "Monthly support", "An Peeters")
    b.t(c, "2026-09-10", -500, "birth_gift", "Birth of Lena", "An Peeters")
    b.t(c, "2026-09-03", -31.2, "pharmacy", "Pharmacy", "Pharmacy")                # excluded (art. 9)
    b.products += [(c, "current_account", "", None), (c, "savings", "", None), (c, "home_insurance", "", "2027-04-01")]

    # ---------------- Marcel: suspicious transfer -> PROTECT (voice + fraud review) ----------------
    c = "c_004"
    b.customer(c, "Marcel Lambert", "Marcel", 78, "retired", "single", "Liège", "low", 15500.0,
               "Senior, unusual transfer in progress", "marcel")
    b.monthly(c, 1, 1850, "pension", "Pension", "Pension service")
    b.monthly(c, 8, -130, "utilities", "Energy", "Energy supplier")
    b.groceries(c, 70)
    b.pending.append((c, (NOW - timedelta(minutes=4)).isoformat(), 4900.0, "Account Security Support", 1, "person"))
    b.products += [(c, "current_account", "", None), (c, "savings", "", None)]

    # ---------------- Lucas: overdraft likely, app not opened -> PROTECT (push) ----------------
    c = "c_008"
    b.customer(c, "Lucas Martin", "Lucas", 38, "employed", "single", "Mechelen", "medium", 1500.0,
               "Overdraft likely, rarely opens the app", "lucas")
    b.monthly(c, 25, 2600, "salary", "Salary", "Employer NV", full)
    b.monthly(c, 3, -1100, "rent", "Rent", "Landlord")
    b.monthly(c, 5, -150, "utilities", "Energy", "Energy supplier")
    b.monthly(c, 15, -40, "telecom", "Telecom", "Operator")
    b.monthly(c, 26, -200, "savings_transfer", "Savings", "Savings account", full)
    b.groceries(c, 90)
    b.t(c, "2026-09-12", -2400.0, "car_repair", "Garage - gearbox repair", "Garage")
    b.t(c, "2026-09-20", -3400.0, "travel", "Holiday booking", "Travel agency")
    b.ev(c, NOW - timedelta(days=20), "home")
    b.products += [(c, "current_account", "", None), (c, "savings", "", None), (c, "car_insurance", "", "2027-02-01")]

    # ---------------- Yasmine: first salary -> INFORM (app) ----------------
    c = "c_005"
    b.customer(c, "Yasmine El Idrissi", "Yasmine", 23, "employed", "single", "Brussels", "high", 1400.0,
               "First job", "yasmine")
    for (y, m) in full[:-1]:
        b.t(c, d(y, m, 28), 780, "student_job", "Student job", "Temp agency")
    b.t(c, "2026-09-25", 2150, "salary", "Salary", "Startup SRL")
    b.monthly(c, 3, -550, "rent", "Student room", "Landlord")
    b.monthly(c, 15, -25, "telecom", "Telecom", "Operator")
    b.groceries(c, 45)
    for i in range(5):
        b.ev(c, NOW - timedelta(days=i, hours=5), "home")
    b.products += [(c, "student_account", "Youth account", None)]

    # ---------------- Thomas: nothing to report -> ABSTAIN ----------------
    c = "c_006"
    b.customer(c, "Thomas Verbeke", "Thomas", 45, "employed", "family", "Wavre", "medium", 9000.0,
               "Stable situation, nothing to suggest", "thomas")
    b.monthly(c, 25, 3800, "salary", "Salary", "Employer NV", full)
    b.monthly(c, 2, -1200, "mortgage_payment", "Mortgage", "Bank")
    b.monthly(c, 10, -210, "utilities", "Energy", "Energy supplier")
    b.monthly(c, 26, -400, "savings_transfer", "Savings", "Savings account", full)
    b.groceries(c, 150)
    b.t(c, "2026-09-07", -50.0, "religious_donation", "Donation", "Association")      # excluded (art. 9)
    b.t(c, "2026-09-16", -18.7, "pharmacy", "Pharmacy", "Pharmacy")                   # excluded (art. 9)
    b.ev(c, NOW - timedelta(days=2), "home")
    b.products += [(c, "current_account", "", None), (c, "savings", "", None),
                   (c, "mortgage_fixed_rate", "10-year fixed rate", "2027-06-30"), (c, "car_insurance", "", "2026-12-15")]

    # ---------------- Nina: abandoned loan simulation -> SIMPLIFY (credit = human) ----------------
    c = "c_007"
    b.customer(c, "Nina Haddad", "Nina", 29, "employed", "couple", "Mons", "high", 18000.0,
               "Buying a home, simulation abandoned", "nina")
    b.monthly(c, 25, 2900, "salary", "Salary", "Employer SA", full)
    b.monthly(c, 3, -900, "rent", "Rent", "Landlord")
    b.monthly(c, 26, -700, "savings_transfer", "Deposit savings", "Savings account", full)
    b.groceries(c, 90)
    b.ev(c, NOW - timedelta(days=6), "sim_loan", "start")
    b.ev(c, NOW - timedelta(days=6, minutes=-12), "sim_loan", "abandon")
    for i in range(4):
        b.ev(c, NOW - timedelta(days=i + 1, hours=3), "loan_info")
    b.ev(c, NOW - timedelta(hours=20), "home")
    b.products += [(c, "current_account", "", None), (c, "savings", "", None)]

    b.users.append((ADVISOR, "advisor", None))

    # ---------------- Advisor availability: next 7 working days, 9:00 to 16:00 (lunch break at 12:00) -------
    day = TODAY
    added = 0
    while added < 7:
        day += timedelta(days=1)
        if day.weekday() >= 5:
            continue
        for hour in (9, 10, 11, 14, 15, 16):
            b.slots.append((datetime(day.year, day.month, day.day, hour).isoformat(), ADVISOR))
        added += 1
    return b


def write(b: Builder, db_path: Path | None = None) -> dict[str, str]:
    path = db_path or settings.db_path
    if path.exists():
        path.unlink()
    init_db(path)
    shared = os.getenv("DEMO_PASSWORD", "")
    creds: dict[str, str] = {}
    with get_conn(path) as conn:
        conn.executemany("INSERT INTO customers VALUES (?,?,?,?,?,?,?,?,?,?,?)", b.customers)
        conn.executemany("INSERT INTO transactions(customer_id,date,amount,category,label,counterparty) VALUES (?,?,?,?,?,?)", b.tx)
        conn.executemany("INSERT INTO app_events(customer_id,ts,screen,action) VALUES (?,?,?,?)", b.events)
        conn.executemany("INSERT INTO products(customer_id,product_type,detail,end_date) VALUES (?,?,?,?)", b.products)
        conn.executemany("INSERT INTO pending_transfers(customer_id,created_at,amount,beneficiary,beneficiary_is_new,beneficiary_type) VALUES (?,?,?,?,?,?)", b.pending)
        conn.executemany("INSERT INTO appointment_slots(starts_at, advisor) VALUES (?, ?)", b.slots)
        for username, role, cid in b.users:
            # Advisor accounts must never share the demo password to prevent privilege escalation
            pwd = secrets.token_urlsafe(9) if role == "advisor" else (shared or secrets.token_urlsafe(9))
            creds[username] = pwd
            conn.execute("INSERT INTO users VALUES (?,?,?,?)", (username, hash_password(pwd), role, cid))
    return creds


def main() -> None:
    b = build()
    creds = write(b)
    out = ROOT / ".demo_credentials"          # ignored by git
    out.write_text("\n".join(f"{u}: {p}" for u, p in creds.items()) + "\n", encoding="utf-8")
    try:
        out.chmod(0o600)
    except OSError:
        pass
    print(f"Database created: {settings.db_path}")
    print(f"{len(b.customers)} customers, {len(b.tx)} transactions, {len(b.events)} app events, {len(b.slots)} advisor slots")
    print(f"Demo credentials written to {out.name} (not versioned):")
    for u, p in creds.items():
        print(f"  {u:<9} {p}")


if __name__ == "__main__":
    main()
