# app.py (SECURE RBAC VERSION)
# - Login + PBKDF2 password hashing
# - Admin sees all claims/dashboard/export/users
# - Employee sees ONLY their own claims
# - Sender locked to logged-in user for employees (anti-spoofing)

import os
import re
import hmac
import hashlib
import secrets
import sqlite3
from pathlib import Path
from datetime import date, datetime

import pandas as pd
import streamlit as st

# =========================
# CONFIG
# =========================
APP_TITLE = "REUDE Reimbursement Tool (Secure)"
DB_PATH = "reimburse.db"
LOGO_PATH = "Logo-Secondary.png"
BILLS_DIR = Path("bills")
BILLS_DIR.mkdir(exist_ok=True)

CTO_EMAIL = "cto_ira@reude.tech"

STATUS_OPTIONS = ["Draft", "Submitted", "Approved", "Reimbursed", "Rejected"]
PAYMENT_MODES = ["Cash", "Card", "UPI", "Bank Transfer", "Other"]
CURRENCIES = ["INR", "SGD", "USD"]

DEFAULT_CATEGORIES = ["Travel", "Accommodation", "Food", "Supplies", "Client Meeting", "Repair", "Software", "Other"]

DEFAULT_PERSONS = [
    ("Rajesh Kumar", "cto_ira@reude.tech"),
    ("Reginald", ""),
    ("Sivasankaran", ""),
    ("Arunachalam", ""),
    ("Kandan", ""),
    ("Keerthana", ""),
    ("Veerapradeepan", ""),
    ("Praveen", ""),
    ("Deepak", ""),
]

# Password hashing parameters
PBKDF2_ITER = 200_000
HASH_ALG = "sha256"


# =========================
# UI
# =========================
def inject_css():
    st.markdown(
        """
        <style>
        .stApp { background: linear-gradient(180deg,#ffffff 0%,#fbfbfb 60%,#f6f6f6 100%); color:#111; }
        section[data-testid="stSidebar"] { background:#fff; border-right:1px solid rgba(255,127,0,0.25); }
        h1,h2,h3,h4 { color:#ff7f00 !important; }
        .stButton>button { background:#ff7f00; color:#111; border:1px solid rgba(255,127,0,0.55);
            border-radius:10px; padding:0.45rem 0.9rem; font-weight:700; }
        .stButton>button:hover { background:#ffa64d; }
        div[data-baseweb="input"]>div, div[data-baseweb="select"]>div, textarea{
            border-radius:10px !important; border:1px solid rgba(0,0,0,0.12) !important; background:#fff !important;
        }
        div[data-testid="stDataFrame"]{ border-radius:12px; overflow:hidden; border:1px solid rgba(0,0,0,0.08); background:#fff; }
        div[data-testid="stMetric"]{ background:#fff; border:1px solid rgba(0,0,0,0.08); border-radius:12px; padding:12px; }
        .block-container { padding-top: 1.2rem; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def show_logo(path: str, width_fallback: int = 260):
    if not os.path.exists(path):
        return
    try:
        st.image(path, use_container_width=True)
    except TypeError:
        st.image(path, width=width_fallback)


# =========================
# DB
# =========================
def get_conn():
    return sqlite3.connect(DB_PATH, check_same_thread=False)


def init_db():
    with get_conn() as conn:
        # USERS
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE,
                name TEXT,
                role TEXT,               -- 'admin' or 'employee'
                password_salt BLOB,
                password_hash BLOB,
                is_active INTEGER DEFAULT 1,
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now'))
            )
            """
        )

        # Masters
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS persons (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE,
                email TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS vendors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS categories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE
            )
            """
        )

        # Claims (owner_email drives access control)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS claims (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                txn_id TEXT UNIQUE,
                owner_email TEXT,

                claim_date TEXT,
                project TEXT,
                category TEXT,
                vendor TEXT,

                sender_name TEXT,
                sender_email TEXT,

                receiver_name TEXT,
                receiver_email TEXT,

                payment_mode TEXT,
                currency TEXT,
                total_amount REAL,

                status TEXT,
                submitted_date TEXT,
                approved_date TEXT,
                reimbursed_date TEXT,
                rejected_date TEXT,

                remarks TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now'))
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS bills (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                claim_txn_id TEXT,
                file_name TEXT,
                file_path TEXT,
                bill_amount REAL,
                uploaded_at TEXT DEFAULT (datetime('now'))
            )
            """
        )

        # Optional audit log
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_email TEXT,
                action TEXT,
                txn_id TEXT,
                at TEXT DEFAULT (datetime('now'))
            )
            """
        )
        conn.commit()


def audit(actor_email: str, action: str, txn_id: str = ""):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO audit_log(actor_email, action, txn_id) VALUES (?,?,?)",
            (actor_email or "", action, txn_id or ""),
        )
        conn.commit()


def seed_defaults():
    with get_conn() as conn:
        for name, email in DEFAULT_PERSONS:
            conn.execute("INSERT OR IGNORE INTO persons(name,email) VALUES(?,?)", (name, email))
        for c in DEFAULT_CATEGORIES:
            conn.execute("INSERT OR IGNORE INTO categories(name) VALUES(?)", (c,))
        conn.commit()


def fetch_list(table: str) -> list[str]:
    with get_conn() as conn:
        rows = conn.execute(f"SELECT name FROM {table} ORDER BY name").fetchall()
    return [r[0] for r in rows if r and r[0]]


def upsert_simple(table: str, name: str):
    name = (name or "").strip()
    if not name:
        return
    with get_conn() as conn:
        conn.execute(f"INSERT OR IGNORE INTO {table}(name) VALUES(?)", (name,))
        conn.commit()


def upsert_person(name: str, email: str):
    name = (name or "").strip()
    email = (email or "").strip()
    if not name:
        return
    with get_conn() as conn:
        conn.execute("INSERT OR IGNORE INTO persons(name,email) VALUES(?,?)", (name, email))
        if email:
            conn.execute("UPDATE persons SET email=? WHERE name=?", (email, name))
        conn.commit()


def get_person_email(name: str) -> str:
    if not name:
        return ""
    with get_conn() as conn:
        row = conn.execute("SELECT email FROM persons WHERE name=?", (name,)).fetchone()
    return row[0] if row and row[0] else ""


# =========================
# Passwords / Auth
# =========================
def normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def hash_password(password: str) -> tuple[bytes, bytes]:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac(HASH_ALG, password.encode("utf-8"), salt, PBKDF2_ITER, dklen=32)
    return salt, dk


def verify_password(password: str, salt: bytes, pw_hash: bytes) -> bool:
    dk = hashlib.pbkdf2_hmac(HASH_ALG, password.encode("utf-8"), salt, PBKDF2_ITER, dklen=32)
    return hmac.compare_digest(dk, pw_hash)


def get_user_by_email(email: str):
    email = normalize_email(email)
    with get_conn() as conn:
        row = conn.execute(
            "SELECT email, name, role, password_salt, password_hash, is_active FROM users WHERE email=?",
            (email,),
        ).fetchone()
    if not row:
        return None
    return {
        "email": row[0],
        "name": row[1],
        "role": row[2],
        "salt": row[3],
        "hash": row[4],
        "is_active": int(row[5]),
    }


def create_user(email: str, name: str, role: str, password: str):
    email = normalize_email(email)
    if role not in ("admin", "employee"):
        raise ValueError("role must be admin or employee")
    salt, pw_hash = hash_password(password)
    with get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO users(email,name,role,password_salt,password_hash,is_active,updated_at) VALUES (?,?,?,?,?,1,datetime('now'))",
            (email, name.strip(), role, salt, pw_hash),
        )
        conn.commit()


def bootstrap_admin():
    """Create initial admin if there are no users, using env vars."""
    with get_conn() as conn:
        count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if count > 0:
        return

    admin_email = os.getenv("ADMIN_BOOTSTRAP_EMAIL", "").strip()
    admin_pw = os.getenv("ADMIN_BOOTSTRAP_PASSWORD", "").strip()
    if admin_email and admin_pw:
        create_user(admin_email, "Admin", "admin", admin_pw)
    # If not provided, tool will run but no one can login until admin is added via DB.


def login_ui():
    st.subheader("Login")
    email = st.text_input("Email", placeholder="name@reude.tech")
    password = st.text_input("Password", type="password")
    col1, col2 = st.columns([1, 4])
    with col1:
        ok = st.button("Login")
    if ok:
        u = get_user_by_email(email)
        if not u or not u["is_active"]:
            st.error("Invalid login or inactive user.")
            return False
        if not verify_password(password, u["salt"], u["hash"]):
            st.error("Invalid login.")
            return False

        st.session_state["auth"] = {
            "email": u["email"],
            "name": u["name"],
            "role": u["role"],
        }
        audit(u["email"], "login")
        st.rerun()
    return False


def require_auth():
    if "auth" not in st.session_state:
        return False
    a = st.session_state["auth"]
    return bool(a.get("email"))


def is_admin() -> bool:
    return require_auth() and st.session_state["auth"].get("role") == "admin"


def current_email() -> str:
    return st.session_state.get("auth", {}).get("email", "")


def current_name() -> str:
    return st.session_state.get("auth", {}).get("name", "")


def logout_button():
    if st.sidebar.button("Logout"):
        audit(current_email(), "logout")
        st.session_state.pop("auth", None)
        st.rerun()


# =========================
# Claims / Bills
# =========================
def make_txn_id(claim_dt: date) -> str:
    ym = claim_dt.strftime("%Y%m")
    with get_conn() as conn:
        rows = conn.execute("SELECT txn_id FROM claims WHERE txn_id LIKE ?", (f"REUDE-{ym}-%",)).fetchall()
    seqs = []
    for (tid,) in rows:
        try:
            seqs.append(int(str(tid).split("-")[-1]))
        except Exception:
            pass
    next_seq = (max(seqs) + 1) if seqs else 1
    return f"REUDE-{ym}-{next_seq:04d}"


def insert_claim(row: dict):
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO claims (
                txn_id, owner_email,
                claim_date, project, category, vendor,
                sender_name, sender_email, receiver_name, receiver_email,
                payment_mode, currency, total_amount,
                status, submitted_date, approved_date, reimbursed_date, rejected_date,
                remarks, updated_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, datetime('now'))
            """,
            (
                row["txn_id"], row["owner_email"],
                row["claim_date"], row["project"], row["category"], row["vendor"],
                row["sender_name"], row["sender_email"], row["receiver_name"], row["receiver_email"],
                row["payment_mode"], row["currency"], float(row["total_amount"]),
                row["status"], row.get("submitted_date", ""), row.get("approved_date", ""),
                row.get("reimbursed_date", ""), row.get("rejected_date", ""),
                row.get("remarks", ""),
            ),
        )
        conn.commit()


def add_bill(txn_id: str, file_name: str, file_path: str, bill_amount: float):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO bills (claim_txn_id, file_name, file_path, bill_amount) VALUES (?,?,?,?)",
            (txn_id, file_name, file_path, float(bill_amount)),
        )
        conn.commit()


def load_claims_df_for_user(email: str, role: str) -> pd.DataFrame:
    with get_conn() as conn:
        if role == "admin":
            df = pd.read_sql_query("SELECT * FROM claims ORDER BY id DESC", conn)
        else:
            df = pd.read_sql_query("SELECT * FROM claims WHERE owner_email=? ORDER BY id DESC", conn, params=(email,))
    if df.empty:
        return df
    df["total_amount"] = pd.to_numeric(df.get("total_amount", 0), errors="coerce").fillna(0.0)
    return df


def load_bills_df_secure(txn_id: str, email: str, role: str) -> pd.DataFrame:
    # check ownership for employee
    if role != "admin":
        with get_conn() as conn:
            row = conn.execute("SELECT owner_email FROM claims WHERE txn_id=?", (txn_id,)).fetchone()
        if not row or row[0] != email:
            return pd.DataFrame()

    with get_conn() as conn:
        df = pd.read_sql_query("SELECT * FROM bills WHERE claim_txn_id=? ORDER BY id", conn, params=(txn_id,))
    if not df.empty:
        df["bill_amount"] = pd.to_numeric(df.get("bill_amount", 0), errors="coerce").fillna(0.0)
    return df


def update_claim_secure(txn_id: str, fields: dict, actor_email: str, actor_role: str):
    # employee can only update their own claim (and should not change ownership/sender)
    if actor_role != "admin":
        with get_conn() as conn:
            row = conn.execute("SELECT owner_email FROM claims WHERE txn_id=?", (txn_id,)).fetchone()
        if not row or row[0] != actor_email:
            raise PermissionError("Not allowed")

        # disallow identity spoof
        fields.pop("owner_email", None)
        fields.pop("sender_email", None)
        fields.pop("sender_name", None)

    allowed = {
        "claim_date","project","category","vendor",
        "receiver_name","receiver_email",
        "payment_mode","currency","total_amount",
        "status","submitted_date","approved_date","reimbursed_date","rejected_date",
        "remarks"
    }
    if actor_role == "admin":
        allowed |= {"sender_name","sender_email"}  # admin can fix sender if needed

    fields = {k: v for k, v in fields.items() if k in allowed}
    if not fields:
        return

    sets = ", ".join([f"{k}=?" for k in fields.keys()])
    values = list(fields.values()) + [txn_id]

    with get_conn() as conn:
        conn.execute(f"UPDATE claims SET {sets}, updated_at=datetime('now') WHERE txn_id=?", values)
        conn.commit()


def delete_claim_secure(txn_id: str, actor_email: str, actor_role: str):
    if actor_role != "admin":
        # employee can only delete their own drafts (optional restriction)
        with get_conn() as conn:
            row = conn.execute("SELECT owner_email, status FROM claims WHERE txn_id=?", (txn_id,)).fetchone()
        if not row or row[0] != actor_email:
            raise PermissionError("Not allowed")
        if row[1] not in ("Draft",):
            raise PermissionError("Only Draft claims can be deleted by employee")

    with get_conn() as conn:
        file_rows = conn.execute("SELECT file_path FROM bills WHERE claim_txn_id=?", (txn_id,)).fetchall()
        conn.execute("DELETE FROM bills WHERE claim_txn_id=?", (txn_id,))
        conn.execute("DELETE FROM claims WHERE txn_id=?", (txn_id,))
        conn.commit()

    for (fp,) in file_rows:
        try:
            if fp and os.path.exists(fp):
                os.remove(fp)
        except Exception:
            pass


# =========================
# Email (same SMTP pattern)
# =========================
def can_send_email() -> bool:
    return all(os.getenv(k) for k in ["REUDE_SMTP_HOST","REUDE_SMTP_PORT","REUDE_SMTP_USER","REUDE_SMTP_PASS","REUDE_SMTP_FROM"])


def send_claim_email(txn_id: str):
    import smtplib
    from email.message import EmailMessage

    if not can_send_email():
        raise RuntimeError("SMTP env vars not set. Set REUDE_SMTP_HOST/PORT/USER/PASS/FROM.")

    with get_conn() as conn:
        claim = pd.read_sql_query("SELECT * FROM claims WHERE txn_id=?", conn, params=(txn_id,))
        bills = pd.read_sql_query("SELECT * FROM bills WHERE claim_txn_id=?", conn, params=(txn_id,))

    if claim.empty:
        raise RuntimeError("Claim not found")

    claim_row = claim.iloc[0].to_dict()

    msg = EmailMessage()
    msg["Subject"] = f"[REUDE] Claim Submitted: {txn_id} | {claim_row.get('sender_name','')}"
    msg["From"] = os.getenv("REUDE_SMTP_FROM")

    to_list = [CTO_EMAIL]
    sender_email = (claim_row.get("sender_email") or "").strip()
    if sender_email:
        to_list.append(sender_email)
    msg["To"] = ", ".join(to_list)

    lines = [
        f"Claim ID: {txn_id}",
        f"Owner: {claim_row.get('owner_email','')}",
        f"Date: {claim_row.get('claim_date','')}",
        f"Project: {claim_row.get('project','')}",
        f"Category: {claim_row.get('category','')}",
        f"Vendor: {claim_row.get('vendor','')}",
        "",
        f"Sender: {claim_row.get('sender_name','')} ({claim_row.get('sender_email','')})",
        f"Receiver: {claim_row.get('receiver_name','')} ({claim_row.get('receiver_email','')})",
        f"Payment Mode: {claim_row.get('payment_mode','')}",
        f"Currency: {claim_row.get('currency','')}",
        f"Total Amount: {claim_row.get('total_amount',0)}",
        "",
        f"Status: {claim_row.get('status','')}",
        f"Submitted Date: {claim_row.get('submitted_date','')}",
        "",
        "Bills:",
    ]

    if bills.empty:
        lines.append("  - No files attached")
    else:
        for _, r in bills.iterrows():
            lines.append(f"  - {r.get('file_name','')} | Amount: {r.get('bill_amount',0)}")

    remarks = (claim_row.get("remarks") or "").strip()
    if remarks:
        lines += ["", "Remarks:", remarks]

    msg.set_content("\n".join(lines))

    # attach files
    if not bills.empty:
        for _, r in bills.iterrows():
            fp = str(r.get("file_path", ""))
            fn = str(r.get("file_name", ""))
            if fp and os.path.exists(fp):
                with open(fp, "rb") as f:
                    msg.add_attachment(f.read(), maintype="application", subtype="octet-stream", filename=fn or os.path.basename(fp))

    host = os.getenv("REUDE_SMTP_HOST")
    port = int(os.getenv("REUDE_SMTP_PORT"))
    user = os.getenv("REUDE_SMTP_USER")
    pwd = os.getenv("REUDE_SMTP_PASS")

    with smtplib.SMTP(host, port) as server:
        server.starttls()
        server.login(user, pwd)
        server.send_message(msg)


# =========================
# APP START
# =========================
st.set_page_config(page_title=APP_TITLE, layout="wide")
inject_css()
init_db()
seed_defaults()
bootstrap_admin()

with st.sidebar:
    show_logo(LOGO_PATH)
    st.markdown("### Secure Access")
    if require_auth():
        st.success(f"Logged in: {current_email()} ({st.session_state['auth']['role']})")
        logout_button()
    else:
        st.info("Login required")

st.title(APP_TITLE)

# If not logged in -> login page only
if not require_auth():
    st.warning("Please login to continue.")
    login_ui()
    st.stop()

ROLE = st.session_state["auth"]["role"]
EMAIL = current_email()

# Navigation based on role
with st.sidebar:
    st.markdown("### Navigation")
    if ROLE == "admin":
        page = st.radio("", ["New Claim", "Claims List", "Dashboard", "Export", "Admin: Users"], index=0)
    else:
        page = st.radio("", ["New Claim", "My Claims"], index=0)

# =========================
# NEW CLAIM (employee sender locked)
# =========================
if page == "New Claim":
    persons = fetch_list("persons")
    vendors = fetch_list("vendors")
    projects = fetch_list("projects")
    categories = fetch_list("categories") or DEFAULT_CATEGORIES

    st.subheader("Create Claim")

    c1, c2, c3 = st.columns(3)
    with c1:
        claim_dt = st.date_input("Claim Date", value=date.today())
        project_options = (projects if projects else []) + ["Others (Add new)"]
        project_pick = st.selectbox("Project", project_options, index=0 if projects else 0)
        project_new = ""
        if project_pick == "Others (Add new)":
            project_new = st.text_input("New Project Name", placeholder="Type new project name here")

    with c2:
        category_sel = st.selectbox("Category", categories, index=0)
        vendor_options = (vendors if vendors else []) + ["Others (Add new)"]
        vendor_pick = st.selectbox("Vendor", vendor_options, index=0 if vendors else 0)
        vendor_new = ""
        if vendor_pick == "Others (Add new)":
            vendor_new = st.text_input("New Vendor Name", placeholder="Type new vendor name here")

    with c3:
        payment_mode = st.selectbox("Payment Mode", PAYMENT_MODES, index=1)
        currency = st.selectbox("Currency", CURRENCIES, index=0)
        total_amount = st.number_input("Total Claim Amount", min_value=0.0, step=1.0)

    st.markdown("### People")

    # Sender locked for employee; admin can choose sender
    if ROLE == "admin":
        sender_pick = st.selectbox("Sender", persons + ["Others (Add new)"])
        if sender_pick == "Others (Add new)":
            sender_name = st.text_input("New Sender Name")
            sender_email = st.text_input("New Sender Email")
        else:
            sender_name = sender_pick
            sender_email = st.text_input("Sender Email", value=get_person_email(sender_pick))
    else:
        # employee: sender = logged-in user
        sender_name = current_name() or EMAIL.split("@")[0]
        sender_email = EMAIL
        st.info(f"Sender locked to your login: {sender_name} ({sender_email})")

    # Receiver (can be someone else, e.g., finance/admin)
    receiver_pick = st.selectbox("Receiver", persons + ["Others (Add new)"])
    if receiver_pick == "Others (Add new)":
        receiver_name = st.text_input("New Receiver Name")
        receiver_email = st.text_input("New Receiver Email")
    else:
        receiver_name = receiver_pick
        receiver_email = st.text_input("Receiver Email", value=get_person_email(receiver_pick))

    remarks = st.text_area("Remarks (optional)")
    status = st.selectbox("Status", STATUS_OPTIONS, index=0)

    st.markdown("### Status Dates")
    submitted_date = approved_date = reimbursed_date = rejected_date = ""
    d1, d2, d3, d4 = st.columns(4)
    with d1:
        if status == "Submitted":
            submitted_date = str(st.date_input("Submitted Date", value=date.today()))
    with d2:
        if status == "Approved":
            approved_date = str(st.date_input("Approved Date", value=date.today()))
    with d3:
        if status == "Reimbursed":
            reimbursed_date = str(st.date_input("Reimbursed Date", value=date.today()))
    with d4:
        if status == "Rejected":
            rejected_date = str(st.date_input("Rejected Date", value=date.today()))

    st.markdown("### Bills Upload (multiple)")
    files = st.file_uploader("Upload bills (PDF/JPG/PNG) – optional", type=["pdf", "jpg", "jpeg", "png"], accept_multiple_files=True)
    bill_amounts = []
    if files:
        st.caption("Enter amount for each bill file:")
        for i, f in enumerate(files):
            bill_amounts.append(st.number_input(f"Amount for {f.name}", min_value=0.0, step=1.0, key=f"bill_amt_{i}"))

    save_btn = st.button("Save Claim")

    if save_btn:
        final_project = project_new.strip() if project_pick == "Others (Add new)" else project_pick.strip()
        final_vendor = vendor_new.strip() if vendor_pick == "Others (Add new)" else vendor_pick.strip()

        if project_pick == "Others (Add new)" and not final_project:
            st.error("Enter New Project Name (because you selected Others).")
            st.stop()
        if vendor_pick == "Others (Add new)" and not final_vendor:
            st.error("Enter New Vendor Name (because you selected Others).")
            st.stop()

        sender_name = (sender_name or "").strip()
        sender_email = normalize_email(sender_email)

        receiver_name = (receiver_name or "").strip()
        receiver_email = normalize_email(receiver_email)

        if not final_project:
            st.error("Project is required.")
            st.stop()
        if not sender_email or "@" not in sender_email:
            st.error("Sender email invalid.")
            st.stop()
        if float(total_amount) <= 0:
            st.error("Total amount must be > 0.")
            st.stop()

        # Employee anti-spoof: sender must be login email
        if ROLE != "admin" and sender_email != EMAIL:
            st.error("Security check failed: sender must match your login.")
            st.stop()

        # store masters
        upsert_person(sender_name, sender_email)
        if receiver_name:
            upsert_person(receiver_name, receiver_email)
        upsert_simple("projects", final_project)
        if final_vendor:
            upsert_simple("vendors", final_vendor)
        upsert_simple("categories", category_sel)

        txn_id = make_txn_id(claim_dt)

        insert_claim({
            "txn_id": txn_id,
            "owner_email": EMAIL,  # ownership fixed to login email
            "claim_date": str(claim_dt),
            "project": final_project,
            "category": category_sel,
            "vendor": final_vendor,
            "sender_name": sender_name,
            "sender_email": sender_email,
            "receiver_name": receiver_name,
            "receiver_email": receiver_email,
            "payment_mode": payment_mode,
            "currency": currency,
            "total_amount": float(total_amount),
            "status": status,
            "submitted_date": submitted_date,
            "approved_date": approved_date,
            "reimbursed_date": reimbursed_date,
            "rejected_date": rejected_date,
            "remarks": (remarks or "").strip(),
        })
        audit(EMAIL, "create_claim", txn_id)

        # bills
        if files:
            claim_folder = BILLS_DIR / txn_id
            claim_folder.mkdir(parents=True, exist_ok=True)
            for f, amt in zip(files, bill_amounts):
                safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", f.name)
                out_path = claim_folder / safe_name
                with open(out_path, "wb") as w:
                    w.write(f.getbuffer())
                add_bill(txn_id, f.name, str(out_path), float(amt))

        st.success(f"✅ Saved claim {txn_id}")

        if status == "Submitted":
            try:
                send_claim_email(txn_id)
                st.success(f"📧 Email sent to {CTO_EMAIL} and Sender email.")
            except Exception as e:
                st.warning(f"Email not sent: {e}")

        st.rerun()


# =========================
# EMPLOYEE: MY CLAIMS
# =========================
elif page == "My Claims":
    st.subheader("My Claims")
    df = load_claims_df_for_user(EMAIL, ROLE)
    if df.empty:
        st.info("No claims yet.")
        st.stop()

    cols = [
        "txn_id","claim_date","project","category","vendor",
        "total_amount","currency","payment_mode","status",
        "submitted_date","approved_date","reimbursed_date","rejected_date","updated_at"
    ]
    cols = [c for c in cols if c in df.columns]
    st.dataframe(df[cols], use_container_width=True)

    st.markdown("---")
    st.subheader("Edit my Claim (limited)")
    sel = st.selectbox("Select Claim ID", df["txn_id"].tolist())
    row = df[df["txn_id"] == sel].iloc[0].to_dict()

    # Employee edits limited; sender locked; no dashboard access.
    c1, c2, c3 = st.columns(3)
    with c1:
        project = st.text_input("Project", value=str(row.get("project","")))
        category = st.text_input("Category", value=str(row.get("category","")))
    with c2:
        vendor = st.text_input("Vendor", value=str(row.get("vendor","")))
        payment_mode = st.selectbox("Payment Mode", PAYMENT_MODES,
                                    index=PAYMENT_MODES.index(row.get("payment_mode","Card")) if row.get("payment_mode","Card") in PAYMENT_MODES else 1)
        currency = st.selectbox("Currency", CURRENCIES,
                                index=CURRENCIES.index(row.get("currency","INR")) if row.get("currency","INR") in CURRENCIES else 0)
    with c3:
        total_amount = st.number_input("Total Amount", min_value=0.0, step=1.0, value=float(row.get("total_amount",0.0)))
        status = st.selectbox("Status", STATUS_OPTIONS,
                              index=STATUS_OPTIONS.index(row.get("status","Draft")) if row.get("status","Draft") in STATUS_OPTIONS else 0)

    remarks = st.text_area("Remarks", value=str(row.get("remarks","")))

    # Bills view (secured)
    bills_df = load_bills_df_secure(sel, EMAIL, ROLE)
    st.markdown("### Bills")
    if bills_df.empty:
        st.info("No bills.")
    else:
        st.dataframe(bills_df[["file_name","bill_amount","uploaded_at"]], use_container_width=True)

    st.markdown("### Add more bills")
    add_files = st.file_uploader("Upload more bills", type=["pdf","jpg","jpeg","png"], accept_multiple_files=True)
    add_amounts = []
    if add_files:
        for i, f in enumerate(add_files):
            add_amounts.append(st.number_input(f"Amount for {f.name}", min_value=0.0, step=1.0, key=f"emp_add_amt_{i}"))

    colA, colB = st.columns([1.2, 1.2])
    with colA:
        if st.button("Save Updates"):
            try:
                update_claim_secure(
                    sel,
                    {
                        "project": project.strip(),
                        "category": category.strip(),
                        "vendor": vendor.strip(),
                        "payment_mode": payment_mode,
                        "currency": currency,
                        "total_amount": float(total_amount),
                        "status": status,
                        "remarks": remarks.strip(),
                    },
                    actor_email=EMAIL,
                    actor_role=ROLE,
                )
                audit(EMAIL, "update_claim", sel)

                if add_files:
                    claim_folder = BILLS_DIR / sel
                    claim_folder.mkdir(parents=True, exist_ok=True)
                    for f, amt in zip(add_files, add_amounts):
                        safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", f.name)
                        out_path = claim_folder / safe_name
                        with open(out_path, "wb") as w:
                            w.write(f.getbuffer())
                        add_bill(sel, f.name, str(out_path), float(amt))

                st.success("✅ Updated.")
                st.rerun()
            except Exception as e:
                st.error(f"Update failed: {e}")

    with colB:
        confirm = st.checkbox("Confirm delete Draft only")
        if st.button("Delete Draft", disabled=not confirm):
            try:
                delete_claim_secure(sel, EMAIL, ROLE)
                audit(EMAIL, "delete_claim", sel)
                st.success("Deleted.")
                st.rerun()
            except Exception as e:
                st.error(f"Delete failed: {e}")


# =========================
# ADMIN: CLAIMS LIST
# =========================
elif page == "Claims List":
    if not is_admin():
        st.error("Admin only.")
        st.stop()

    st.subheader("Claims List (Admin - All)")

    df = load_claims_df_for_user(EMAIL, "admin")
    if df.empty:
        st.info("No claims.")
        st.stop()

    st.dataframe(df, use_container_width=True)

    st.markdown("---")
    st.subheader("Edit / Delete (Admin)")

    sel = st.selectbox("Select Claim ID", df["txn_id"].tolist())
    row = df[df["txn_id"] == sel].iloc[0].to_dict()

    c1, c2, c3 = st.columns(3)
    with c1:
        claim_date_str = st.text_input("Claim Date (YYYY-MM-DD)", value=str(row.get("claim_date","")))
        project = st.text_input("Project", value=str(row.get("project","")))
        category = st.text_input("Category", value=str(row.get("category","")))
    with c2:
        vendor = st.text_input("Vendor", value=str(row.get("vendor","")))
        sender_name = st.text_input("Sender Name", value=str(row.get("sender_name","")))
        sender_email = st.text_input("Sender Email", value=str(row.get("sender_email","")))
    with c3:
        receiver_name = st.text_input("Receiver Name", value=str(row.get("receiver_name","")))
        receiver_email = st.text_input("Receiver Email", value=str(row.get("receiver_email","")))
        total_amount = st.number_input("Total Amount", min_value=0.0, step=1.0, value=float(row.get("total_amount",0.0)))

    payment_mode = st.selectbox("Payment Mode", PAYMENT_MODES,
                                index=PAYMENT_MODES.index(row.get("payment_mode","Card")) if row.get("payment_mode","Card") in PAYMENT_MODES else 1)
    currency = st.selectbox("Currency", CURRENCIES,
                            index=CURRENCIES.index(row.get("currency","INR")) if row.get("currency","INR") in CURRENCIES else 0)
    status = st.selectbox("Status", STATUS_OPTIONS,
                          index=STATUS_OPTIONS.index(row.get("status","Draft")) if row.get("status","Draft") in STATUS_OPTIONS else 0)
    remarks = st.text_area("Remarks", value=str(row.get("remarks","")))

    colA, colB = st.columns([1.2, 1.2])
    with colA:
        if st.button("Save Admin Updates"):
            update_claim_secure(
                sel,
                {
                    "claim_date": claim_date_str.strip(),
                    "project": project.strip(),
                    "category": category.strip(),
                    "vendor": vendor.strip(),
                    "sender_name": sender_name.strip(),
                    "sender_email": normalize_email(sender_email),
                    "receiver_name": receiver_name.strip(),
                    "receiver_email": normalize_email(receiver_email),
                    "payment_mode": payment_mode,
                    "currency": currency,
                    "total_amount": float(total_amount),
                    "status": status,
                    "remarks": remarks.strip(),
                },
                actor_email=EMAIL,
                actor_role=ROLE,
            )
            audit(EMAIL, "admin_update_claim", sel)
            st.success("Updated.")
            st.rerun()

    with colB:
        confirm = st.checkbox("Confirm delete (admin)")
        if st.button("Delete Claim (Admin)", disabled=not confirm):
            delete_claim_secure(sel, EMAIL, ROLE)
            audit(EMAIL, "admin_delete_claim", sel)
            st.success("Deleted.")
            st.rerun()


# =========================
# ADMIN: DASHBOARD
# =========================
elif page == "Dashboard":
    if not is_admin():
        st.error("Admin only.")
        st.stop()

    st.subheader("Dashboard (Admin)")

    df = load_claims_df_for_user(EMAIL, "admin")
    if df.empty:
        st.info("No data.")
        st.stop()

    df["claim_date_dt"] = pd.to_datetime(df.get("claim_date", ""), errors="coerce")
    df["month"] = df["claim_date_dt"].dt.to_period("M").astype(str)
    df["total_amount"] = pd.to_numeric(df.get("total_amount", 0), errors="coerce").fillna(0.0)

    view_mode = st.selectbox("View Mode", ["Compact", "Expanded"], index=0)

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        dmin = df["claim_date_dt"].min()
        start = st.date_input("From", value=(dmin.date() if pd.notna(dmin) else date.today()))
    with c2:
        dmax = df["claim_date_dt"].max()
        end = st.date_input("To", value=(dmax.date() if pd.notna(dmax) else date.today()))
    with c3:
        status_filter = st.selectbox("Status", ["All"] + STATUS_OPTIONS, index=0)
    with c4:
        owner_filter = st.text_input("Owner email contains")

    fdf = df.copy()
    fdf = fdf[(fdf["claim_date_dt"].dt.date >= start) & (fdf["claim_date_dt"].dt.date <= end)]
    if status_filter != "All":
        fdf = fdf[fdf["status"] == status_filter]
    if owner_filter:
        fdf = fdf[fdf["owner_email"].astype(str).str.contains(owner_filter, case=False, na=False)]

    total = float(fdf["total_amount"].sum())
    pending = float(fdf.loc[fdf["status"].isin(["Draft", "Submitted"]), "total_amount"].sum())
    approved = float(fdf.loc[fdf["status"] == "Approved", "total_amount"].sum())
    reimbursed = float(fdf.loc[fdf["status"] == "Reimbursed", "total_amount"].sum())

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total", f"{total:,.2f}")
    m2.metric("Pending", f"{pending:,.2f}")
    m3.metric("Approved", f"{approved:,.2f}")
    m4.metric("Reimbursed", f"{reimbursed:,.2f}")

    monthly = fdf.groupby("month")["total_amount"].sum().sort_index()

    if view_mode == "Compact":
        r1c1, r1c2 = st.columns(2)
        with r1c1:
            st.markdown("### Monthly Trend")
            st.line_chart(monthly)
        with r1c2:
            st.markdown("### Status Count")
            st.bar_chart(fdf["status"].value_counts())

        r2c1, r2c2 = st.columns(2)
        with r2c1:
            st.markdown("### Category Spend")
            st.bar_chart(fdf.groupby("category")["total_amount"].sum().sort_values(ascending=False))
        with r2c2:
            st.markdown("### Project Spend (Top 15)")
            st.bar_chart(fdf.groupby("project")["total_amount"].sum().sort_values(ascending=False).head(15))

        st.markdown("### Table (Filtered)")
        cols = ["txn_id","owner_email","claim_date","project","category","vendor","total_amount","currency","status"]
        cols = [c for c in cols if c in fdf.columns]
        st.dataframe(fdf[cols], use_container_width=True)
    else:
        st.markdown("### Monthly Trend")
        st.line_chart(monthly)

        st.markdown("### Spend by Category")
        st.bar_chart(fdf.groupby("category")["total_amount"].sum().sort_values(ascending=False))

        st.markdown("### Spend by Project (Top 15)")
        st.bar_chart(fdf.groupby("project")["total_amount"].sum().sort_values(ascending=False).head(15))

        st.markdown("### Spend by Owner (Top 20)")
        st.bar_chart(fdf.groupby("owner_email")["total_amount"].sum().sort_values(ascending=False).head(20))

        st.markdown("### Top Vendors (Top 15)")
        st.bar_chart(fdf.groupby("vendor")["total_amount"].sum().sort_values(ascending=False).head(15))

        st.markdown("### Status Distribution")
        st.bar_chart(fdf["status"].value_counts())

        st.markdown("### Detailed Table")
        st.dataframe(fdf, use_container_width=True)


# =========================
# ADMIN: EXPORT
# =========================
elif page == "Export":
    if not is_admin():
        st.error("Admin only.")
        st.stop()

    st.subheader("Export (Admin)")
    df = load_claims_df_for_user(EMAIL, "admin")
    if df.empty:
        st.info("No data to export.")
    else:
        st.download_button(
            "Download Claims CSV",
            df.to_csv(index=False).encode("utf-8"),
            file_name="reude_claims_export.csv",
            mime="text/csv",
        )
        with get_conn() as conn:
            bills = pd.read_sql_query("SELECT * FROM bills ORDER BY id DESC", conn)
        st.download_button(
            "Download Bills CSV",
            bills.to_csv(index=False).encode("utf-8"),
            file_name="reude_bills_export.csv",
            mime="text/csv",
        )


# =========================
# ADMIN: USER MANAGEMENT
# =========================
elif page == "Admin: Users":
    if not is_admin():
        st.error("Admin only.")
        st.stop()

    st.subheader("User Management (Admin)")

    with get_conn() as conn:
        users = pd.read_sql_query("SELECT email, name, role, is_active, created_at, updated_at FROM users ORDER BY role, email", conn)
    st.dataframe(users, use_container_width=True)

    st.markdown("### Create / Reset User Password")
    c1, c2, c3 = st.columns(3)
    with c1:
        u_email = st.text_input("User Email")
        u_name = st.text_input("User Name")
    with c2:
        u_role = st.selectbox("Role", ["employee", "admin"], index=0)
        u_active = st.checkbox("Active", value=True)
    with c3:
        u_password = st.text_input("Password (set/reset)", type="password")

    if st.button("Create/Update User"):
        if not u_email or "@" not in u_email:
            st.error("Valid email required.")
            st.stop()
        if not u_password or len(u_password) < 8:
            st.error("Password must be at least 8 characters.")
            st.stop()

        create_user(u_email, u_name or u_email.split("@")[0], u_role, u_password)

        # active flag update
        with get_conn() as conn:
            conn.execute("UPDATE users SET is_active=?, updated_at=datetime('now') WHERE email=?", (1 if u_active else 0, normalize_email(u_email)))
            conn.commit()

        audit(EMAIL, f"admin_create_update_user:{normalize_email(u_email)}")
        st.success("User created/updated.")
        st.rerun()
