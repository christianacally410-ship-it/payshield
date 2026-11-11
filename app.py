"""PayShield - verify before you pay.

One small web app that does two jobs:
  1. A web dashboard where a finance person reviews, edits and approves invoices.
  2. An MCP endpoint (/mcp) so Claude can register vendors and submit invoices.

There is NO AI inside this app. Claude (on the customer's own plan) reads the
invoice and sends the extracted fields in. PayShield only stores them and runs
fixed, readable rules (see run_checks). No API keys are used anywhere.
"""
import html
import json
import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse

DATA_DIR = os.environ.get("DATA_DIR", os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(DATA_DIR, "payshield.db")
IST = timezone(timedelta(hours=5, minutes=30))

# ----------------------------------------------------------------------------
# Database
# ----------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS vendors (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  vendor_key TEXT NOT NULL UNIQUE,
  gstin TEXT DEFAULT '',
  bank_account TEXT DEFAULT '',
  ifsc TEXT DEFAULT '',
  email TEXT DEFAULT '',
  created_at TEXT
);
CREATE TABLE IF NOT EXISTS invoices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  vendor_id INTEGER,
  vendor_name TEXT NOT NULL,
  vendor_key TEXT NOT NULL,
  invoice_number TEXT NOT NULL,
  amount REAL NOT NULL,
  invoice_date TEXT DEFAULT '',
  gstin TEXT DEFAULT '',
  bank_account TEXT DEFAULT '',
  ifsc TEXT DEFAULT '',
  po_amount REAL,
  description TEXT DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending',
  risk TEXT NOT NULL DEFAULT 'low',
  flags_json TEXT NOT NULL DEFAULT '[]',
  source TEXT DEFAULT 'web',
  decision_note TEXT DEFAULT '',
  payment_ref TEXT DEFAULT '',
  created_at TEXT,
  updated_at TEXT
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  invoice_id INTEGER NOT NULL,
  at TEXT,
  actor TEXT,
  text TEXT
);
"""


@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def now() -> str:
    return datetime.now(IST).strftime("%d %b %Y, %H:%M IST")


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
def inr(x) -> str:
    x = float(x)
    neg = x < 0
    x = abs(x)
    whole = int(x)
    paise = round((x - whole) * 100)
    if paise == 100:
        whole, paise = whole + 1, 0
    s = str(whole)
    if len(s) > 3:
        head, tail = s[:-3], s[-3:]
        parts = []
        while len(head) > 2:
            parts.insert(0, head[-2:])
            head = head[:-2]
        if head:
            parts.insert(0, head)
        s = ",".join(parts + [tail])
    out = "₹" + s + (f".{paise:02d}" if paise else "")
    return "-" + out if neg else out


def norm_name(name: str) -> str:
    n = re.sub(r"[^a-z0-9 ]", " ", (name or "").lower())
    n = re.sub(r"\b(pvt|private|ltd|limited|llp|inc|co|company)\b", " ", n)
    return re.sub(r"\s+", " ", n).strip()


def norm_invno(n: str) -> str:
    s = re.sub(r"[^A-Z0-9]", "", (n or "").upper())
    return re.sub(r"(?<![0-9])0+(?=[0-9])", "", s)


def norm_acct(a: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", (a or "").upper())


def mask(a: str) -> str:
    a = norm_acct(a)
    return ("ending " + a[-4:]) if len(a) >= 4 else "(short)"


GSTIN_RE = re.compile(r"^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]$")


def gstin_format_ok(g: str) -> bool:
    if not GSTIN_RE.match(g):
        return False
    state = int(g[:2])
    return 1 <= state <= 38 or g[:2] in ("97", "99")


def to_float(v, default=None):
    try:
        if v is None or str(v).strip() == "":
            return default
        return float(str(v).replace(",", "").replace("₹", "").strip())
    except ValueError:
        return default


# ----------------------------------------------------------------------------
# The rules. Plain, fixed, readable. No AI.
# ----------------------------------------------------------------------------
def run_checks(conn, inv: dict, exclude_id: Optional[int] = None):
    flags = []

    def add(code, severity, message):
        flags.append({"code": code, "severity": severity, "message": message})

    vkey = norm_name(inv["vendor_name"])
    vendor = conn.execute("SELECT * FROM vendors WHERE vendor_key=?", (vkey,)).fetchone()
    others = conn.execute(
        "SELECT * FROM invoices WHERE vendor_key=? AND status!='rejected' AND id!=? ORDER BY id",
        (vkey, exclude_id or -1),
    ).fetchall()
    amount = float(inv["amount"])

    if amount <= 0:
        add("AMOUNT_INVALID", "high", "Invoice amount is zero or negative.")

    # 1. Unknown vendor
    if not vendor:
        add("VENDOR_UNKNOWN", "medium",
            f"'{inv['vendor_name']}' is not a registered vendor. Register it and confirm "
            "its bank details through a trusted channel before paying.")

    # 2. Duplicate invoices (exact number, then same amount + date)
    num = norm_invno(inv["invoice_number"])
    dup = next((o for o in others if num and norm_invno(o["invoice_number"]) == num), None)
    if dup:
        add("DUPLICATE", "high",
            f"Invoice number {dup['invoice_number']} was already submitted for this vendor "
            f"(invoice #{dup['id']}, {inr(dup['amount'])}, status: {dup['status']}).")
    else:
        like = next((o for o in others if inv.get("invoice_date")
                     and o["invoice_date"] == inv["invoice_date"]
                     and abs(o["amount"] - amount) < 0.005), None)
        if like:
            add("DUPLICATE_LIKELY", "medium",
                f"Same vendor, amount and date as invoice #{like['id']} ({like['invoice_number']}). "
                "Possible duplicate under a different invoice number.")

    # 3. Changed bank details
    if vendor and vendor["bank_account"] and inv.get("bank_account"):
        if norm_acct(vendor["bank_account"]) != norm_acct(inv["bank_account"]):
            add("BANK_CHANGED", "high",
                f"Bank account on this invoice ({mask(inv['bank_account'])}) differs from the account "
                f"on file ({mask(vendor['bank_account'])}). Confirm with the vendor on a number you "
                "already trust before paying.")
        elif (vendor["ifsc"] and inv.get("ifsc")
              and vendor["ifsc"].upper() != inv["ifsc"].strip().upper()):
            add("IFSC_CHANGED", "medium",
                f"IFSC on this invoice ({inv['ifsc'].upper()}) differs from the one on file "
                f"({vendor['ifsc'].upper()}).")

    # 4. GSTIN format and mismatch (format check only, not a registry lookup)
    g = (inv.get("gstin") or "").strip().upper()
    if g:
        if not gstin_format_ok(g):
            add("GSTIN_INVALID", "medium",
                f"GSTIN '{g}' is not in a valid 15-character format. This is a format check only; "
                "it does not confirm the number is registered.")
        elif vendor and vendor["gstin"] and vendor["gstin"].strip().upper() != g:
            add("GSTIN_MISMATCH", "high",
                f"GSTIN on this invoice ({g}) differs from the GSTIN on file ({vendor['gstin'].upper()}).")

    # 5. Amount vs purchase order, and vs the vendor's usual amounts
    po = inv.get("po_amount")
    if po is not None and abs(amount - po) > 0.005:
        pct = abs(amount - po) / po * 100 if po else 100
        add("AMOUNT_PO_MISMATCH", "high" if pct > 5 else "medium",
            f"Invoice amount {inr(amount)} does not match the purchase order amount {inr(po)} "
            f"({pct:.1f}% difference).")
    prior = [o["amount"] for o in others]
    if len(prior) >= 2:
        avg = sum(prior) / len(prior)
        if avg > 0 and amount > 2 * avg:
            add("AMOUNT_UNUSUAL", "medium",
                f"Amount {inr(amount)} is more than double this vendor's average of {inr(avg)} "
                f"across {len(prior)} earlier invoices.")

    risk = "high" if any(f["severity"] == "high" for f in flags) else \
           "medium" if flags else "low"
    return flags, risk


def add_event(conn, invoice_id, actor, text):
    conn.execute("INSERT INTO events (invoice_id, at, actor, text) VALUES (?,?,?,?)",
                 (invoice_id, now(), actor, text))


def create_invoice(conn, d: dict, source: str, actor: str) -> int:
    vendor_name = (d.get("vendor_name") or "").strip()
    vkey = norm_name(vendor_name)
    vendor = conn.execute("SELECT id FROM vendors WHERE vendor_key=?", (vkey,)).fetchone()
    inv = {
        "vendor_name": vendor_name,
        "invoice_number": (d.get("invoice_number") or "").strip(),
        "amount": float(d["amount"]),
        "invoice_date": (d.get("invoice_date") or "").strip(),
        "gstin": (d.get("gstin") or "").strip().upper(),
        "bank_account": (d.get("bank_account") or "").strip(),
        "ifsc": (d.get("ifsc") or "").strip().upper(),
        "po_amount": d.get("po_amount"),
        "description": (d.get("description") or "").strip(),
    }
    flags, risk = run_checks(conn, inv)
    cur = conn.execute(
        """INSERT INTO invoices (vendor_id, vendor_name, vendor_key, invoice_number, amount,
           invoice_date, gstin, bank_account, ifsc, po_amount, description, status, risk,
           flags_json, source, created_at, updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,'pending',?,?,?,?,?)""",
        (vendor["id"] if vendor else None, inv["vendor_name"], vkey, inv["invoice_number"],
         inv["amount"], inv["invoice_date"], inv["gstin"], inv["bank_account"], inv["ifsc"],
         inv["po_amount"], inv["description"], risk, json.dumps(flags), source, now(), now()),
    )
    iid = cur.lastrowid
    add_event(conn, iid, actor, f"Invoice submitted ({inr(inv['amount'])}).")
    add_event(conn, iid, "PayShield rules",
              f"Checks run: {len(flags)} flag(s), risk {risk}." if flags else "Checks run: no flags.")
    return iid


def recheck(conn, iid: int, reason: str, actor: str):
    row = conn.execute("SELECT * FROM invoices WHERE id=?", (iid,)).fetchone()
    inv = dict(row)
    flags, risk = run_checks(conn, inv, exclude_id=iid)
    vendor = conn.execute("SELECT id FROM vendors WHERE vendor_key=?", (row["vendor_key"],)).fetchone()
    conn.execute("UPDATE invoices SET flags_json=?, risk=?, vendor_id=?, updated_at=? WHERE id=?",
                 (json.dumps(flags), risk, vendor["id"] if vendor else None, now(), iid))
    add_event(conn, iid, actor, f"{reason} Checks re-run: {len(flags)} flag(s), risk {risk}.")


def apply_decision(conn, iid: int, decision: str, note: str, actor: str):
    row = conn.execute("SELECT * FROM invoices WHERE id=?", (iid,)).fetchone()
    if not row:
        return False, f"Invoice #{iid} not found."
    if row["status"] == "paid":
        return False, "This invoice is already marked paid."
    if decision not in ("approve", "reject", "clarify"):
        return False, "Decision must be approve, reject or clarify."
    if decision == "approve" and row["risk"] == "high" and not (note or "").strip():
        return False, ("This invoice has high-risk flags. Add a note explaining why it is safe "
                       "to approve (for example, who you confirmed the bank details with).")
    status = {"approve": "approved", "reject": "rejected", "clarify": "clarification"}[decision]
    conn.execute("UPDATE invoices SET status=?, decision_note=?, updated_at=? WHERE id=?",
                 (status, (note or "").strip(), now(), iid))
    label = {"approve": "Approved", "reject": "Rejected", "clarify": "Clarification requested"}[decision]
    add_event(conn, iid, actor, label + (f". Note: {note.strip()}" if (note or "").strip() else "."))
    return True, status


def mark_paid(conn, iid: int, ref: str, actor: str):
    row = conn.execute("SELECT * FROM invoices WHERE id=?", (iid,)).fetchone()
    if not row:
        return False, f"Invoice #{iid} not found."
    if row["status"] != "approved":
        return False, "Only approved invoices can be marked as paid."
    conn.execute("UPDATE invoices SET status='paid', payment_ref=?, updated_at=? WHERE id=?",
                 ((ref or "").strip(), now(), iid))
    add_event(conn, iid, actor, "Marked as paid" + (f" (ref {ref.strip()})." if (ref or "").strip() else "."))
    return True, "paid"


def public_invoice(row, flags=None):
    flags = flags if flags is not None else json.loads(row["flags_json"])
    return {
        "invoice_id": row["id"], "vendor": row["vendor_name"],
        "invoice_number": row["invoice_number"], "amount": row["amount"],
        "amount_display": inr(row["amount"]), "invoice_date": row["invoice_date"],
        "status": row["status"], "risk": row["risk"],
        "flags": [{"severity": f["severity"], "code": f["code"], "message": f["message"]} for f in flags],
        "review_url": f"{base_url()}/invoice/{row['id']}",
    }


def base_url(request: Optional[Request] = None) -> str:
    env = os.environ.get("PUBLIC_URL") or os.environ.get("RENDER_EXTERNAL_URL")
    if env:
        return env.rstrip("/")
    if request is not None:
        proto = request.headers.get("x-forwarded-proto", request.url.scheme)
        host = request.headers.get("x-forwarded-host", request.headers.get("host", ""))
        return f"{proto}://{host}"
    return "http://localhost:8000"


# ----------------------------------------------------------------------------
# Demo data
# ----------------------------------------------------------------------------
def init_db(reset: bool = False):
    os.makedirs(DATA_DIR, exist_ok=True)
    with db() as conn:
        if reset:
            conn.executescript("DROP TABLE IF EXISTS events; DROP TABLE IF EXISTS invoices; "
                               "DROP TABLE IF EXISTS vendors;")
        conn.executescript(SCHEMA)
        if conn.execute("SELECT COUNT(*) FROM vendors").fetchone()[0] == 0:
            seed(conn)


def seed(conn):
    vendors = [
        ("ABC Technologies Pvt Ltd", "36ABCDE1234F1Z5", "50200012345678", "HDFC0001234", "accounts@abctech.example"),
        ("Greenleaf Packaging", "29GLEAF5678K1Z2", "004501234567", "ICIC0000045", "billing@greenleaf.example"),
        ("Nova Cloud Services", "27NOVAC9012P1Z8", "918020045671234", "UTIB0000123", "finance@novacloud.example"),
    ]
    for n, g, b, i, e in vendors:
        conn.execute("INSERT INTO vendors (name, vendor_key, gstin, bank_account, ifsc, email, created_at) "
                     "VALUES (?,?,?,?,?,?,?)", (n, norm_name(n), g, b, i, e, now()))
    history = [
        ("ABC Technologies Pvt Ltd", "INV-1001", 45000, "2026-10-05", "36ABCDE1234F1Z5", "50200012345678", "HDFC0001234", "Website maintenance, Sept"),
        ("ABC Technologies Pvt Ltd", "INV-1002", 52000, "2026-10-20", "36ABCDE1234F1Z5", "50200012345678", "HDFC0001234", "Website maintenance, Oct"),
        ("Greenleaf Packaging", "GP-221", 18500, "2026-10-12", "29GLEAF5678K1Z2", "004501234567", "ICIC0000045", "Packaging boxes, 500 units"),
    ]
    for vn, no, amt, dt, g, b, i, desc in history:
        iid = create_invoice(conn, dict(vendor_name=vn, invoice_number=no, amount=amt, invoice_date=dt,
                                        gstin=g, bank_account=b, ifsc=i, description=desc),
                             "demo data", "Demo data")
        apply_decision(conn, iid, "approve", "Matches PO. Approved.", "Demo approver")
        mark_paid(conn, iid, "UTR-DEMO-" + str(iid), "Demo approver")
    create_invoice(conn, dict(vendor_name="Nova Cloud Services", invoice_number="NCS-778", amount=30000,
                              invoice_date="2026-11-03", gstin="27NOVAC9012P1Z8",
                              bank_account="918020045671234", ifsc="UTIB0000123",
                              description="Cloud hosting, Nov"), "demo data", "Demo data")


# ----------------------------------------------------------------------------
# MCP server (the plug between Claude and this app)
# ----------------------------------------------------------------------------
mcp = FastMCP(
    "PayShield",
    instructions=(
        "PayShield checks vendor invoices before payment. You (Claude) read the invoice and pass the "
        "extracted fields to submit_invoice. Only pass values that are actually visible in the invoice; "
        "leave a field blank rather than guessing. Amounts are in INR. PayShield applies fixed rules and "
        "flags RISKS FOR HUMAN REVIEW. It does not detect fraud and does not verify bank-account "
        "ownership. After submitting, tell the user the flags in plain words and give them the review_url "
        "so a person can check and edit the record. Do not approve invoices unless the user asks you to."
    ),
    stateless_http=True,
    json_response=True,
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
)


@mcp.tool()
def add_vendor(name: str, gstin: str = "", bank_account: str = "", ifsc: str = "", email: str = "") -> dict:
    """Register a vendor (or update it if the name already exists) with the details PayShield should
    trust when checking later invoices: GSTIN, bank account number, IFSC and email."""
    name = name.strip()
    if not name:
        return {"error": "Vendor name is required."}
    with db() as conn:
        key = norm_name(name)
        row = conn.execute("SELECT * FROM vendors WHERE vendor_key=?", (key,)).fetchone()
        if row:
            conn.execute("UPDATE vendors SET gstin=?, bank_account=?, ifsc=?, email=? WHERE id=?",
                         (gstin.strip().upper() or row["gstin"], bank_account.strip() or row["bank_account"],
                          ifsc.strip().upper() or row["ifsc"], email.strip() or row["email"], row["id"]))
            vid, action = row["id"], "updated"
        else:
            vid = conn.execute(
                "INSERT INTO vendors (name, vendor_key, gstin, bank_account, ifsc, email, created_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (name, key, gstin.strip().upper(), bank_account.strip(), ifsc.strip().upper(),
                 email.strip(), now())).lastrowid
            action = "registered"
        warn = []
        if gstin.strip() and not gstin_format_ok(gstin.strip().upper()):
            warn.append("The GSTIN is not in a valid format. Double-check it.")
    return {"vendor_id": vid, "result": f"Vendor {action}.", "warnings": warn,
            "vendors_url": f"{base_url()}/vendors"}


@mcp.tool()
def submit_invoice(vendor_name: str, invoice_number: str, amount: float, invoice_date: str = "",
                   gstin: str = "", bank_account: str = "", ifsc: str = "",
                   po_amount: Optional[float] = None, description: str = "") -> dict:
    """Submit an invoice for pre-payment checks. Read these fields from the invoice document (leave blank
    if not visible; never guess). amount is the total payable in INR. invoice_date is YYYY-MM-DD.
    po_amount is the purchase order amount if the user gave one. PayShield runs fixed rules (unknown
    vendor, duplicate invoice, changed bank details, GSTIN mismatch, PO mismatch, unusual amount),
    saves the invoice as 'pending' and returns the flags plus a link for a person to review it."""
    if not vendor_name.strip() or not invoice_number.strip():
        return {"error": "vendor_name and invoice_number are required."}
    with db() as conn:
        iid = create_invoice(conn, dict(vendor_name=vendor_name, invoice_number=invoice_number,
                                        amount=amount, invoice_date=invoice_date, gstin=gstin,
                                        bank_account=bank_account, ifsc=ifsc, po_amount=po_amount,
                                        description=description), "Claude (MCP)", "Claude")
        row = conn.execute("SELECT * FROM invoices WHERE id=?", (iid,)).fetchone()
    out = public_invoice(row)
    out["recommendation"] = {
        "high": "Do not pay yet. Resolve the high-risk flags with the vendor first.",
        "medium": "Review the flags before approving.",
        "low": "No issues found by PayShield's rules. A person should still approve before payment.",
    }[row["risk"]]
    return out


@mcp.tool()
def list_invoices(status: str = "", risk: str = "") -> dict:
    """List invoices, newest first. Optional filters: status (pending, approved, rejected,
    clarification, paid) and risk (low, medium, high)."""
    q, args = "SELECT * FROM invoices WHERE 1=1", []
    if status:
        q += " AND status=?"; args.append(status.strip().lower())
    if risk:
        q += " AND risk=?"; args.append(risk.strip().lower())
    with db() as conn:
        rows = conn.execute(q + " ORDER BY id DESC LIMIT 50", args).fetchall()
    return {"count": len(rows), "invoices": [
        {k: v for k, v in public_invoice(r).items() if k != "flags"} | {"flag_count": len(json.loads(r["flags_json"]))}
        for r in rows], "dashboard_url": base_url()}


@mcp.tool()
def get_invoice(invoice_id: int) -> dict:
    """Get one invoice with its flags and activity timeline."""
    with db() as conn:
        row = conn.execute("SELECT * FROM invoices WHERE id=?", (invoice_id,)).fetchone()
        if not row:
            return {"error": f"Invoice #{invoice_id} not found."}
        events = [dict(e) for e in conn.execute(
            "SELECT at, actor, text FROM events WHERE invoice_id=? ORDER BY id", (invoice_id,))]
    out = public_invoice(row)
    out["decision_note"] = row["decision_note"]
    out["timeline"] = events
    return out


@mcp.tool()
def decide_invoice(invoice_id: int, decision: str, note: str = "") -> dict:
    """Record a human decision on an invoice: decision is 'approve', 'reject' or 'clarify' (ask the vendor
    for clarification). Approving a high-risk invoice requires a note explaining why it is safe.
    Only use this when the user explicitly tells you the decision."""
    with db() as conn:
        ok, res = apply_decision(conn, invoice_id, decision.strip().lower(), note, "Claude (on user's instruction)")
    return {"ok": True, "status": res} if ok else {"ok": False, "error": res}


@mcp.tool()
def mark_invoice_paid(invoice_id: int, payment_reference: str = "") -> dict:
    """Record that an approved invoice has been paid (PayShield does not move money). Optionally include
    the bank payment reference."""
    with db() as conn:
        ok, res = mark_paid(conn, invoice_id, payment_reference, "Claude (on user's instruction)")
    return {"ok": True, "status": res} if ok else {"ok": False, "error": res}


@mcp.tool()
def list_vendors() -> dict:
    """List registered vendors with the GSTIN and bank details PayShield checks against
    (bank accounts are masked)."""
    with db() as conn:
        rows = conn.execute("SELECT * FROM vendors ORDER BY name").fetchall()
    return {"vendors": [{"vendor_id": r["id"], "name": r["name"], "gstin": r["gstin"],
                         "bank_account": mask(r["bank_account"]) if r["bank_account"] else "",
                         "ifsc": r["ifsc"], "email": r["email"]} for r in rows]}


# ----------------------------------------------------------------------------
# Web app (where a person checks and edits what Claude created)
# ----------------------------------------------------------------------------
CSS = """
:root{--bg:#f6f7fb;--card:#fff;--ink:#14161f;--mute:#6a7083;--line:#e5e8f0;--accent:#4f46e5;
--red:#c62828;--redbg:#fdecec;--amb:#9a6700;--ambbg:#fff4d6;--grn:#1b7f3b;--grnbg:#e3f6e8;--blu:#1d4ed8;--blubg:#e6eefc}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--ink)}
header{background:#0f1222;color:#fff;padding:14px 24px;display:flex;align-items:center;gap:24px}
header .logo{font-weight:700;font-size:18px;letter-spacing:.2px}header .tag{color:#a9b0d0;font-size:13px}
header nav{margin-left:auto;display:flex;gap:18px}header nav a{color:#d7dcf5;text-decoration:none;font-size:14px}header nav a:hover{color:#fff}
main{max-width:1100px;margin:24px auto;padding:0 20px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:0 0 12px}.sub{color:var(--mute);margin:0 0 20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px;margin-bottom:18px}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:18px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
.stat b{display:block;font-size:26px}.stat span{color:var(--mute);font-size:13px}
table{width:100%;border-collapse:collapse}th{font-size:12px;text-transform:uppercase;letter-spacing:.5px;color:var(--mute);text-align:left;padding:8px 10px;border-bottom:1px solid var(--line)}
td{padding:11px 10px;border-bottom:1px solid var(--line);vertical-align:middle}tr:last-child td{border-bottom:0}tbody tr:hover{background:#fafbff}
a{color:var(--accent)}.num{text-align:right;font-variant-numeric:tabular-nums}
.badge{display:inline-block;padding:2px 10px;border-radius:99px;font-size:12px;font-weight:600}
.high{background:var(--redbg);color:var(--red)}.medium{background:var(--ambbg);color:var(--amb)}.low{background:var(--grnbg);color:var(--grn)}
.s-pending{background:var(--blubg);color:var(--blu)}.s-approved,.s-paid{background:var(--grnbg);color:var(--grn)}.s-rejected{background:var(--redbg);color:var(--red)}.s-clarification{background:var(--ambbg);color:var(--amb)}
.flag{border-left:4px solid;border-radius:8px;padding:10px 14px;margin-bottom:10px}
.flag.high{border-color:var(--red)}.flag.medium{border-color:#e0a100}.flag b{display:block;font-size:12px;letter-spacing:.4px;text-transform:uppercase}
.ok{background:var(--grnbg);color:var(--grn);padding:12px 14px;border-radius:8px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}@media(max-width:800px){.grid,.stats{grid-template-columns:1fr 1fr}.grid{grid-template-columns:1fr}}
label{display:block;font-size:12px;color:var(--mute);margin:10px 0 3px}
input,textarea{width:100%;padding:8px 10px;border:1px solid #cfd4e3;border-radius:8px;font:inherit;background:#fff}
input:focus,textarea:focus{outline:2px solid #c7c4fb;border-color:var(--accent)}
.row2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
button,.btn{display:inline-block;border:0;border-radius:8px;padding:9px 16px;font:inherit;font-weight:600;cursor:pointer;background:var(--accent);color:#fff;text-decoration:none}
button.green{background:var(--grn)}button.red{background:var(--red)}button.amber{background:#c98a00}button.ghost{background:#eef0f8;color:var(--ink)}
.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}
.timeline{list-style:none;padding:0;margin:0}.timeline li{padding:8px 0 8px 16px;border-left:2px solid var(--line);position:relative;font-size:14px}
.timeline li:before{content:"";position:absolute;left:-6px;top:14px;width:10px;height:10px;background:var(--accent);border-radius:50%}
.timeline small{color:var(--mute);display:block}
.banner{padding:11px 14px;border-radius:8px;margin-bottom:16px;background:var(--ambbg);color:var(--amb);font-weight:500}
.banner.good{background:var(--grnbg);color:var(--grn)}
code.url{display:block;background:#0f1222;color:#e5e8ff;padding:10px 12px;border-radius:8px;word-break:break-all;margin:8px 0}
details summary{cursor:pointer;font-weight:600}.mute{color:var(--mute)}.mono{font-family:ui-monospace,Menlo,monospace;font-size:13px}
"""


def e(x) -> str:
    return html.escape("" if x is None else str(x), quote=True)


def page(title: str, body: str, msg: str = "", good: bool = False) -> HTMLResponse:
    banner = f'<div class="banner{" good" if good else ""}">{e(msg)}</div>' if msg else ""
    return HTMLResponse(f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{e(title)} | PayShield</title>
<style>{CSS}</style></head><body>
<header><div class="logo">&#128737; PayShield</div><div class="tag">Verify before you pay</div>
<nav><a href="/">Invoices</a><a href="/vendors">Vendors</a></nav></header>
<main>{banner}{body}</main></body></html>""")


def risk_badge(r):
    return f'<span class="badge {e(r)}">{e(r).upper()} RISK</span>'


def status_badge(s):
    label = {"clarification": "Clarification asked"}.get(s, s.capitalize())
    return f'<span class="badge s-{e(s)}">{e(label)}</span>'


def dashboard(request: Request):
    with db() as conn:
        rows = conn.execute("SELECT * FROM invoices ORDER BY id DESC").fetchall()
    attention = [r for r in rows if r["status"] in ("pending", "clarification") and r["risk"] in ("high", "medium")]
    tr = ""
    for r in rows:
        n = len(json.loads(r["flags_json"]))
        tr += (f'<tr><td><a href="/invoice/{r["id"]}">#{r["id"]}</a></td><td>{e(r["vendor_name"])}</td>'
               f'<td class="mono">{e(r["invoice_number"])}</td><td class="num">{inr(r["amount"])}</td>'
               f'<td>{risk_badge(r["risk"])}</td><td>{n if n else "&mdash;"}</td>'
               f'<td>{status_badge(r["status"])}</td><td class="mute">{e(r["source"])}</td></tr>')
    if not tr:
        tr = '<tr><td colspan="8" class="mute">No invoices yet. Ask Claude to submit one.</td></tr>'
    mcp_url = base_url(request) + "/mcp"
    body = f"""
<h1>Invoices</h1><p class="sub">Claude reads and submits invoices. PayShield checks them with fixed rules. A person decides.</p>
<div class="stats">
 <div class="stat"><b>{len(rows)}</b><span>Total invoices</span></div>
 <div class="stat"><b>{len(attention)}</b><span>Need attention</span></div>
 <div class="stat"><b>{sum(1 for r in rows if r["status"] in ("approved","paid"))}</b><span>Approved / paid</span></div>
 <div class="stat"><b>{sum(1 for r in rows if r["status"]=="rejected")}</b><span>Rejected</span></div>
</div>
<div class="card"><details><summary>Connect PayShield to Claude</summary>
<p>In Claude: <b>Customize &rarr; Connectors &rarr; Add custom connector</b>. Name it <b>PayShield</b> and paste this URL:</p>
<code class="url" id="u">{e(mcp_url)}</code>
<button class="ghost" onclick="navigator.clipboard.writeText(document.getElementById('u').innerText);this.innerText='Copied'">Copy URL</button>
<p class="mute">Then start a chat and try: &ldquo;Register ABC Technologies as a vendor, then submit invoice INV-1001 for &#8377;45,000.&rdquo;</p>
</details></div>
<div class="card"><table><thead><tr><th>ID</th><th>Vendor</th><th>Invoice no.</th><th class="num">Amount</th><th>Risk</th><th>Flags</th><th>Status</th><th>Source</th></tr></thead>
<tbody>{tr}</tbody></table></div>
<form method="post" action="/reset" onsubmit="return confirm('Reset all data back to the demo set?')">
<button class="ghost">Reset demo data</button> <span class="mute">Demo only. Do not enter real bank details.</span></form>"""
    return page("Invoices", body, request.query_params.get("msg", ""), request.query_params.get("ok") == "1")


def invoice_page(request: Request):
    iid = request.path_params["iid"]
    with db() as conn:
        r = conn.execute("SELECT * FROM invoices WHERE id=?", (iid,)).fetchone()
        if not r:
            return page("Not found", '<div class="card">Invoice not found. <a href="/">Back</a></div>')
        events = conn.execute("SELECT * FROM events WHERE invoice_id=? ORDER BY id DESC", (iid,)).fetchall()
        vendor = conn.execute("SELECT * FROM vendors WHERE vendor_key=?", (r["vendor_key"],)).fetchone()
    flags = json.loads(r["flags_json"])
    flag_html = "".join(
        f'<div class="flag {e(f["severity"])}" style="background:var(--{"redbg" if f["severity"]=="high" else "ambbg"})">'
        f'<b>{e(f["severity"])} &middot; {e(f["code"].replace("_"," "))}</b>{e(f["message"])}</div>' for f in flags
    ) or '<div class="ok">No issues found by PayShield\'s rules. A person should still approve before payment.</div>'
    accept = ""
    if vendor and any(f["code"] == "BANK_CHANGED" for f in flags) and r["status"] not in ("paid", "rejected"):
        accept = f"""<form method="post" action="/invoice/{iid}/accept-bank" class="card" style="margin-top:14px">
<b>Bank details changed?</b><p class="mute" style="margin:4px 0 10px">Only after you have confirmed the new account with the vendor on a trusted number, update the vendor record to this invoice's account.</p>
<button class="amber">Update vendor's bank details</button></form>"""
    closed = r["status"] in ("paid",)
    decide = ""
    if r["status"] == "approved":
        decide = f"""<h2>Payment</h2><form method="post" action="/invoice/{iid}/paid">
<label>Payment reference (optional)</label><input name="ref" placeholder="e.g. UTR number">
<div class="actions"><button class="green">Mark as paid</button></div></form>
<p class="mute">PayShield does not move money. It records the outcome.</p>"""
    elif not closed:
        decide = f"""<h2>Your decision</h2><form method="post" action="/invoice/{iid}/decide">
<label>Note {"(required to approve a high-risk invoice)" if r["risk"]=="high" else "(optional)"}</label>
<textarea name="note" rows="3" placeholder="e.g. Confirmed new bank details by phone with the vendor's accountant">{e(r["decision_note"])}</textarea>
<div class="actions"><button class="green" name="decision" value="approve">Approve</button>
<button class="amber" name="decision" value="clarify">Ask vendor to clarify</button>
<button class="red" name="decision" value="reject">Reject</button></div></form>"""
    ev = "".join(f'<li><small>{e(x["at"])} &middot; {e(x["actor"])}</small>{e(x["text"])}</li>' for x in events)
    po = "" if r["po_amount"] is None else r["po_amount"]

    def field(label, name, val, extra=""):
        return f'<div><label>{label}</label><input name="{name}" value="{e(val)}" {extra}></div>'

    body = f"""
<p><a href="/">&larr; All invoices</a></p>
<h1>Invoice #{iid} &middot; {e(r["vendor_name"])}</h1>
<p class="sub">{inr(r["amount"])} &middot; {e(r["invoice_number"])} &nbsp; {risk_badge(r["risk"])} {status_badge(r["status"])}
 &nbsp;<span class="mute">Created via {e(r["source"])}</span></p>
<div class="grid"><div>
<div class="card"><h2>Checks</h2>{flag_html}{accept}</div>
<div class="card">{decide or '<h2>Paid</h2><p>This invoice is marked paid'+(f" (ref {e(r['payment_ref'])})" if r["payment_ref"] else "")+'.</p>'}</div>
</div><div>
<form method="post" action="/invoice/{iid}/edit" class="card"><h2>Edit details</h2>
<p class="mute" style="margin:0 0 6px">Fix anything Claude got wrong. Checks re-run when you save.</p>
{field("Vendor name","vendor_name",r["vendor_name"])}
<div class="row2">{field("Invoice number","invoice_number",r["invoice_number"])}{field("Amount (INR)","amount",r["amount"])}</div>
<div class="row2">{field("Invoice date","invoice_date",r["invoice_date"],'placeholder="YYYY-MM-DD"')}{field("PO amount (optional)","po_amount",po)}</div>
{field("GSTIN","gstin",r["gstin"])}
<div class="row2">{field("Bank account","bank_account",r["bank_account"])}{field("IFSC","ifsc",r["ifsc"])}</div>
{field("Description","description",r["description"])}
<div class="actions"><button>Save and re-run checks</button></div></form>
<div class="card"><h2>Activity</h2><ul class="timeline">{ev}</ul></div>
</div></div>"""
    return page(f"Invoice #{iid}", body, request.query_params.get("msg", ""), request.query_params.get("ok") == "1")


def vendors_page(request: Request):
    with db() as conn:
        vs = conn.execute("SELECT * FROM vendors ORDER BY name").fetchall()
    cards = ""
    for v in vs:
        cards += f"""<form method="post" action="/vendor/{v["id"]}/edit" class="card">
<h2>{e(v["name"])}</h2>
<div class="row2"><div><label>GSTIN</label><input name="gstin" value="{e(v["gstin"])}"></div>
<div><label>Email</label><input name="email" value="{e(v["email"])}"></div></div>
<div class="row2"><div><label>Bank account</label><input name="bank_account" value="{e(v["bank_account"])}"></div>
<div><label>IFSC</label><input name="ifsc" value="{e(v["ifsc"])}"></div></div>
<div class="actions"><button>Save vendor</button></div></form>"""
    body = f"""<h1>Vendors</h1><p class="sub">These are the trusted details PayShield checks every invoice against.
Changing them re-runs checks on open invoices.</p>{cards or '<div class="card mute">No vendors yet. Ask Claude to register one.</div>'}"""
    return page("Vendors", body, request.query_params.get("msg", ""), request.query_params.get("ok") == "1")


def back(path: str, msg: str, ok: bool = True):
    from urllib.parse import quote
    return RedirectResponse(f"{path}?msg={quote(msg)}&ok={1 if ok else 0}", status_code=303)


async def invoice_edit(request: Request):
    iid = request.path_params["iid"]
    f = await request.form()
    amount = to_float(f.get("amount"))
    if amount is None:
        return back(f"/invoice/{iid}", "Amount must be a number.", False)
    with db() as conn:
        row = conn.execute("SELECT * FROM invoices WHERE id=?", (iid,)).fetchone()
        if not row:
            return back("/", "Invoice not found.", False)
        vname = (f.get("vendor_name") or "").strip() or row["vendor_name"]
        conn.execute(
            """UPDATE invoices SET vendor_name=?, vendor_key=?, invoice_number=?, amount=?, invoice_date=?,
               gstin=?, bank_account=?, ifsc=?, po_amount=?, description=? WHERE id=?""",
            (vname, norm_name(vname), (f.get("invoice_number") or "").strip(), amount,
             (f.get("invoice_date") or "").strip(), (f.get("gstin") or "").strip().upper(),
             (f.get("bank_account") or "").strip(), (f.get("ifsc") or "").strip().upper(),
             to_float(f.get("po_amount")), (f.get("description") or "").strip(), iid))
        recheck(conn, iid, "Details edited by reviewer.", "Reviewer")
    return back(f"/invoice/{iid}", "Saved. Checks have been re-run.")


async def invoice_decide(request: Request):
    iid = request.path_params["iid"]
    f = await request.form()
    with db() as conn:
        ok, res = apply_decision(conn, iid, f.get("decision", ""), f.get("note", ""), "Reviewer")
    return back(f"/invoice/{iid}", f"Invoice marked: {res}." if ok else res, ok)


async def invoice_paid(request: Request):
    iid = request.path_params["iid"]
    f = await request.form()
    with db() as conn:
        ok, res = mark_paid(conn, iid, f.get("ref", ""), "Reviewer")
    return back(f"/invoice/{iid}", "Marked as paid." if ok else res, ok)


async def invoice_accept_bank(request: Request):
    iid = request.path_params["iid"]
    with db() as conn:
        r = conn.execute("SELECT * FROM invoices WHERE id=?", (iid,)).fetchone()
        if not r:
            return back("/", "Invoice not found.", False)
        v = conn.execute("SELECT * FROM vendors WHERE vendor_key=?", (r["vendor_key"],)).fetchone()
        if not v:
            return back(f"/invoice/{iid}", "Vendor is not registered.", False)
        conn.execute("UPDATE vendors SET bank_account=?, ifsc=? WHERE id=?",
                     (r["bank_account"], r["ifsc"] or v["ifsc"], v["id"]))
        add_event(conn, iid, "Reviewer", "Vendor bank details updated to match this invoice (reviewer confirmed).")
        for o in conn.execute("SELECT id FROM invoices WHERE vendor_key=? AND status IN ('pending','clarification')",
                              (r["vendor_key"],)).fetchall():
            recheck(conn, o["id"], "Vendor record updated.", "PayShield rules")
    return back(f"/invoice/{iid}", "Vendor record updated. Checks re-run.")


async def vendor_edit(request: Request):
    vid = request.path_params["vid"]
    f = await request.form()
    with db() as conn:
        v = conn.execute("SELECT * FROM vendors WHERE id=?", (vid,)).fetchone()
        if not v:
            return back("/vendors", "Vendor not found.", False)
        conn.execute("UPDATE vendors SET gstin=?, email=?, bank_account=?, ifsc=? WHERE id=?",
                     ((f.get("gstin") or "").strip().upper(), (f.get("email") or "").strip(),
                      (f.get("bank_account") or "").strip(), (f.get("ifsc") or "").strip().upper(), vid))
        for o in conn.execute("SELECT id FROM invoices WHERE vendor_key=? AND status IN ('pending','clarification')",
                              (v["vendor_key"],)).fetchall():
            recheck(conn, o["id"], "Vendor record edited.", "PayShield rules")
    return back("/vendors", "Vendor saved. Open invoices were re-checked.")


async def reset(request: Request):
    init_db(reset=True)
    return back("/", "Demo data restored.")


def health(request: Request):
    return JSONResponse({"ok": True, "app": "PayShield"})


# Build one app: the MCP app already serves /mcp, we add the web pages to it.
app = mcp.streamable_http_app()
app.add_route("/", dashboard, methods=["GET"])
app.add_route("/health", health, methods=["GET"])
app.add_route("/vendors", vendors_page, methods=["GET"])
app.add_route("/invoice/{iid:int}", invoice_page, methods=["GET"])
app.add_route("/invoice/{iid:int}/edit", invoice_edit, methods=["POST"])
app.add_route("/invoice/{iid:int}/decide", invoice_decide, methods=["POST"])
app.add_route("/invoice/{iid:int}/paid", invoice_paid, methods=["POST"])
app.add_route("/invoice/{iid:int}/accept-bank", invoice_accept_bank, methods=["POST"])
app.add_route("/vendor/{vid:int}/edit", vendor_edit, methods=["POST"])
app.add_route("/reset", reset, methods=["POST"])

init_db()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
