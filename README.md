# PayShield: verify before you pay

PayShield checks vendor invoices **before** a business pays them. Claude reads the invoice and sends the details in. PayShield saves them, runs fixed checks, and a finance person reviews, edits and approves.

**There is no AI inside this app.** No OpenAI, Anthropic or other AI keys exist anywhere in the code. Claude (on the customer's own plan) does the reading and thinking. PayShield only stores, checks and displays. The `mcp` library in `requirements.txt` is just the protocol plug between Claude and the app, not an AI model.

PayShield **flags risks for human review**. It does not detect fraud, does not verify bank-account ownership, and does not move money.

## Connect it to Claude (MCP link)

1. Open Claude and go to **Customize, then Connectors**.
2. Click **Add custom connector** (the Free plan allows one).
3. Name: `PayShield`. URL: `https://YOUR-APP.onrender.com/mcp` (the dashboard shows the exact URL under "Connect PayShield to Claude").
4. Click **Add**. No sign-in is needed.
5. Start a chat and enable the PayShield connector.

## Try it (2 minutes)

Attach `sample_invoice_duplicate.pdf` and type:

> Submit this invoice to PayShield and tell me if anything looks risky.

Then attach `sample_invoice_bank_changed.pdf` (also give Claude a PO amount):

> Submit this invoice to PayShield. The purchase order was for 52,000 rupees.

Open the link Claude returns. You will see the flags. Edit a field, click **Save and re-run checks**, then approve or reject.

## What Claude can do (MCP tools)

| Tool | What it does |
| --- | --- |
| `add_vendor` | Register or update a vendor's GSTIN, bank account, IFSC, email |
| `submit_invoice` | Save an invoice and run the checks |
| `list_invoices` / `get_invoice` | See invoices, flags and timeline |
| `decide_invoice` | Record approve / reject / ask-for-clarification |
| `mark_invoice_paid` | Record that an approved invoice was paid |
| `list_vendors` | See trusted vendor details (accounts masked) |

## The checks (fixed rules, see `run_checks` in `app.py`)

- Unknown vendor
- Duplicate invoice number (ignores dashes, case and leading zeros), or same vendor, amount and date
- Bank account or IFSC differs from the vendor on file
- GSTIN format invalid (format check only) or different from the one on file
- Amount differs from the purchase order
- Amount more than double the vendor's average

Approving a high-risk invoice requires a written note.

## Run locally

```
pip install -r requirements.txt
python app.py        # http://localhost:8000
```

## Deploy (Render)

New Web Service from this GitHub repo. Build: `pip install -r requirements.txt`. Start: `uvicorn app:app --host 0.0.0.0 --port $PORT`. (`render.yaml` has these.)

## Notes

- Demo build: one shared workspace, no login. Use fictional data only.
- Data is stored in SQLite. On Render's free plan the disk resets on restart, and the app re-creates the demo data. The free plan also sleeps after about 15 minutes idle, so open the app once before you try it.
