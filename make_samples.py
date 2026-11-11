"""Creates two fictional sample invoices for the demo (run once: python make_samples.py)."""
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas


def invoice(path, vendor, gstin, number, date, desc, amount, bank, ifsc, po=None):
    c = canvas.Canvas(path, pagesize=A4)
    w, h = A4
    c.setFont("Helvetica-Bold", 20); c.drawString(20 * mm, h - 25 * mm, "TAX INVOICE")
    c.setFont("Helvetica-Bold", 12); c.drawString(20 * mm, h - 38 * mm, vendor)
    c.setFont("Helvetica", 10); c.drawString(20 * mm, h - 44 * mm, f"GSTIN: {gstin}")
    c.drawString(20 * mm, h - 50 * mm, "Hyderabad, Telangana, India")
    c.drawString(130 * mm, h - 38 * mm, f"Invoice No: {number}")
    c.drawString(130 * mm, h - 44 * mm, f"Date: {date}")
    if po:
        c.drawString(130 * mm, h - 50 * mm, f"PO Ref amount: Rs {po:,.2f}")
    c.line(20 * mm, h - 60 * mm, 190 * mm, h - 60 * mm)
    c.drawString(20 * mm, h - 70 * mm, "Description"); c.drawString(150 * mm, h - 70 * mm, "Amount (INR)")
    c.drawString(20 * mm, h - 80 * mm, desc); c.drawString(150 * mm, h - 80 * mm, f"{amount:,.2f}")
    c.line(20 * mm, h - 90 * mm, 190 * mm, h - 90 * mm)
    c.setFont("Helvetica-Bold", 12)
    c.drawString(120 * mm, h - 100 * mm, "Total payable:"); c.drawString(150 * mm, h - 100 * mm, f"Rs {amount:,.2f}")
    c.setFont("Helvetica", 10)
    c.drawString(20 * mm, h - 125 * mm, "Please pay to:")
    c.drawString(20 * mm, h - 132 * mm, f"Account number: {bank}")
    c.drawString(20 * mm, h - 138 * mm, f"IFSC: {ifsc}")
    c.setFont("Helvetica-Oblique", 8)
    c.drawString(20 * mm, 15 * mm, "Sample document with fictional data, created for a PayShield demo.")
    c.save()


# 1. Same invoice number as one already in the demo data -> DUPLICATE flag
invoice("sample_invoice_duplicate.pdf", "ABC Technologies Pvt Ltd", "36ABCDE1234F1Z5", "INV-1001",
        "2026-10-05", "Website maintenance, Sept", 45000, "50200012345678", "HDFC0001234")
# 2. New invoice, different bank account + amount above PO -> BANK_CHANGED + PO mismatch
invoice("sample_invoice_bank_changed.pdf", "ABC Technologies Pvt Ltd", "36ABCDE1234F1Z5", "INV-1003",
        "2026-11-08", "Website maintenance, Nov", 61000, "31120099887766", "SBIN0004321", po=52000)
print("done")
