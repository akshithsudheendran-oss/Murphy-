"""
reports/pdf_generator.py — PDF report generator for Murphy.

Generates a scan report as a PDF using ReportLab. The report contains:
  - Cover header (target URL, scan date, Murphy branding)
  - Summary table (total / critical / high / medium / low)
  - Detailed findings table with severity colour-coding
"""

import os
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
)


# Where PDFs are written
REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")


# Severity colours
SEV_COLORS = {
    "Critical": colors.HexColor("#b91c1c"),
    "High":     colors.HexColor("#dc2626"),
    "Medium":   colors.HexColor("#d97706"),
    "Low":      colors.HexColor("#2563eb"),
    "Info":     colors.HexColor("#6b7280"),
}


def _ensure_dir():
    os.makedirs(REPORTS_DIR, exist_ok=True)


def _severity_color(sev):
    return SEV_COLORS.get(sev, colors.black)


def generate_pdf(scan, vulnerabilities, output_path=None):
    """
    Generate a PDF report for a single scan.
    - scan: dict from models.scan.get_scan()
    - vulnerabilities: list from models.scan.get_vulnerabilities()
    Returns the path to the generated PDF.
    """
    _ensure_dir()

    if output_path is None:
        output_path = os.path.join(REPORTS_DIR, f"murphy_report_scan_{scan['id']}.pdf")

    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("H1", parent=styles["Heading1"],
                        fontSize=20, spaceAfter=6)
    h2 = ParagraphStyle("H2", parent=styles["Heading2"],
                        fontSize=14, spaceBefore=14, spaceAfter=6)
    body = styles["BodyText"]
    small = ParagraphStyle("Small", parent=styles["BodyText"],
                           fontSize=8, textColor=colors.grey)
    cell = ParagraphStyle("Cell", parent=styles["BodyText"], fontSize=8,
                          leading=10)
    cell_bold = ParagraphStyle("CellBold", parent=cell, fontName="Helvetica-Bold")

    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=18 * mm, bottomMargin=18 * mm,
        title=f"Murphy Scan Report #{scan['id']}",
    )

    story = []

    # ---- Cover / header ----
    story.append(Paragraph("Murphy Security Scan Report", h1))
    story.append(Paragraph(
        f"<b>Target:</b> {scan['target_url']}", body
    ))
    story.append(Paragraph(
        f"<b>Scan ID:</b> {scan['id']} &nbsp;&nbsp; "
        f"<b>Status:</b> {scan['scan_status']} &nbsp;&nbsp; "
        f"<b>Date:</b> {scan['created_at']}", body
    ))
    story.append(Spacer(1, 10))

    # ---- Summary table ----
    story.append(Paragraph("Summary", h2))
    summary_data = [
        ["Total", "Critical", "High", "Medium", "Low"],
        [
            str(scan.get("total_vulnerabilities") or 0),
            str(scan.get("critical_count") or 0),
            str(scan.get("high_count") or 0),
            str(scan.get("medium_count") or 0),
            str(scan.get("low_count") or 0),
        ],
    ]
    summary = Table(summary_data, colWidths=[34 * mm] * 5)
    summary.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME",   (0, 1), (-1, 1), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, -1), 11),
        ("ALIGN",      (0, 0), (-1, -1), "CENTER"),
        ("GRID",       (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(summary)
    story.append(Spacer(1, 14))

    # ---- Findings ----
    story.append(Paragraph(f"Detailed Findings ({len(vulnerabilities)})", h2))

    if not vulnerabilities:
        story.append(Paragraph(
            "No vulnerabilities were detected against the tested payloads. "
            "This does not guarantee the target is secure — only that it "
            "did not respond to the specific checks Murphy performs.",
            body,
        ))
    else:
        header = ["#", "Severity", "Type", "Affected URL", "Payload",
                  "Description", "Remediation"]
        rows = [header]
        for i, v in enumerate(vulnerabilities, start=1):
            rows.append([
                str(i),
                Paragraph(f"<b>{v['severity']}</b>", cell_bold),
                Paragraph(v.get("vuln_type") or "", cell),
                Paragraph((v.get("affected_url") or "")[:200], cell),
                Paragraph((v.get("payload_used") or "-")[:120], cell),
                Paragraph(v.get("description") or "", cell),
                Paragraph(v.get("remediation") or "", cell),
            ])

        col_widths = [8 * mm, 18 * mm, 28 * mm, 38 * mm, 30 * mm, 40 * mm, 35 * mm]
        table = Table(rows, colWidths=col_widths, repeatRows=1)
        table_style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",   (0, 0), (-1, 0), 9),
            ("VALIGN",     (0, 0), (-1, -1), "TOP"),
            ("GRID",       (0, 0), (-1, -1), 0.4, colors.HexColor("#d1d5db")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]
        # Colour the Severity column per-row
        for i, v in enumerate(vulnerabilities, start=1):
            table_style.append((
                "BACKGROUND", (1, i), (1, i),
                _severity_color(v["severity"]),
            ))
            table_style.append((
                "TEXTCOLOR", (1, i), (1, i), colors.white,
            ))
        table.setStyle(TableStyle(table_style))
        story.append(table)

    # ---- Footer ----
    story.append(Spacer(1, 18))
    story.append(Paragraph(
        "Generated by Murphy — Web Vulnerability Scanner. "
        "For educational / authorized testing only.", small
    ))

    doc.build(story)
    return output_path


# ---------- self-test ----------
if __name__ == "__main__":
    demo_scan = {
        "id": 999,
        "target_url": "http://localhost/dvwa",
        "scan_status": "completed",
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_vulnerabilities": 3,
        "critical_count": 1,
        "high_count": 1,
        "medium_count": 1,
        "low_count": 0,
    }
    demo_vulns = [
        {"severity": "Critical", "vuln_type": "SQL Injection (Error-based)",
         "affected_url": "http://localhost/dvwa/vulnerabilities/sqli/index.php?id=1",
         "payload_used": "'", "description": "Database error triggered by input.",
         "remediation": "Use parameterized queries."},
        {"severity": "High", "vuln_type": "Reflected XSS",
         "affected_url": "http://localhost/dvwa/vulnerabilities/xss_r/?name=...",
         "payload_used": "<script>alert(1)</script>",
         "description": "Payload reflected unescaped.",
         "remediation": "HTML-encode output."},
        {"severity": "Medium", "vuln_type": "Exposed Admin Path: /server-status",
         "affected_url": "http://localhost/server-status",
         "payload_used": "HEAD /server-status",
         "description": "Apache server-status page is exposed.",
         "remediation": "Restrict /server-status to localhost."},
    ]

    path = generate_pdf(demo_scan, demo_vulns)
    print(f"[+] PDF generated: {path}")
    print(f"    Size: {os.path.getsize(path)} bytes")