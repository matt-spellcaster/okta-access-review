"""PDF version of the review for sharing and sign-off."""

from __future__ import annotations

from collections import Counter
from datetime import date
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import landscape, letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from . import __version__
from .checks import CHECKS, SEVERITIES, Finding
from .models import Snapshot

SEVERITY_COLORS = {
    "critical": colors.HexColor("#b42318"),
    "high": colors.HexColor("#c4320a"),
    "medium": colors.HexColor("#b54708"),
    "low": colors.HexColor("#475467"),
    "info": colors.HexColor("#1570ef"),
}
HEADER_BG = colors.HexColor("#f2f4f7")
GRID = colors.HexColor("#d0d5dd")

_styles = getSampleStyleSheet()
TITLE = ParagraphStyle("title", parent=_styles["Title"], alignment=0, fontSize=20, spaceAfter=4)
H2 = ParagraphStyle("h2", parent=_styles["Heading2"], spaceBefore=14, spaceAfter=6, keepWithNext=1)
BODY = ParagraphStyle("body", parent=_styles["BodyText"], fontSize=9, leading=12)
SMALL = ParagraphStyle("small", parent=BODY, fontSize=8, leading=10)
MUTED = ParagraphStyle("muted", parent=SMALL, textColor=colors.HexColor("#475467"))
WARN = ParagraphStyle("warn", parent=BODY, textColor=colors.HexColor("#b42318"))
CELL_BOLD = ParagraphStyle("cellbold", parent=SMALL, fontName="Helvetica-Bold")


def _p(text: str, style: ParagraphStyle = SMALL) -> Paragraph:
    return Paragraph(escape(str(text)), style)


def _table(rows: list[list], widths: list[float]) -> Table:
    table = Table(rows, colWidths=widths, repeatRows=1, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), HEADER_BG),
        ("GRID", (0, 0), (-1, -1), 0.5, GRID),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return table


def _severity_cell(severity: str) -> Paragraph:
    color = SEVERITY_COLORS.get(severity, colors.black).hexval()[2:]
    return Paragraph(f'<font color="#{color}"><b>{escape(severity.upper())}</b></font>', SMALL)


def _page_decor(org_url: str):
    def draw(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(colors.HexColor("#475467"))
        width, _ = doc.pagesize
        canvas.drawString(doc.leftMargin, 0.4 * inch, f"CONFIDENTIAL · Okta access review · {org_url}")
        canvas.drawRightString(width - doc.rightMargin, 0.4 * inch, f"Page {doc.page}")
        canvas.restoreState()

    return draw


def write_pdf(
    path: Path,
    snapshot: Snapshot,
    findings: list[Finding],
    skipped: list[str],
    as_of: date,
    matrix: list[dict],
) -> Path:
    doc = SimpleDocTemplate(
        str(path),
        pagesize=landscape(letter),
        leftMargin=0.5 * inch,
        rightMargin=0.5 * inch,
        topMargin=0.5 * inch,
        bottomMargin=0.6 * inch,
        title="Okta user access review",
        author=f"okta-access-review {__version__}",
        invariant=1,  # no embedded timestamps, so identical input gives identical bytes
    )
    width = doc.width
    counts = Counter(f.severity for f in findings)
    story: list = []

    story.append(Paragraph("Okta user access review", TITLE))
    live = sum(1 for u in snapshot.users if u.status != "DEPROVISIONED")
    meta = [
        ["Org", snapshot.org_url],
        ["Data collected", snapshot.collected_at.strftime("%Y-%m-%d %H:%M UTC")],
        ["Review date", as_of.isoformat()],
        ["Scope", f"{len(snapshot.users)} users ({live} not deprovisioned), "
                  f"{len(snapshot.groups)} groups, {len(snapshot.apps)} apps"],
        ["Status", "INCOMPLETE, see data gaps" if snapshot.gaps else "Complete"],
        ["Tool", f"okta-access-review {__version__} (read-only)"],
    ]
    meta_table = Table(
        [[_p(k, CELL_BOLD), _p(v)] for k, v in meta], colWidths=[1.3 * inch, width - 1.3 * inch], hAlign="LEFT"
    )
    meta_table.setStyle(TableStyle([
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
        ("TOPPADDING", (0, 0), (-1, -1), 1),
        ("LEFTPADDING", (0, 0), (0, -1), 0),
    ]))
    story.append(meta_table)

    story.append(Paragraph("Summary", H2))
    summary = [[_p("Severity", CELL_BOLD)] + [_severity_cell(s) for s in SEVERITIES] + [_p("Total", CELL_BOLD)]]
    summary.append([_p("Findings", CELL_BOLD)] + [_p(counts.get(s, 0)) for s in SEVERITIES] + [_p(len(findings))])
    story.append(_table(summary, [1.2 * inch] + [0.9 * inch] * len(SEVERITIES) + [0.9 * inch]))
    if skipped:
        story.append(Spacer(1, 4))
        story.append(_p(f"Skipped (no HR roster provided): {', '.join(skipped)}", MUTED))

    if snapshot.gaps:
        story.append(Paragraph("Data gaps", H2))
        story.append(_p("This review is incomplete. Fix these before relying on it:", WARN))
        for gap in snapshot.gaps:
            story.append(_p(f"• {gap}", BODY))

    story.append(Paragraph("Findings", H2))
    if findings:
        titles = {c.id: c.title for c in CHECKS}
        rows = [[_p(h, CELL_BOLD) for h in ("Severity", "Check", "Subject", "Detail")]]
        for f in findings:
            rows.append([_severity_cell(f.severity), _p(f"{f.check_id} {titles[f.check_id]}"), _p(f.subject), _p(f.detail)])
        story.append(_table(rows, [0.8 * inch, 2.2 * inch, 2.2 * inch, width - 5.2 * inch]))
    else:
        story.append(_p("No findings.", BODY))

    used = {f.check_id for f in findings}
    story.append(Paragraph("Remediation and control mapping", H2))
    rows = [[_p(h, CELL_BOLD) for h in ("Check", "Controls", "Fix")]]
    for c in CHECKS:
        if c.id in used:
            rows.append([_p(f"{c.id} {c.title}"), _p(", ".join(c.controls)), _p(c.remediation)])
    if len(rows) > 1:
        story.append(_table(rows, [2.6 * inch, 2.6 * inch, width - 5.2 * inch]))

    story.append(Paragraph("Access by user", H2))
    story.append(_p("Full detail, including apps, is in access_matrix.csv. Record decisions there.", MUTED))
    story.append(Spacer(1, 4))
    headers = ("Login", "Status", "Type", "Manager", "Last sign-in", "MFA", "Admin roles", "Groups")
    rows = [[_p(h, CELL_BOLD) for h in headers]]
    for r in matrix:
        rows.append([_p(r["login"]), _p(r["status"]), _p(r["type"]), _p(r["manager"]), _p(r["last_login"]),
                     _p(r["mfa"]), _p(r["admin_roles"]), _p(r["groups"])])
    story.append(_table(rows, [2.0 * inch, 1.15 * inch, 0.8 * inch, 1.05 * inch, 0.85 * inch, 1.25 * inch,
                               1.3 * inch, width - 8.4 * inch]))

    sign = Table(
        [["", "", ""], [_p("Reviewer name", MUTED), _p("Signature", MUTED), _p("Date", MUTED)]],
        colWidths=[width / 3] * 3,
        rowHeights=[20, 14],
        hAlign="LEFT",
    )
    sign.setStyle(TableStyle([("LINEABOVE", (0, 1), (-1, 1), 0.75, colors.black), ("RIGHTPADDING", (0, 0), (-1, -1), 18)]))
    story.append(KeepTogether([
        Paragraph("Reviewer sign-off", H2),
        _p("I reviewed the findings and the access list above and recorded a decision for each user.", BODY),
        Spacer(1, 18),
        sign,
    ]))

    doc.build(story, onFirstPage=_page_decor(snapshot.org_url), onLaterPages=_page_decor(snapshot.org_url))
    return path
