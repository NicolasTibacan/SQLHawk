from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

from jinja2 import Environment, FileSystemLoader, select_autoescape
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

from ..core.config import settings


TEMPLATES_DIR = Path(__file__).resolve().parents[1] / "templates"

_env = Environment(
    loader=FileSystemLoader(TEMPLATES_DIR),
    autoescape=select_autoescape(["html", "xml"]),
)


def build_report_payload(scan) -> dict:
    generated_at = datetime.now(timezone.utc).isoformat()
    return {
        "scan_id": scan.id,
        "target_name": scan.target_name,
        "risk_score": scan.risk_score,
        "risk_level": scan.risk_level,
        "strength_score": scan.strength_score,
        "findings": scan.findings or [],
        "recommendations": scan.recommendations or [],
        "generated_at": generated_at,
    }


def render_report_html(scan) -> str:
    payload = build_report_payload(scan)
    template = _env.get_template("report.html")
    return template.render(**payload)


def ensure_report_pdf(scan) -> str:
    path = _report_pdf_path(scan.id)
    if path.exists():
        return str(path)
    return write_report_pdf(scan)


def write_report_pdf(scan) -> str:
    payload = build_report_payload(scan)
    path = _report_pdf_path(scan.id)
    path.parent.mkdir(parents=True, exist_ok=True)

    styles = getSampleStyleSheet()
    story = [
        Paragraph("SQLHawk Security Report", styles["Title"]),
        Spacer(1, 12),
        Paragraph(
            f"<b>Target:</b> {_safe_text(payload['target_name'])}",
            styles["Normal"],
        ),
        Paragraph(
            f"<b>Risk score:</b> {payload['risk_score']} "
            f"({_safe_text(payload['risk_level'])})",
            styles["Normal"],
        ),
        Paragraph(
            f"<b>Strength score:</b> {payload['strength_score']}",
            styles["Normal"],
        ),
        Paragraph(
            f"<b>Generated at:</b> {_safe_text(payload['generated_at'])}",
            styles["Normal"],
        ),
        Spacer(1, 12),
        Paragraph("Findings", styles["Heading2"]),
    ]

    findings = payload["findings"]
    if findings:
        for finding in findings:
            story.append(
                Paragraph(
                    _safe_text(finding.get("title", "Finding")),
                    styles["Heading3"],
                )
            )
            story.append(
                Paragraph(
                    f"<b>Severity:</b> {_safe_text(finding.get('severity', 'low'))}",
                    styles["Normal"],
                )
            )
            story.append(
                Paragraph(
                    _safe_text(finding.get("description", "")),
                    styles["Normal"],
                )
            )
            if finding.get("evidence"):
                story.append(
                    Paragraph(
                        f"<b>Evidence:</b> {_safe_text(finding.get('evidence'))}",
                        styles["Normal"],
                    )
                )
            story.append(
                Paragraph(
                    f"<b>Recommendation:</b> {_safe_text(finding.get('recommendation', ''))}",
                    styles["Normal"],
                )
            )
            story.append(Spacer(1, 8))
    else:
        story.append(Paragraph("No findings were reported.", styles["Normal"]))

    story.append(Spacer(1, 12))
    story.append(Paragraph("Recommendations", styles["Heading2"]))

    recommendations = payload["recommendations"]
    if recommendations:
        for item in recommendations:
            title = _safe_text(item.get("title", "Recommendation"))
            recommendation = _safe_text(item.get("recommendation", ""))
            severity = _safe_text(item.get("severity", ""))
            if severity:
                line = f"<b>{title}</b> ({severity}): {recommendation}"
            else:
                line = f"<b>{title}</b>: {recommendation}"
            story.append(Paragraph(line, styles["Normal"]))
            story.append(Spacer(1, 6))
    else:
        story.append(Paragraph("No recommendations were generated.", styles["Normal"]))

    doc = SimpleDocTemplate(str(path), pagesize=LETTER, title="SQLHawk Report")
    doc.build(story)
    return str(path)


def _safe_text(value: object) -> str:
    if value is None:
        return ""
    return escape(str(value))


def _report_pdf_path(scan_id: int) -> Path:
    return Path(settings.reports_dir) / f"scan_{scan_id}.pdf"
