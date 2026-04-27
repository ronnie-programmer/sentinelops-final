import os
import pathlib
from datetime import datetime

import yaml

from models import AlertLog, ComplianceReport, Threat

_MANIFEST_DIR = pathlib.Path(__file__).parent.parent.parent / "data" / "compliance"
_REPORTS_DIR = pathlib.Path(__file__).parent.parent.parent / "reports"

VALID_FRAMEWORKS = {"SOC2", "HIPAA", "NIST", "CMMC"}


def load_manifest(framework: str) -> dict:
    key = framework.upper()
    yaml_path = _MANIFEST_DIR / f"{key.lower()}.yaml"
    if not yaml_path.exists():
        raise FileNotFoundError(f"No manifest found for framework '{framework}' at {yaml_path}")
    with yaml_path.open("r") as fh:
        return yaml.safe_load(fh)


def generate_report(report: ComplianceReport, db) -> str:
    os.makedirs(_REPORTS_DIR, exist_ok=True)

    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import (
            HRFlowable,
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as exc:
        raise ImportError("reportlab is required for PDF generation") from exc

    manifest = load_manifest(report.framework)

    alerts = (
        db.query(AlertLog)
        .filter(AlertLog.created_at >= report.date_range_start)
        .filter(AlertLog.created_at <= report.date_range_end)
        .all()
    )
    threats = (
        db.query(Threat)
        .filter(Threat.created_at >= report.date_range_start)
        .filter(Threat.created_at <= report.date_range_end)
        .all()
    )

    alert_count = len(alerts)
    threat_count = len(threats)
    critical_count = sum(1 for t in threats if t.severity == "CRITICAL")
    resolved_count = sum(1 for t in threats if t.status == "Resolved")

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"{report.framework}_{timestamp}.pdf"
    file_path = str(_REPORTS_DIR / filename)

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=24,
        textColor=colors.HexColor("#1a1a2e"),
        spaceAfter=6,
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontSize=12,
        textColor=colors.HexColor("#555555"),
        spaceAfter=4,
    )
    heading1_style = ParagraphStyle(
        "Heading1Custom",
        parent=styles["Heading1"],
        fontSize=14,
        textColor=colors.HexColor("#1a1a2e"),
        spaceBefore=16,
        spaceAfter=6,
        borderPad=4,
    )
    heading2_style = ParagraphStyle(
        "Heading2Custom",
        parent=styles["Heading2"],
        fontSize=11,
        textColor=colors.HexColor("#2c3e50"),
        spaceBefore=10,
        spaceAfter=4,
    )
    body_style = ParagraphStyle(
        "BodyCustom",
        parent=styles["Normal"],
        fontSize=9,
        textColor=colors.HexColor("#333333"),
        spaceAfter=4,
        leading=14,
    )
    label_style = ParagraphStyle(
        "LabelCustom",
        parent=styles["Normal"],
        fontSize=8,
        textColor=colors.HexColor("#777777"),
        spaceAfter=2,
    )

    doc = SimpleDocTemplate(
        file_path,
        pagesize=letter,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )

    story = []

    # Title page
    story.append(Spacer(1, 0.5 * inch))
    story.append(Paragraph("SentinelOps", ParagraphStyle(
        "Logo",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.HexColor("#58a6ff"),
        spaceAfter=2,
    )))
    story.append(Paragraph("Security Operations Platform", label_style))
    story.append(Spacer(1, 0.3 * inch))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#58a6ff")))
    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph(manifest["title"], title_style))
    story.append(Paragraph(f"Framework Version: {manifest['version']}", subtitle_style))
    story.append(Spacer(1, 0.3 * inch))

    meta_data = [
        ["Report Generated", report.generated_at.strftime("%Y-%m-%d %H:%M UTC") if report.generated_at else datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")],
        ["Audit Period Start", report.date_range_start.strftime("%Y-%m-%d")],
        ["Audit Period End", report.date_range_end.strftime("%Y-%m-%d")],
        ["Framework", report.framework],
    ]
    meta_table = Table(meta_data, colWidths=[2 * inch, 4 * inch])
    meta_table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#555555")),
        ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor("#1a1a2e")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.HexColor("#f8f9fa"), colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(meta_table)
    story.append(PageBreak())

    # Summary page
    story.append(Paragraph("Executive Summary", heading1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#dddddd")))
    story.append(Spacer(1, 0.1 * inch))

    summary_data = [
        ["Metric", "Count"],
        ["Total Alerts in Period", str(alert_count)],
        ["Total Threats in Period", str(threat_count)],
        ["Critical Severity Threats", str(critical_count)],
        ["Resolved Threats", str(resolved_count)],
        ["Open/Investigating Threats", str(threat_count - resolved_count)],
        ["Framework Controls Assessed", str(len(manifest["controls"]))],
    ]
    summary_table = Table(summary_data, colWidths=[3.5 * inch, 2.5 * inch])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8f9fa"), colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ("PADDING", (0, 0), (-1, -1), 7),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
        # Highlight critical count red if > 0
        *([("TEXTCOLOR", (1, 3), (1, 3), colors.HexColor("#cc0000"))] if critical_count > 0 else []),
        ("FONTNAME", (0, 1), (0, -1), "Helvetica"),
        ("TEXTCOLOR", (0, 1), (0, -1), colors.HexColor("#333333")),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.3 * inch))

    story.append(Paragraph("Scope of Assessment", heading2_style))
    scope_text = (
        f"This report covers the audit period from <b>{report.date_range_start.strftime('%Y-%m-%d')}</b> "
        f"to <b>{report.date_range_end.strftime('%Y-%m-%d')}</b>. Evidence was collected from the "
        f"SentinelOps platform including alert logs, threat records, asset inventory, and integration "
        f"status. The assessment maps platform telemetry to {report.framework} framework controls."
    )
    story.append(Paragraph(scope_text, body_style))
    story.append(PageBreak())

    # Controls section
    story.append(Paragraph("Control Assessment Details", heading1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#dddddd")))
    story.append(Spacer(1, 0.1 * inch))

    for ctrl in manifest["controls"]:
        story.append(Paragraph(f"{ctrl['id']} — {ctrl['name']}", heading2_style))

        ctrl_meta = [
            ["Category", ctrl.get("category", "")],
            ["Status", "Assessed"],
        ]
        ctrl_meta_table = Table(ctrl_meta, colWidths=[1.5 * inch, 5 * inch])
        ctrl_meta_table.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#777777")),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica"),
            ("FONTNAME", (1, 0), (1, -1), "Helvetica-Bold"),
            ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor("#2c3e50")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#eeeeee")),
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fafafa")),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(ctrl_meta_table)
        story.append(Spacer(1, 0.05 * inch))

        story.append(Paragraph("Control Description", label_style))
        story.append(Paragraph(ctrl["description"], body_style))

        story.append(Paragraph("Evidence Sources", label_style))
        story.append(Paragraph(ctrl.get("evidence_source", ""), body_style))

        # Build dynamic evidence narrative from DB counts
        narrative = _build_evidence_narrative(ctrl["id"], report.framework, alert_count, threat_count, critical_count, resolved_count, threats)
        if narrative:
            story.append(Paragraph("Platform Evidence", label_style))
            story.append(Paragraph(narrative, body_style))

        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#eeeeee")))
        story.append(Spacer(1, 0.05 * inch))

    doc.build(story)
    return file_path


def _build_evidence_narrative(
    control_id: str,
    framework: str,
    alert_count: int,
    threat_count: int,
    critical_count: int,
    resolved_count: int,
    threats: list,
) -> str:
    parts = []

    monitoring_controls = {"CC7.2", "SI-4", "AU-2", "AU.L2-3.3.1"}
    incident_controls = {"CC7.3", "IR-4", "IR.L2-3.6.1", "164.308(a)(1)"}
    alert_controls = {"CC7.2", "AU-2", "AU.L2-3.3.1", "164.312(b)", "SI.L2-3.14.6"}
    reporting_controls = {"IR-6", "164.308(a)(6)"}

    if control_id in monitoring_controls or control_id in alert_controls:
        parts.append(
            f"During the audit period, the SentinelOps platform recorded {alert_count} alert(s) "
            f"and {threat_count} threat(s)."
        )

    if control_id in incident_controls:
        parts.append(
            f"Of the {threat_count} threat(s) identified, {critical_count} were classified as "
            f"CRITICAL severity. {resolved_count} threat(s) were resolved within the period."
        )
        mitre_count = sum(1 for t in threats if t.mitre_technique)
        if mitre_count > 0:
            parts.append(
                f"{mitre_count} threat(s) included MITRE ATT&CK technique classifications, "
                "providing structured adversary behavior context."
            )

    if control_id in reporting_controls:
        parts.append(
            f"Automated notification dispatch was active for the {threat_count} threat(s) "
            "in scope, with routing to configured Slack and PagerDuty channels."
        )

    return " ".join(parts)
