"""PDF Report Generation for AutonomSOC Cases."""

from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from datetime import datetime
import json


def generate_incident_report_pdf(case: dict) -> BytesIO:
    """
    Generate a comprehensive PDF report for a security incident case.
    
    Args:
        case: Dictionary containing case data from /cases/{case_id}
    
    Returns:
        BytesIO object containing the PDF data (can be returned as file download)
    """
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=0.5*inch,
                            leftMargin=0.5*inch, topMargin=0.75*inch, bottomMargin=0.75*inch)
    
    elements = []
    styles = getSampleStyleSheet()
    
    # Custom title style
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#00D4FF'),
        spaceAfter=12,
        fontName='Helvetica-Bold'
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#00D4FF'),
        spaceAfter=10,
        spaceBefore=12,
        fontName='Helvetica-Bold'
    )
    
    subheading_style = ParagraphStyle(
        'Subheading',
        parent=styles['Heading3'],
        fontSize=11,
        textColor=colors.HexColor('#8BA4C7'),
        spaceAfter=8,
        fontName='Helvetica-Bold'
    )
    
    normal_style = ParagraphStyle(
        'Normal',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.black,
        spaceAfter=6
    )
    
    # ─── HEADER ─────────────────────────────────────────────────────
    elements.append(Paragraph("AutonomSOC — Security Incident Report", title_style))
    elements.append(Spacer(1, 0.2*inch))
    
    # Case metadata
    metadata_data = [
        ["Case ID", case.get("case_id", "N/A"), "Status", case.get("status", "N/A")],
        ["Risk Level", case.get("risk_level", "N/A"), "Escalated", "Yes" if case.get("escalated") else "No"],
        ["Created", case.get("created_at", "N/A")[:19], "Report Generated", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")],
    ]
    
    metadata_table = Table(metadata_data, colWidths=[1.2*inch, 1.5*inch, 1.2*inch, 1.5*inch])
    metadata_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#0D1F3C')),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#8BA4C7')),
        ('TEXTCOLOR', (1, 0), (1, -1), colors.HexColor('#00D4FF')),
        ('TEXTCOLOR', (2, 0), (2, -1), colors.HexColor('#8BA4C7')),
        ('TEXTCOLOR', (3, 0), (3, -1), colors.HexColor('#00FF9C' if not case.get("escalated") else '#FF3B5C')),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (2, 0), (2, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#1A3A6B')),
    ]))
    elements.append(metadata_table)
    elements.append(Spacer(1, 0.3*inch))
    
    # ─── IDENTITY DETAILS ────────────────────────────────────────
    elements.append(Paragraph("Identity Details", heading_style))
    
    identity_data = [
        ["Identity ID", case.get("identity_id", "N/A")],
        ["Identity Type", case.get("identity_type", "N/A")],
        ["Anomalies Detected", len(case.get("anomalies", []))],
    ]
    
    identity_table = Table(identity_data, colWidths=[1.5*inch, 4*inch])
    identity_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#0D1F3C')),
        ('BACKGROUND', (1, 0), (1, -1), colors.HexColor('#050E1F')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#B8C5D6')),
        ('ALIGN', (0, 0), (0, -1), 'LEFT'),
        ('ALIGN', (1, 0), (1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.HexColor('#0A1628'), colors.HexColor('#050E1F')]),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#1A3A6B')),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (1, -1), 8),
    ]))
    elements.append(identity_table)
    elements.append(Spacer(1, 0.2*inch))
    
    # ─── RISK ASSESSMENT ──────────────────────────────────────
    elements.append(Paragraph("Risk Assessment", heading_style))
    
    risk_data = [
        ["Risk Score", f"{case.get('risk_score', 0)}/100"],
        ["MITRE Technique", f"{case.get('mitre_technique', 'N/A')} — {case.get('mitre_technique_name', 'N/A')}"],
        ["Tactic", case.get("mitre_tactic", "N/A")],
        ["Blast Radius", f"{case.get('blast_radius', 0)}/100"],
        ["Affected Identities", len(case.get("affected_identities", []))],
    ]
    
    risk_table = Table(risk_data, colWidths=[1.5*inch, 4*inch])
    risk_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#0D1F3C')),
        ('BACKGROUND', (1, 0), (1, -1), colors.HexColor('#050E1F')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#B8C5D6')),
        ('ALIGN', (0, 0), (0, -1), 'LEFT'),
        ('ALIGN', (1, 0), (1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.HexColor('#0A1628'), colors.HexColor('#050E1F')]),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#1A3A6B')),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(risk_table)
    elements.append(Spacer(1, 0.2*inch))
    
    # ─── DETECTED ANOMALIES ───────────────────────────────────
    if case.get("anomalies"):
        elements.append(Paragraph("Detected Anomalies", heading_style))
        for anomaly in case.get("anomalies", []):
            elements.append(Paragraph(f"• {anomaly}", normal_style))
        elements.append(Spacer(1, 0.2*inch))
    
    # ─── RESPONSE ACTIONS ───────────────────────────────────
    elements.append(Paragraph("Automated Response Actions", heading_style))
    
    if case.get("response_actions"):
        for action in case.get("response_actions", []):
            elements.append(Paragraph(f"✓ {action}", normal_style))
        elements.append(Paragraph(f"<b>MTTC (Mean Time To Contain):</b> {case.get('mttc_seconds', 'N/A')} seconds",
                                 normal_style))
    else:
        elements.append(Paragraph("No automated actions taken.", normal_style))
    
    elements.append(Spacer(1, 0.2*inch))
    
    # ─── LLM-GENERATED REPORT ─────────────────────────────────
    if case.get("report"):
        elements.append(PageBreak())
        elements.append(Paragraph("LLM-Generated Incident Analysis", heading_style))
        elements.append(Spacer(1, 0.1*inch))
        report_text = case.get("report", "No report available")
        for line in report_text.split("\n"):
            safe_line = line.strip() or " "
            elements.append(Paragraph(safe_line, normal_style))
    
    # ─── PIPELINE LOG ─────────────────────────────────────────
    if case.get("pipeline_log"):
        elements.append(PageBreak())
        elements.append(Paragraph("Agent Pipeline Execution Log", heading_style))
        elements.append(Spacer(1, 0.1*inch))
        log_text = ""
        for i, log_line in enumerate(case.get("pipeline_log", []), 1):
            log_text += f"{str(i).zfill(2)}. {log_line}<br/>"
        elements.append(Paragraph(log_text, ParagraphStyle(
            'MonoLog',
            parent=styles['Normal'],
            fontSize=8,
            textColor=colors.HexColor('#B8C5D6'),
            fontName='Courier',
            spaceAfter=2
        )))
    
    # ─── FOOTER ──────────────────────────────────────────────────
    elements.append(Spacer(1, 0.3*inch))
    footer_text = f"<i>Generated by AutonomSOC on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</i>"
    elements.append(Paragraph(footer_text, ParagraphStyle(
        'Footer',
        parent=styles['Normal'],
        fontSize=9,
        textColor=colors.HexColor('#64748B'),
        alignment=TA_CENTER
    )))
    
    doc.build(elements)
    buffer.seek(0)
    return buffer


def generate_pipeline_trace_pdf(case: dict) -> BytesIO:
    """
    Generate a detailed PDF with only the pipeline execution trace and reasoning.
    
    Args:
        case: Dictionary containing case data
    
    Returns:
        BytesIO object containing the PDF data
    """
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=0.5*inch,
                            leftMargin=0.5*inch, topMargin=0.75*inch, bottomMargin=0.75*inch)
    
    elements = []
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'Title',
        parent=styles['Heading1'],
        fontSize=22,
        textColor=colors.HexColor('#00D4FF'),
        spaceAfter=12,
        fontName='Helvetica-Bold'
    )
    
    heading_style = ParagraphStyle(
        'Heading',
        parent=styles['Heading2'],
        fontSize=12,
        textColor=colors.HexColor('#00D4FF'),
        spaceAfter=10,
        spaceBefore=12,
        fontName='Helvetica-Bold'
    )
    
    log_style = ParagraphStyle(
        'LogLine',
        parent=styles['Normal'],
        fontSize=9,
        textColor=colors.black,
        fontName='Courier',
        spaceAfter=3,
        leftIndent=12
    )
    
    elements.append(Paragraph("AutonomSOC — Agent Pipeline Trace", title_style))
    elements.append(Spacer(1, 0.15*inch))
    
    metadata = f"""
    <b>Case ID:</b> {case.get('case_id', 'N/A')} | 
    <b>Identity:</b> {case.get('identity_id', 'N/A')} | 
    <b>Risk Level:</b> {case.get('risk_level', 'N/A')} | 
    <b>Generated:</b> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
    """
    elements.append(Paragraph(metadata, ParagraphStyle(
        'Meta',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.HexColor('#8BA4C7')
    )))
    elements.append(Spacer(1, 0.2*inch))
    
    elements.append(Paragraph("6-Agent Pipeline Execution", heading_style))
    
    agents = [
        ("Identity Monitor", "Agent 1: Detects identity-based anomalies"),
        ("Behavior Analyzer", "Agent 2: Analyzes behavioral deviations from baseline"),
        ("Threat Intel RAG", "Agent 3: Maps to MITRE ATT&CK techniques"),
        ("Correlation Agent", "Agent 4: Correlates with other events"),
        ("Response Agent", "Agent 5: Recommends automated responses"),
        ("Reporting Agent", "Agent 6: Generates final incident report"),
    ]
    
    elements.append(Paragraph("Agent Pipeline Sequence:", log_style))
    for i, (name, desc) in enumerate(agents, 1):
        elements.append(Paragraph(f"<b>{i}. {name}</b> — {desc}", log_style))
    
    elements.append(Spacer(1, 0.2*inch))
    elements.append(Paragraph("Detailed Execution Log", heading_style))
    
    if case.get("pipeline_log"):
        for log_line in case.get("pipeline_log", []):
            color = colors.HexColor('#FF3B5C')
            if '✅' in log_line or 'CLEARED' in log_line:
                color = colors.HexColor('#00FF9C')
            elif '⚠' in log_line or 'MEDIUM' in log_line:
                color = colors.HexColor('#FFB400')
            elif '🚨' in log_line or 'CRITICAL' in log_line:
                color = colors.HexColor('#FF3B5C')
            else:
                color = colors.HexColor('#B8C5D6')
            log_para = Paragraph(f"<font color='{color.hexval()}'>▶</font> {log_line}", log_style)
            elements.append(log_para)
    else:
        elements.append(Paragraph("No pipeline log available.", log_style))
    
    elements.append(Spacer(1, 0.2*inch))
    elements.append(PageBreak())
    elements.append(Paragraph("Agent Outputs Summary", heading_style))
    
    outputs = [
        ("Identity Alert", case.get("identity_alert")),
        ("Behavior Score", case.get("behavior_score")),
        ("Threat Intel", case.get("threat_intel")),
        ("Correlation", case.get("correlation")),
        ("Response Actions", case.get("response_actions")),
    ]
    
    for agent_name, output_data in outputs:
        if output_data:
            elements.append(Paragraph(f"<b>{agent_name}:</b>", heading_style))
            import json as _json
            json_str = _json.dumps(output_data, indent=2)
            elements.append(Paragraph(f"<font face='Courier' size='8'>{json_str}</font>", log_style))
            elements.append(Spacer(1, 0.1*inch))
    
    elements.append(Spacer(1, 0.2*inch))
    elements.append(Paragraph(
        f"<i>AutonomSOC Pipeline Trace | Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</i>",
        ParagraphStyle(
            'Footer',
            parent=styles['Normal'],
            fontSize=9,
            textColor=colors.HexColor('#64748B'),
            alignment=TA_CENTER
        )
    ))
    
    doc.build(elements)
    buffer.seek(0)
    return buffer
