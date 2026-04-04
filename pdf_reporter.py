from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle,
    HRFlowable,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
import os

from config import REMEDIATION_MAP


def export_full_pdf_report(all_paths, graph_ref, filename="Full_Security_Audit.pdf"):
    """
    Generates a multi-page PDF audit report.

    Parameters
    ----------
    all_paths  : list of path dicts (must NOT contain 'graph_ref' key)
    graph_ref  : AttackPathGraph instance used to look up edge attributes
    filename   : output filename
    """
    report_dir = os.getenv('REPORT_PATH', '.')
    full_path = os.path.join(report_dir, filename)

    doc = SimpleDocTemplate(full_path, pagesize=letter,
                            leftMargin=0.75 * inch, rightMargin=0.75 * inch,
                            topMargin=0.75 * inch, bottomMargin=0.75 * inch)

    styles = getSampleStyleSheet()
    title_style = styles['Title']
    title_style.textColor = colors.HexColor('#1a237e')

    h2_style = styles['Heading2']
    h2_style.textColor = colors.HexColor('#283593')

    h3_style = styles['Heading3']
    h3_style.textColor = colors.HexColor('#c62828')

    normal_style = styles['Normal']
    normal_style.leading = 14

    code_style = ParagraphStyle(
        'Code', parent=styles['Normal'],
        fontName='Courier', fontSize=8, leading=11,
        backColor=colors.HexColor('#f5f5f5'),
        borderPadding=(4, 4, 4, 4),
    )

    subtitle_style = styles.get('Subtitle', styles['Heading2'])

    story = []

    # ── Cover ──────────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.5 * inch))
    story.append(Paragraph("Kubernetes Cluster Security Audit", title_style))
    story.append(Paragraph("Automated Attack Path &amp; Risk Analysis Report", subtitle_style))
    story.append(Spacer(1, 0.2 * inch))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#1a237e')))
    story.append(Spacer(1, 0.3 * inch))

    # ── Executive Summary ──────────────────────────────────────────────────
    story.append(Paragraph("1. Executive Summary", h2_style))

    total_paths = len(all_paths)
    critical_paths = len([p for p in all_paths if p.get('total_risk_score', 0) >= 15])
    high_paths = len([p for p in all_paths if 8 <= p.get('total_risk_score', 0) < 15])
    highest_risk = all_paths[0].get('total_risk_score', 0) if all_paths else 0
    status_colour = colors.HexColor('#c62828') if total_paths > 0 else colors.HexColor('#2e7d32')

    summary_data = [
        ["Metric", "Value"],
        ["Total Exploitable Paths Found", str(total_paths)],
        ["Critical Severity Paths (≥15)", str(critical_paths)],
        ["High Severity Paths (8–14)", str(high_paths)],
        ["Highest Path Risk Score", f"{highest_risk}"],
        ["Cluster Status", "VULNERABLE" if total_paths > 0 else "SECURE"],
    ]

    summary_table = Table(summary_data, colWidths=[3.5 * inch, 2 * inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (1, 0), colors.HexColor('#1a237e')),
        ('TEXTCOLOR', (0, 0), (1, 0), colors.whitesmoke),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('ALIGN', (1, 0), (1, -1), 'CENTER'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#e8eaf6')]),
        ('TEXTCOLOR', (1, -1), (1, -1), status_colour),
        ('FONTNAME', (1, -1), (1, -1), 'Helvetica-Bold'),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.3 * inch))

    # ── Kill Chain Analysis ────────────────────────────────────────────────
    story.append(Paragraph("2. Detailed Kill Chain Analysis", h2_style))
    story.append(Paragraph(
        "The following attack paths were discovered. Each path shows the sequence of "
        "permissions and relationships an attacker would follow from an entry point to a "
        "crown jewel resource.",
        normal_style,
    ))
    story.append(Spacer(1, 0.15 * inch))

    for idx, p_data in enumerate(all_paths[:]):
        score = p_data.get('total_risk_score', 0)
        hops = p_data.get('total_hops', 0)
        severity = "CRITICAL" if score >= 15 else "HIGH" if score >= 8 else "MEDIUM"
        severity_colour = (
            colors.HexColor('#c62828') if severity == "CRITICAL"
            else colors.HexColor('#e65100') if severity == "HIGH"
            else colors.HexColor('#f57f17')
        )

        story.append(Paragraph(
            f"Path #{idx + 1}:  [{severity}]  Risk Score: {score}  |  Hops: {hops}",
            h3_style,
        ))

        path = p_data['path']
        path_lines = []
        for i, node in enumerate(path):
            if i < len(path) - 1:
                rel = graph_ref.G[path[i]][path[i + 1]].get('relation', 'access')
                path_lines.append(f"{'  ' * i}▶ {node}")
                path_lines.append(f"{'  ' * i}  └─[{rel}]")
            else:
                path_lines.append(f"{'  ' * i}🎯 {node}  ← CROWN JEWEL")

        story.append(Paragraph("<br/>".join(path_lines), code_style))
        story.append(Spacer(1, 0.2 * inch))

    story.append(PageBreak())

    # ── Critical Node Analysis (Task 4) ───────────────────────────────────
    story.append(Paragraph("3. Critical Node Analysis", h2_style))
    story.append(Paragraph(
        "The critical node is the single graph node whose removal would break the greatest "
        "number of attack paths. This is computed by temporarily removing each candidate node "
        "and recounting all valid source-to-crown-jewel paths (per the problem specification).",
        normal_style,
    ))
    story.append(Spacer(1, 0.15 * inch))

    # Re-run critical node analysis to include in PDF
    entry_points = graph_ref.get_entry_points()
    all_pods = [n for n, d in graph_ref.G.nodes(data=True) if d.get('type') == 'Pod']
    crown_jewels = graph_ref.get_crown_jewels()
    all_sources = list(set(entry_points + all_pods))

    critical_res = graph_ref.identify_critical_node(all_sources, crown_jewels)

    if "node" in critical_res:
        cn_data = [
            ["Field", "Value"],
            ["Critical Node", critical_res["node"]],
            ["Node Type", critical_res.get("node_type", "—")],
            ["Attack Paths Eliminated", str(critical_res.get("paths_eliminated", "—"))],
            ["Total Baseline Paths", str(critical_res.get("total_paths", "—"))],
        ]
        cn_table = Table(cn_data, colWidths=[2 * inch, 4.5 * inch])
        cn_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (1, 0), colors.HexColor('#283593')),
            ('TEXTCOLOR', (0, 0), (1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#e8eaf6')]),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
        ]))
        story.append(cn_table)
        story.append(Spacer(1, 0.15 * inch))
        story.append(Paragraph(
            f"<b>Action Required:</b> {critical_res.get('recommendation', '')}",
            normal_style,
        ))
    else:
        story.append(Paragraph(critical_res.get("message", ""), normal_style))

    story.append(Spacer(1, 0.3 * inch))

    # ── Remediation Roadmap ────────────────────────────────────────────────
    story.append(Paragraph("4. Remediation Roadmap", h2_style))
    story.append(Paragraph(
        "The following mitigations address specific vulnerability types detected across "
        "all attack paths. Apply these in order of path severity.",
        normal_style,
    ))
    story.append(Spacer(1, 0.15 * inch))

    detected_vulns = set()
    for p_data in all_paths:
        for u, v in zip(p_data['path'][:-1], p_data['path'][1:]):
            rel = graph_ref.G[u][v].get('relation')
            if rel in REMEDIATION_MAP:
                detected_vulns.add(rel)

    if detected_vulns:
        remediation_data = [["Vulnerability Type", "Recommended Action"]]
        for vuln in sorted(detected_vulns):
            remediation_data.append([
                vuln.replace('-', ' ').title(),
                REMEDIATION_MAP[vuln],
            ])
        rem_table = Table(remediation_data, colWidths=[1.8 * inch, 4.7 * inch])
        rem_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (1, 0), colors.HexColor('#1a237e')),
            ('TEXTCOLOR', (0, 0), (1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#e8eaf6')]),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('LEADING', (0, 0), (-1, -1), 11),
        ]))
        story.append(rem_table)
    else:
        story.append(Paragraph("No specific vulnerability types mapped to remediations.", normal_style))

    doc.build(story)
    print(f"[+] Security Audit PDF exported to: {full_path}")
