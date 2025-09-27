import io
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER

styles = getSampleStyleSheet()
title_style = ParagraphStyle('title_style', parent=styles['Title'], alignment=TA_CENTER, fontSize=22, spaceAfter=20)
subtitle_style = ParagraphStyle('subtitle_style', parent=styles['Normal'], alignment=TA_CENTER, fontSize=12, textColor=colors.grey, spaceAfter=40)

def save_plot(fig):
    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight")
    buf.seek(0)
    return buf

def generate_pdf_report(buffer, df, results, plots, high_threat=None, metadata=None):
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    story = []

    # --- Cover Page ---
    story.append(Paragraph("🔍 Smart Packet Analyzer Report", title_style))
    story.append(Paragraph("Network Threat Analysis & Traffic Insights", subtitle_style))

    if metadata:
        for key, value in metadata.items():
            story.append(Paragraph(f"<b>{key}:</b> {value}", styles["Normal"]))
    else:
        story.append(Paragraph("No metadata available.", styles["Normal"]))

    story.append(Spacer(1, 100))
    story.append(Paragraph("Prepared by Smart Packet Analyzer", subtitle_style))
    story.append(PageBreak())

    # --- Analysis Results ---
    story.append(Paragraph("📊 Analysis Results", styles['Heading1']))
    story.append(Spacer(1, 12))

    for section, content in results.items():
        story.append(Paragraph(f"🚨 {section}", styles['Heading2']))
        if isinstance(content, str):
            story.append(Paragraph(content, styles['Normal']))
        elif hasattr(content, "to_dict"):
            data = [[str(k), str(v)] for k, v in content.to_dict().items()]
            table = Table([["Item", "Value"]] + data)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.black)
            ]))
            story.append(table)
        story.append(Spacer(1, 12))

    # --- Plots ---
    for title, fig in plots.items():
        story.append(Paragraph(title, styles['Heading2']))
        if fig:
            img_buf = save_plot(fig)
            story.append(Image(img_buf, width=400, height=250))
            story.append(Spacer(1, 12))

    # --- High Threat Packets ---
    if high_threat is not None and not high_threat.empty:
        story.append(Paragraph("🔥 High Threat Packets", styles['Heading2']))
        data = [high_threat.columns.tolist()] + high_threat.astype(str).values.tolist()
        table = Table(data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.red),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black)
        ]))
        story.append(table)
        story.append(Spacer(1, 12))

    doc.build(story)
    buffer.seek(0)
    return buffer
