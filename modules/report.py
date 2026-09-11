import os
from datetime import datetime
from urllib.parse import urlparse
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    """
    Canvas to handle two-pass page numbering securely.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_number(num_pages)
            super().showPage()
        super().save()

    def draw_page_number(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 9)
        self.setFillColor(colors.HexColor("#718096"))
        
        # Draw header rule and text on pages after the first
        if self._pageNumber > 1:
            self.setStrokeColor(colors.HexColor("#E2E8F0"))
            self.setLineWidth(0.5)
            self.line(54, letter[1] - 40, letter[0] - 54, letter[1] - 40)
            self.drawString(54, letter[1] - 35, "AI-Driven Email Threat Platform - Forensic Analysis Report")

        # Draw footer rule and page number
        self.setStrokeColor(colors.HexColor("#E2E8F0"))
        self.setLineWidth(0.5)
        self.line(54, 50, letter[0] - 54, 50)
        
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(letter[0] - 54, 38, page_text)
        self.drawString(54, 38, f"Generated automatically by ThreatWatch Engine • {datetime.now().strftime('%Y-%m-%d')}")
        self.restoreState()


def generate_report(result, email_meta=None, forensic_timeline=None):
    """
    Generates a secure, comprehensive threat analysis PDF report.
    
    Parameters:
    - result (list or dict): Data containing analyzed URLs with keys 'url', 'phishing_probability', 'prediction'.
    - email_meta (dict, optional): Contextual data about scanned emails.
    - forensic_timeline (list, optional): List of event checkpoints.
    """
    # Normalize result into a uniform list format
    if isinstance(result, dict):
        result = [result]
    elif not isinstance(result, list):
        result = []

    # Configure document layout metrics
    pdf_filename = "Threat_Analysis_Report.pdf"
    doc = SimpleDocTemplate(
        pdf_filename,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=64
    )
    
    # Initialize UI stylesheets
    styles = getSampleStyleSheet()
    
    # Define custom UI design palette matching the Streamlit interface
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=28,
        textColor=colors.HexColor("#1A202C"),
        spaceAfter=6
    )
    
    h1_style = ParagraphStyle(
        'SectionH1',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#2D3748"),
        spaceBefore=14,
        spaceAfter=8,
        keepWithNext=True
    )
    
    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#4A5568")
    )
    
    meta_label_style = ParagraphStyle(
        'MetaLabel',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#2D3748")
    )

    table_header_style = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=12,
        textColor=colors.white
    )

    story = []

    # 1. Document Title & Header Area
    story.append(Paragraph("Forensic Threat Analysis Report", title_style))
    story.append(Paragraph(f"Analysis Execution Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S IST')}", body_style))
    story.append(Spacer(1, 15))

    # 2. Executive Metadata Summary Card
    story.append(Paragraph("Executive Summary Context", h1_style))
    
    email_subject = "Standalone URL Module Scan"
    email_sender = "Manual User Input Interface"
    
    if isinstance(email_meta, dict):
        email_subject = email_meta.get("subject", email_subject)
        email_sender = email_meta.get("sender", email_sender)

    meta_data = [
        [Paragraph("Target Category / Subject:", meta_label_style), Paragraph(str(email_subject), body_style)],
        [Paragraph("Origin Node / Sender:", meta_label_style), Paragraph(str(email_sender), body_style)],
        [Paragraph("Engine Classification Framework:", meta_label_style), Paragraph("WHOIS & Lexical URL AI Processing", body_style)]
    ]
    
    # Calculate text layout constraints for table columns (Total width = 504 pt)
    meta_table = Table(meta_data, colWidths=[160, 344])
    meta_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('LINEBELOW', (0,0), (-1,-1), 0.5, colors.HexColor("#EDF2F7")),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 15))

    # 3. Main Threat Indicators Data Table
    story.append(Paragraph("Analyzed Indicators Registry", h1_style))
    
    # Build clean headers matching your Streamlit table rows
    table_content = [[
        Paragraph("Extracted Target Node (URL)", table_header_style),
        Paragraph("Parsed Domain", table_header_style),
        Paragraph("Probability", table_header_style),
        Paragraph("System Verdict", table_header_style)
    ]]

    # Parse dataset elements dynamically matching your AI core keys
    for item in result:
        raw_url = item.get("url", "N/A")
        
        # Safely parse the clean domain string from the full URL netloc
        try:
            parsed_domain = urlparse(raw_url).netloc if raw_url != "N/A" else "N/A"
            if not parsed_domain and raw_url != "N/A":
                parsed_domain = urlparse(f"http://{raw_url}").netloc
        except Exception:
            parsed_domain = "Extraction Failed"

        # Math evaluation to capture clean scores out of 100
        raw_prob = item.get("phishing_probability", 0)
        risk_percentage = f"{int(raw_prob * 100)}/100" if raw_prob <= 1.0 else f"{int(raw_prob)}/100"
        
        verdict = str(item.get("prediction", "Unknown")).upper()

        # Render rows dynamically wrapped inside reportlab Paragraph text flows
        table_content.append([
            Paragraph(raw_url, body_style),
            Paragraph(parsed_domain if parsed_domain else "Unknown Domain", body_style),
            Paragraph(risk_percentage, body_style),
            Paragraph(verdict, body_style)
        ])

    indicator_table = Table(table_content, colWidths=[174, 130, 80, 120], repeatRows=1)
    indicator_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1A202C")),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E0")),
    ]))
    story.append(indicator_table)
    story.append(Spacer(1, 15))

    # 4. Forensic Timeline Pipeline Flow Logs
    if forensic_timeline and isinstance(forensic_timeline, list):
        timeline_elements = [Paragraph("System Forensic Execution Log", h1_style)]
        
        timeline_data = []
        for event in forensic_timeline:
            if isinstance(event, dict):
                timestamp = event.get("time", datetime.now().strftime("%H:%M:%S"))
                action = event.get("action", "Engine Subprocess Triggered")
                timeline_data.append([
                    Paragraph(f"<b>[{timestamp}]</b>", body_style),
                    Paragraph(str(action), body_style)
                ])
        
        if timeline_data:
            timeline_table = Table(timeline_data, colWidths=[80, 424])
            timeline_table.setStyle(TableStyle([
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ('TOPPADDING', (0,0), (-1,-1), 4),
                ('LINELEFT', (0,0), (0,-1), 1.5, colors.HexColor("#3182CE")),
                ('LEFTPADDING', (0,0), (0,-1), 10),
            ]))
            timeline_elements.append(timeline_table)
            story.append(KeepTogether(timeline_elements))

    # Compile components using custom two-pass NumberedCanvas layout template
    doc.build(story, canvasmaker=NumberedCanvas)
    return pdf_filename
