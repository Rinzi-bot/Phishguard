# app/routes/analyzer.py
from flask import Blueprint, render_template, request, flash, redirect, url_for, abort, send_file
from flask_login import login_required, current_user
from app.services.risk_scorer import calculate_risk
from app.services.quarantine import QuarantineManager
from app.services.attachment_checker import check_attachment
from app.models.analysis import EmailAnalysis
from app import db
import io
import csv
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, KeepTogether
from reportlab.platypus.doctemplate import PageTemplate, Frame
from reportlab.platypus.tableofcontents import TableOfContents
import json

analyzer_bp = Blueprint('analyzer', __name__)
quarantine = QuarantineManager()

@analyzer_bp.route('/', methods=['GET', 'POST'])
@login_required
def analyze():
    if request.method == 'POST':
        if 'email_file' not in request.files:
            flash("No file uploaded", "danger")
            return redirect(request.url)
        
        file = request.files['email_file']
        if file.filename == '':
            flash("No selected file", "danger")
            return redirect(request.url)

        raw_email = file.read()
        result = calculate_risk(raw_email)

        # Attachment Check
        file.seek(0)
        attachment_result = check_attachment(file)

        # Save analysis to database
        analysis = EmailAnalysis(
            filename=file.filename,
            risk_level=result['risk_level'],
            score=result['score'],
            details={
                **result['details'],
                "attachment": attachment_result
            },
            user_id=current_user.id
        )
        db.session.add(analysis)
        db.session.commit()

        # Auto-quarantine high risk emails
        if result['risk_level'] == "HIGH":
            file.seek(0)
            quarantine.quarantine_email(file, result, current_user.id)
            flash("High risk email has been quarantined.", "warning")

        return render_template('results.html', 
                             result=result, 
                             filename=file.filename,
                             attachment=attachment_result,
                             analysis_id=analysis.id)

    return render_template('upload.html')


def _generate_pdf_filename(analysis):
    """Generate meaningful PDF filename with date and risk level"""
    timestamp = analysis.timestamp.strftime('%Y-%m-%d')
    risk_level = analysis.risk_level
    safe_filename = analysis.filename.replace('/', '_').replace('\\', '_')[:30]
    return f"PhishGuard_Report_{risk_level}_{timestamp}_{safe_filename}.pdf"


def _get_risk_color(risk_level):
    """Return color based on risk level"""
    colors_map = {
        "HIGH": colors.HexColor("#DC3545"),      # Red
        "MEDIUM": colors.HexColor("#FFC107"),    # Yellow/Orange
        "LOW": colors.HexColor("#28A745")        # Green
    }
    return colors_map.get(risk_level, colors.grey)


def _create_header_footer(canvas_obj, doc):
    """Add header and footer to each page"""
    canvas_obj.saveState()
    
    # Header
    canvas_obj.setFont("Helvetica-Bold", 14)
    canvas_obj.drawString(0.75*inch, letter[1] - 0.5*inch, "🛡️ PhishGuard - Phishing Analysis Report")
    
    # Footer
    canvas_obj.setFont("Helvetica", 9)
    canvas_obj.setFillColor(colors.grey)
    footer_text = f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Page {doc.page}"
    canvas_obj.drawRightString(letter[0] - 0.75*inch, 0.5*inch, footer_text)
    
    canvas_obj.restoreState()


@analyzer_bp.route('/report/<int:analysis_id>')
@login_required
def download_report(analysis_id):
    """Download Enhanced PDF Report with professional formatting"""
    analysis = EmailAnalysis.query.get_or_404(analysis_id)
    
    # Only allow owner or admin to download
    if analysis.user_id != current_user.id and not current_user.is_admin():
        abort(403)

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=0.75*inch,
        leftMargin=0.75*inch,
        topMargin=1.25*inch,
        bottomMargin=0.75*inch,
        title=f"PhishGuard Report - {analysis.filename}"
    )
    
    # Register header/footer
    def on_page_change(canvas_obj, doc):
        _create_header_footer(canvas_obj, doc)
    
    doc.build([])  # Initialize page count
    
    styles = getSampleStyleSheet()
    story = []
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor("#1a3a52"),
        spaceAfter=12,
        alignment=1  # Center
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor("#2c5aa0"),
        spaceAfter=10,
        spaceBefore=10
    )
    
    normal_style = ParagraphStyle(
        'CustomNormal',
        parent=styles['Normal'],
        fontSize=11,
        leading=14
    )
    
    # Risk level color
    risk_color = _get_risk_color(analysis.risk_level)
    
    # Title
    story.append(Paragraph("PhishGuard Security Analysis Report", title_style))
    story.append(Spacer(1, 0.2*inch))
    
    # Executive Summary / Alert Box
    alert_data = [
        ["RISK LEVEL", "CONFIDENCE SCORE", "FILE NAME"],
        [analysis.risk_level, f"{analysis.score}/100", analysis.filename]
    ]
    alert_table = Table(alert_data, colWidths=[1.5*inch, 2*inch, 2*inch])
    alert_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), risk_color),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('FONTSIZE', (0, 1), (-1, -1), 11),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('TOPPADDING', (0, 0), (-1, 0), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor("#f9f9f9"), colors.white]),
    ]))
    story.append(alert_table)
    story.append(Spacer(1, 0.2*inch))
    
    # Analysis Details Section
    story.append(Paragraph("Analysis Details", heading_style))
    
    details_data = [
        ["Analysis ID", str(analysis.id)],
        ["Analyzed On", analysis.timestamp.strftime('%Y-%m-%d %H:%M:%S')],
        ["Analyzed By", current_user.email if hasattr(current_user, 'email') else 'System'],
    ]
    
    details_table = Table(details_data, colWidths=[2*inch, 4.5*inch])
    details_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor("#e8f4f8")),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.white, colors.HexColor("#f9f9f9")]),
        ('PADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(details_table)
    story.append(Spacer(1, 0.15*inch))
    
    # Threat Assessment Section
    story.append(Paragraph("Threat Assessment", heading_style))
    
    # Format threat findings from details
    threat_findings = []
    if isinstance(analysis.details, dict):
        for key, value in analysis.details.items():
            if key != 'attachment':
                # Make key readable (convert snake_case to Title Case)
                readable_key = key.replace('_', ' ').title()
                threat_findings.append([readable_key, str(value)[:100]])
    
    if threat_findings:
        threat_table = Table(threat_findings, colWidths=[2*inch, 4.5*inch])
        threat_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor("#fff3cd")),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.white, colors.HexColor("#fafaf0")]),
            ('PADDING', (0, 0), (-1, -1), 8),
            ('WORDWRAP', (0, 0), (-1, -1), True),
        ]))
        story.append(threat_table)
    else:
        story.append(Paragraph("No specific threat indicators detected.", normal_style))
    
    story.append(Spacer(1, 0.15*inch))
    
    # Attachment Analysis
    if analysis.details.get('attachment'):
        story.append(Paragraph("Attachment Analysis", heading_style))
        attachment = analysis.details['attachment']
        
        att_data = [
            ["Status", attachment.get('reason', 'Unknown')],
            ["MIME Type", attachment.get('mime', 'N/A')],
            ["Safe", "✓ Yes" if attachment.get('safe') else "✗ No"],
        ]
        
        att_table = Table(att_data, colWidths=[2*inch, 4.5*inch])
        att_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor("#d4edda")),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.white, colors.HexColor("#f9fdf9")]),
            ('PADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(att_table)
        story.append(Spacer(1, 0.15*inch))
    
    # Recommendations Section
    story.append(Paragraph("Recommendations", heading_style))
    
    recommendations = []
    if analysis.risk_level == "HIGH":
        recommendations = [
            "🚫 DO NOT click any links in this email",
            "🚫 DO NOT download or open attachments",
            "✓ Report this email to your IT security team immediately",
            "✓ Delete the email permanently",
            "✓ Add sender to blocklist if possible"
        ]
        rec_color = colors.HexColor("#f8d7da")
    elif analysis.risk_level == "MEDIUM":
        recommendations = [
            "⚠️ Verify the sender identity before taking any action",
            "⚠️ Do not click links unless you can confirm the sender",
            "✓ Be cautious with attachments",
            "✓ Contact the sender through another channel if unsure",
            "✓ Report to IT if you have any concerns"
        ]
        rec_color = colors.HexColor("#fff3cd")
    else:
        recommendations = [
            "✓ This email appears to be legitimate",
            "✓ Standard email security practices apply",
            "✓ Keep antivirus protection active"
        ]
        rec_color = colors.HexColor("#d4edda")
    
    rec_data = [[rec] for rec in recommendations]
    rec_table = Table(rec_data, colWidths=[6.5*inch])
    rec_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), rec_color),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('PADDING', (0, 0), (-1, -1), 10),
        ('LEFTPADDING', (0, 0), (-1, -1), 15),
    ]))
    story.append(rec_table)
    story.append(Spacer(1, 0.2*inch))
    
    # Disclaimer
    disclaimer_style = ParagraphStyle(
        'Disclaimer',
        parent=styles['Normal'],
        fontSize=9,
        textColor=colors.grey,
        alignment=0
    )
    story.append(Paragraph(
        "<b>Disclaimer:</b> This report is generated by PhishGuard automated analysis system. "
        "While efforts are made to provide accurate threat assessment, human review is recommended for critical decisions. "
        "Always exercise caution with email communications from unknown sources.",
        disclaimer_style
    ))
    
    # Build PDF with custom header/footer
    doc.build(story, onFirstPage=on_page_change, onLaterPages=on_page_change)
    
    buffer.seek(0)
    pdf_filename = _generate_pdf_filename(analysis)
    
    return send_file(
        buffer,
        as_attachment=True,
        download_name=pdf_filename,
        mimetype='application/pdf'
    )


@analyzer_bp.route('/report/<int:analysis_id>/csv')
@login_required
def download_report_csv(analysis_id):
    """Download analysis report as CSV"""
    analysis = EmailAnalysis.query.get_or_404(analysis_id)
    
    # Only allow owner or admin to download
    if analysis.user_id != current_user.id and not current_user.is_admin():
        abort(403)

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    
    # Write header
    writer.writerow(['PhishGuard Analysis Report'])
    writer.writerow([])
    
    # Write analysis metadata
    writer.writerow(['Analysis Information'])
    writer.writerow(['Analysis ID', analysis.id])
    writer.writerow(['File Name', analysis.filename])
    writer.writerow(['Analyzed On', analysis.timestamp.strftime('%Y-%m-%d %H:%M:%S')])
    writer.writerow(['Analyzed By', current_user.email if hasattr(current_user, 'email') else current_user.username])
    writer.writerow([])
    
    # Risk assessment
    writer.writerow(['Risk Assessment'])
    writer.writerow(['Risk Level', analysis.risk_level])
    writer.writerow(['Confidence Score', f"{analysis.score}/100"])
    writer.writerow([])
    
    # Detailed findings
    writer.writerow(['Threat Findings'])
    
    details = analysis.details if isinstance(analysis.details, dict) else {}
    
    # Headers analysis
    if 'headers' in details:
        header_details = details['headers']
        writer.writerow(['Headers Analysis'])
        writer.writerow(['Score', f"{header_details.get('score', 0)}/100"])
        writer.writerow(['From Domain', header_details.get('from_domain', 'N/A')])
        writer.writerow(['External Sender', 'Yes' if header_details.get('external') else 'No'])
        for reason in header_details.get('reasons', []):
            writer.writerow(['', f"• {reason}"])
        writer.writerow([])
    
    # Keywords analysis
    if 'keywords' in details:
        keyword_details = details['keywords']
        writer.writerow(['Content Analysis'])
        writer.writerow(['Score', f"{keyword_details.get('score', 0)}/100"])
        writer.writerow(['Phishing Keywords Found', ', '.join(keyword_details.get('matches', []))])
        for reason in keyword_details.get('reasons', []):
            writer.writerow(['', f"• {reason}"])
        writer.writerow([])
    
    # URLs analysis
    if 'urls' in details:
        url_list = details['urls']
        writer.writerow(['URL Analysis'])
        writer.writerow(['Total URLs Found', len(url_list)])
        for idx, url_data in enumerate(url_list, 1):
            writer.writerow([f'URL {idx}', url_data.get('url', 'N/A')])
            writer.writerow(['Domain', url_data.get('domain', 'N/A')])
            writer.writerow(['Risk Score', f"{url_data.get('score', 0)}/100"])
            for reason in url_data.get('reasons', []):
                writer.writerow(['', f"• {reason}"])
        writer.writerow([])
    
    # Attachment analysis
    if 'attachment' in details:
        att = details['attachment']
        writer.writerow(['Attachment Analysis'])
        writer.writerow(['Status', att.get('reason', 'Unknown')])
        writer.writerow(['MIME Type', att.get('mime', 'N/A')])
        writer.writerow(['Safe', 'Yes' if att.get('safe') else 'No'])
        writer.writerow([])
    
    # Recommendations
    writer.writerow(['Recommendations'])
    if analysis.risk_level == "HIGH":
        recommendations = [
            "🚫 DO NOT click any links in this email",
            "🚫 DO NOT download or open attachments",
            "✓ Report this email to your IT security team immediately",
            "✓ Delete the email permanently",
            "✓ Add sender to blocklist if possible"
        ]
    elif analysis.risk_level == "MEDIUM":
        recommendations = [
            "⚠️ Verify the sender identity before taking any action",
            "⚠️ Do not click links unless you can confirm the sender",
            "✓ Be cautious with attachments",
            "✓ Contact the sender through another channel if unsure",
            "✓ Report to IT if you have any concerns"
        ]
    else:
        recommendations = [
            "✓ This email appears to be legitimate",
            "✓ Standard email security practices apply",
            "✓ Keep antivirus protection active"
        ]
    
    for rec in recommendations:
        writer.writerow([rec])
    
    writer.writerow([])
    writer.writerow(['Disclaimer'])
    writer.writerow(['This report is generated by PhishGuard automated analysis system.'])
    writer.writerow(['While efforts are made to provide accurate threat assessment,'])
    writer.writerow(['human review is recommended for critical decisions.'])
    
    # Create the response
    buffer.seek(0)
    csv_filename = f"PhishGuard_Report_{analysis.risk_level}_{analysis.timestamp.strftime('%Y-%m-%d')}_{analysis.filename.replace('/', '_').replace(chr(92), '_')[:30]}.csv"
    
    return send_file(
        io.BytesIO(buffer.getvalue().encode('utf-8')),
        as_attachment=True,
        download_name=csv_filename,
        mimetype='text/csv'
    )
