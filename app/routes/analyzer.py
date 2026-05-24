# app/routes/analyzer.py
from flask import Blueprint, render_template, request, flash, redirect, url_for, abort, send_file
from flask_login import login_required, current_user
from app.services.risk_scorer import calculate_risk
from app.services.quarantine import QuarantineManager
from app.services.attachment_checker import check_attachment
from app.models.analysis import EmailAnalysis
from app import db
import io
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

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


@analyzer_bp.route('/report/<int:analysis_id>')
@login_required
def download_report(analysis_id):
    """Download PDF Report"""
    analysis = EmailAnalysis.query.get_or_404(analysis_id)
    
    # Only allow owner or admin to download
    if analysis.user_id != current_user.id and not current_user.is_admin():
        abort(403)

    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    
    p.setTitle(f"PhishGuard Report - {analysis.filename}")
    p.drawString(100, 750, "🛡️ PhishGuard - Phishing Analysis Report")
    p.drawString(100, 720, f"File Name: {analysis.filename}")
    p.drawString(100, 690, f"Risk Level: {analysis.risk_level}")
    p.drawString(100, 660, f"Score: {analysis.score}/100")
    p.drawString(100, 630, f"Analyzed On: {analysis.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
    
    p.drawString(100, 580, "Detailed Analysis:")
    y = 550
    details_text = str(analysis.details)
    for line in details_text.split('\n')[:15]:  # Limit lines
        p.drawString(100, y, line[:80])
        y -= 20

    p.showPage()
    p.save()

    buffer.seek(0)
    return send_file(buffer, as_attachment=True, 
                    download_name=f"phishguard_report_{analysis.id}.pdf")
