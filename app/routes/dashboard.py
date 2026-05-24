from flask import Blueprint, render_template, redirect, url_for
from flask_login import login_required, current_user
from app.models.analysis import EmailAnalysis

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/')
@login_required
def index():
    # Get recent analyses for the current user
    analyses = EmailAnalysis.query.filter_by(user_id=current_user.id)\
                .order_by(EmailAnalysis.timestamp.desc()).limit(10).all()
    
    total_analyzed = EmailAnalysis.query.filter_by(user_id=current_user.id).count()
    high_risk = EmailAnalysis.query.filter_by(user_id=current_user.id, risk_level="HIGH").count()
    
    return render_template('dashboard.html', 
                         analyses=analyses,
                         total_analyzed=total_analyzed,
                         high_risk=high_risk)