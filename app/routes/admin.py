# app/routes/admin.py
from flask import Blueprint, render_template, jsonify, request, flash, redirect, url_for, abort
from flask_login import login_required, current_user
from app.decorators import require_admin
from app.models.analysis import EmailAnalysis
from app.models.user import User
from app.services.quarantine import QuarantineManager
from app import db
import json

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')
quarantine = QuarantineManager()


@admin_bp.route('/')
@login_required
@require_admin
def dashboard():
    """Admin dashboard with system-wide statistics"""
    total_analyses = EmailAnalysis.query.count()
    high_risk_count = EmailAnalysis.query.filter_by(risk_level="HIGH").count()
    medium_risk_count = EmailAnalysis.query.filter_by(risk_level="MEDIUM").count()
    low_risk_count = EmailAnalysis.query.filter_by(risk_level="LOW").count()
    
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    admin_users = User.query.filter_by(role='admin').count()
    
    # Get recent high-risk analyses
    recent_high_risk = EmailAnalysis.query\
        .filter_by(risk_level="HIGH")\
        .order_by(EmailAnalysis.timestamp.desc())\
        .limit(10).all()
    
    # Get all users with their analysis counts
    users_stats = db.session.query(
        User.id, User.username, User.role, User.is_active,
        db.func.count(EmailAnalysis.id).label('analysis_count'),
        db.func.count(db.case(
            (EmailAnalysis.risk_level == 'HIGH', 1)
        )).label('high_risk_count')
    ).outerjoin(EmailAnalysis).group_by(User.id).all()
    
    return render_template('admin_dashboard.html',
                         total_analyses=total_analyses,
                         high_risk_count=high_risk_count,
                         medium_risk_count=medium_risk_count,
                         low_risk_count=low_risk_count,
                         total_users=total_users,
                         active_users=active_users,
                         admin_users=admin_users,
                         recent_high_risk=recent_high_risk,
                         users_stats=users_stats)


@admin_bp.route('/quarantine')
@login_required
@require_admin
def quarantine_management():
    """View and manage quarantined emails"""
    quarantined_emails = quarantine.get_quarantined_emails()
    return render_template('admin_quarantine.html', quarantined_emails=quarantined_emails)


@admin_bp.route('/users')
@login_required
@require_admin
def users_management():
    """Manage users and their roles"""
    users = User.query.all()
    return render_template('admin_users.html', users=users)


@admin_bp.route('/users/<int:user_id>/toggle-role', methods=['POST'])
@login_required
@require_admin
def toggle_user_role(user_id):
    """Toggle user role between analyst and admin"""
    user = User.query.get_or_404(user_id)
    
    # Prevent deactivating the last admin
    if current_user.id == user_id and user.role == 'admin':
        admin_count = User.query.filter_by(role='admin').count()
        if admin_count <= 1:
            flash("Cannot remove the last admin user", "danger")
            return redirect(url_for('admin.users_management'))
    
    user.role = 'analyst' if user.role == 'admin' else 'admin'
    db.session.commit()
    
    flash(f"User {user.username} role changed to {user.role}", "success")
    return redirect(url_for('admin.users_management'))


@admin_bp.route('/users/<int:user_id>/toggle-status', methods=['POST'])
@login_required
@require_admin
def toggle_user_status(user_id):
    """Activate or deactivate user"""
    user = User.query.get_or_404(user_id)
    
    # Prevent deactivating yourself
    if current_user.id == user_id:
        flash("Cannot deactivate your own account", "danger")
        return redirect(url_for('admin.users_management'))
    
    user.is_active = not user.is_active
    db.session.commit()
    
    status = "activated" if user.is_active else "deactivated"
    flash(f"User {user.username} has been {status}", "success")
    return redirect(url_for('admin.users_management'))


@admin_bp.route('/analytics')
@login_required
@require_admin
def analytics():
    """Threat intelligence and analytics dashboard"""
    # Risk level distribution
    risk_distribution = db.session.query(
        EmailAnalysis.risk_level,
        db.func.count(EmailAnalysis.id).label('count')
    ).group_by(EmailAnalysis.risk_level).all()
    
    # Average risk scores
    stats = db.session.query(
        db.func.avg(EmailAnalysis.score).label('avg_score'),
        db.func.max(EmailAnalysis.score).label('max_score'),
        db.func.min(EmailAnalysis.score).label('min_score')
    ).first()
    
    # Top threat indicators (if stored)
    # This would require extending the analysis model to track individual threat indicators
    
    return render_template('admin_analytics.html',
                         risk_distribution=risk_distribution,
                         avg_score=round(stats.avg_score or 0, 1),
                         max_score=stats.max_score or 0,
                         min_score=stats.min_score or 0)


@admin_bp.route('/api/user-stats/<int:user_id>')
@login_required
@require_admin
def get_user_stats(user_id):
    """Get detailed stats for a specific user (JSON API)"""
    user = User.query.get_or_404(user_id)
    
    analyses = EmailAnalysis.query.filter_by(user_id=user_id)\
        .order_by(EmailAnalysis.timestamp.desc()).all()
    
    risk_counts = {
        'HIGH': len([a for a in analyses if a.risk_level == 'HIGH']),
        'MEDIUM': len([a for a in analyses if a.risk_level == 'MEDIUM']),
        'LOW': len([a for a in analyses if a.risk_level == 'LOW']),
    }
    
    avg_score = sum([a.score for a in analyses]) / len(analyses) if analyses else 0
    
    return jsonify({
        'username': user.username,
        'role': user.role,
        'is_active': user.is_active,
        'total_analyses': len(analyses),
        'risk_distribution': risk_counts,
        'average_score': round(avg_score, 1),
        'recent_analyses': [{
            'id': a.id,
            'filename': a.filename,
            'risk_level': a.risk_level,
            'score': a.score,
            'timestamp': a.timestamp.isoformat()
        } for a in analyses[:5]]
    })
