from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from app.services.risk_scorer import calculate_risk
from app.models.analysis import EmailAnalysis
from app import db

api_bp = Blueprint('api', __name__, url_prefix='/api')

@api_bp.route('/analyze', methods=['POST'])
@login_required
def api_analyze():
    """API endpoint for analyzing emails (JSON response)"""
    if 'email_file' not in request.files:
        return jsonify({"error": "No email file provided"}), 400
    
    file = request.files['email_file']
    if file.filename == '':
        return jsonify({"error": "Empty filename"}), 400

    try:
        result = calculate_risk(file.read())
        
        # Save to database
        analysis = EmailAnalysis(
            filename=file.filename,
            risk_level=result['risk_level'],
            score=result['score'],
            details=result['details'],
            user_id=current_user.id
        )
        db.session.add(analysis)
        db.session.commit()

        return jsonify({
            "status": "success",
            "filename": file.filename,
            "risk_level": result['risk_level'],
            "score": result['score'],
            "details": result['details']
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route('/analyses', methods=['GET'])
@login_required
def get_analyses():
    """Get all analyses for current user"""
    analyses = EmailAnalysis.query.filter_by(user_id=current_user.id)\
                .order_by(EmailAnalysis.timestamp.desc()).all()
    
    return jsonify([{
        "id": a.id,
        "filename": a.filename,
        "risk_level": a.risk_level,
        "score": a.score,
        "timestamp": a.timestamp.isoformat()
    } for a in analyses])