# app/__init__.py
from flask import Flask, redirect, url_for, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user
from dotenv import load_dotenv

load_dotenv()

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.login_message_category = "info"

def create_app():
    app = Flask(__name__)
    app.config.from_object('app.config.Config')

    db.init_app(app)
    login_manager.init_app(app)

    # Import blueprints
    from app.routes.auth import auth_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.analyzer import analyzer_bp

    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(dashboard_bp, url_prefix='/')
    app.register_blueprint(analyzer_bp, url_prefix='/analyze')

    # Context processor for templates
    @app.context_processor
    def inject_context():
        return {
            'current_user': current_user,
            'session': session
        }

    # 2FA Middleware
    @app.before_request
    def check_2fa():
        if request.endpoint and request.endpoint.startswith('static'):
            return None
            
        if current_user.is_authenticated and not session.get('2fa_verified', False):
            allowed = {'auth.login', 'auth.verify_2fa', 'auth.logout'}
            if request.endpoint not in allowed:
                return redirect(url_for('auth.verify_2fa'))

    with app.app_context():
        db.create_all()

    return app


@login_manager.user_loader
def load_user(user_id):
    from app.models.user import User
    return User.query.get(int(user_id))