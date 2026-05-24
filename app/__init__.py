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

    # Register Blueprints
    from app.routes.auth import auth_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.analyzer import analyzer_bp

    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(dashboard_bp, url_prefix='/')
    app.register_blueprint(analyzer_bp, url_prefix='/analyze')

    # Make current_user available in templates
    @app.context_processor
    def inject_user():
        return dict(current_user=current_user)

    # 2FA Enforcement Middleware
    @app.before_request
    def check_2fa():
        if request.endpoint and request.endpoint.startswith('static'):
            return None

        if current_user.is_authenticated:
            # Skip if 2FA is already verified or on allowed pages
            allowed_endpoints = ['auth.login', 'auth.verify_2fa', 'auth.logout', 'static']
            if request.endpoint not in allowed_endpoints:
                if not session.get('2fa_verified', False):
                    return redirect(url_for('auth.verify_2fa'))

    # Create database tables
    with app.app_context():
        db.create_all()

    return app


@login_manager.user_loader
def load_user(user_id):
    from app.models.user import User
    return User.query.get(int(user_id))
