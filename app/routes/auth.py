# app/routes/auth.py
from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from flask_login import login_user, logout_user, login_required, current_user
import pyotp
import qrcode
import io
import base64
from app import db
from app.models.user import User

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            session['2fa_verified'] = False
            flash("Please complete Two-Factor Authentication", "info")
            return redirect(url_for('auth.verify_2fa'))
        
        flash("Invalid username or password", "danger")
    
    return render_template('login.html')


@auth_bp.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    if not current_user.is_authenticated:
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        token = request.form.get('token')
        totp = pyotp.TOTP(current_user.totp_secret)
        
        if totp.verify(token):
            session['2fa_verified'] = True
            flash("✅ 2FA Successful! Welcome.", "success")
            return redirect(url_for('dashboard.index'))
        else:
            flash("❌ Invalid 2FA code. Try again.", "danger")
            return redirect(url_for('auth.verify_2fa'))

    # Generate QR Code
    totp = pyotp.TOTP(current_user.totp_secret)
    uri = totp.provisioning_uri(current_user.username, issuer_name="PhishGuard")

    try:
        qr = qrcode.QRCode(version=1, box_size=8, border=4)
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        img_str = base64.b64encode(buffer.getvalue()).decode('utf-8')
        qr_code = f"data:image/png;base64,{img_str}"
    except Exception as e:
        qr_code = None
        flash("Could not generate QR code. Please use the secret key instead.", "warning")

    return render_template('verify_2fa.html', 
                         qr_code=qr_code, 
                         secret=current_user.totp_secret)


@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash("You have been logged out successfully.", "success")
    return redirect(url_for('auth.login'))


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """User registration endpoint"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        password_confirm = request.form.get('password_confirm')
        
        # Validation
        if not username or not password or not password_confirm:
            flash("All fields are required", "danger")
            return redirect(url_for('auth.register'))
        
        if len(username) < 3:
            flash("Username must be at least 3 characters", "danger")
            return redirect(url_for('auth.register'))
        
        if len(password) < 6:
            flash("Password must be at least 6 characters", "danger")
            return redirect(url_for('auth.register'))
        
        if password != password_confirm:
            flash("Passwords do not match", "danger")
            return redirect(url_for('auth.register'))
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash("Username already exists", "danger")
            return redirect(url_for('auth.register'))
        
        # Create new user with analyst role
        user = User(username=username, role='analyst')
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash("✅ Registration successful! Please log in.", "success")
        return redirect(url_for('auth.login'))
    
    return render_template('register.html')