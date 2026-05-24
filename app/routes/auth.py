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