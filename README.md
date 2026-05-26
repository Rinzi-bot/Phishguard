
# PhishGuard - Email Phishing Detection Tool

A comprehensive phishing email detection tool that analyzes emails and identifies phishing attempts using pattern recognition and heuristics.

## Core Features

### 🔐 Security
- **Secure Login** with RBAC (Admin/Analyst roles)
- **2FA Authentication** using PyOTP with QR code generation
- **Role-Based Access Control** enforcing admin-only features
- **Session Management** with automatic logout and cleanup

### 📧 Email Analysis Engine
- **URL Analysis** with suspicious domain detection
- **Keyword Pattern Matching** for urgency indicators and financial terms
- **Header Analysis** for spoofed sender detection
- **Attachment Safety Checking** for potentially dangerous files
- **Visual Risk Indicators** (Red/Yellow/Green with detailed reasoning)

### 🛡️ Threat Management
- **Email Quarantine** feature for flagged messages
- **Exportable Analysis Reports** (PDF and CSV formats)
- **Smart Report Naming** (`PhishGuard_Report_[RISK]_[DATE]_[EMAIL]`)
- **Professional PDF Generation** with headers, footers, and branding

### 👨‍💼 Admin Dashboard
- **User Management** (create, promote, deactivate accounts)
- **Quarantine Management** view and operations
- **Threat Analytics** with risk distribution charts
- **System Statistics** and user activity tracking

## Technical Stack

- **Backend:** Python Flask with SQLAlchemy ORM
- **Database:** SQLite
- **Email Parsing:** Python email library, BeautifulSoup
- **PDF Generation:** ReportLab
- **2FA:** PyOTP with QR code support
- **Security Scanning:** Bandit (static analysis), OWASP ZAP (dynamic)

## Installation

### Prerequisites
- Python 3.8+
- pip (Python package manager)

### Setup Steps

1. **Clone the repository**
   ```bash
   cd C:\xampp\htdocs\phishguard
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Create admin user**
   ```bash
   python cli.py create-admin
   ```
   Follow prompts to enter admin username and password.

4. **Start the application**
   ```bash
   python run.py
   ```
   Application runs at `http://localhost:5000`

## Usage

### Web Interface
1. Navigate to `http://localhost:5000`
2. Login with admin credentials
3. Upload or paste email for analysis
4. Review risk assessment with visual indicators
5. Download analysis reports (PDF/CSV)
6. Access admin dashboard for system management

### CLI Admin Utility
Manage users without web interface:

```bash
# Create admin user
python cli.py create-admin

# List all users
python cli.py list-users

# Promote user to admin
python cli.py promote <username>

# Demote user from admin
python cli.py demote <username>

# Activate/deactivate user
python cli.py activate <username>
python cli.py deactivate <username>
```

## Security Features

### Authentication
- Secure password hashing with Werkzeug
- Session-based authentication
- 2FA with time-based one-time passwords (TOTP)
- QR code generation for mobile authenticator apps

### Authorization
- Role-based access control (RBAC)
- Admin-only routes with decorator enforcement
- Default analyst role for new registrations
- Granular permission system

### Code Security
- **Bandit** - Static security analysis
- **OWASP ZAP** - Dynamic security testing
- **SonarQube** - Code quality and security scanning

## Analysis Features

### Risk Indicators
- 🔴 **Red** - High risk, likely phishing
- 🟡 **Yellow** - Medium risk, requires attention
- 🟢 **Green** - Low risk, likely legitimate

### Detailed Analysis Includes
- Sender authentication (SPF/DKIM/DMARC)
- URL reputation and domain analysis
- Keyword heuristics for urgency/financial language
- Attachment scanning and risk assessment
- Structured threat report with reasoning

## Project Requirements Met

✅ Secure login with RBAC and 2FA  
✅ Email analysis engine (URL, keyword, header, attachment)  
✅ Visual risk indicators (Red/Yellow/Green)  
✅ Email quarantine feature  
✅ Exportable reports (PDF/CSV)  
✅ Email parsing (email library, BeautifulSoup)  
✅ Pattern matching (regular expressions)  
✅ Known malicious indicators database  

## File Structure

```
phishguard/
├── app/
│   ├── __init__.py           # Flask app initialization
│   ├── decorators.py         # RBAC decorators
│   ├── routes/
│   │   ├── auth.py           # Login/logout/register
│   │   ├── analyzer.py       # Email analysis & reports
│   │   ├── admin.py          # Admin dashboard routes
│   │   └── api.py            # API endpoints
│   ├── models.py             # Database models
│   ├── templates/            # HTML templates
│   └── static/               # CSS/JavaScript
├── cli.py                    # Admin CLI utility
├── run.py                    # Application entry point
├── requirements.txt          # Python dependencies
└── README.md                 # This file
```

## Learning Outcomes

- **Email Security:** Understanding phishing tactics and detection
- **Pattern Recognition:** Implementing heuristic-based threat detection
- **Threat Intelligence:** Building and maintaining threat databases
- **Web Development:** Flask, SQLAlchemy, Jinja2 templates
- **Security Best Practices:** RBAC, 2FA, secure authentication
- **API Design:** RESTful endpoints with proper authorization

## Troubleshooting

### Login Issues
- Ensure admin user was created: `python cli.py create-admin`
- Check database file exists in `instance/`

### Email Upload Problems
- Verify email format (.eml files)
- Check file size limits in Flask config

### Report Generation Fails
- Ensure ReportLab is installed: `pip install reportlab`
- Check file write permissions in working directory

## Contributing

Submit issues and enhancements via GitHub issues and pull requests.

## License

This project is provided as-is for educational purposes.

---

**Last Updated:** 2026-05-26  
**Version:** 1.0.0
