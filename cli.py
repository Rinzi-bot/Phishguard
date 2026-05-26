#!/usr/bin/env python
"""
PhishGuard CLI Utility for admin operations
"""
import sys
import getpass
from app import create_app, db
from app.models.user import User

app = create_app()

def create_admin_user():
    """Create a new admin user (interactive)"""
    with app.app_context():
        print("\n=== Create Admin User ===\n")
        
        username = input("Enter username: ").strip()
        if not username or len(username) < 3:
            print("❌ Username must be at least 3 characters")
            return
        
        if User.query.filter_by(username=username).first():
            print(f"❌ Username '{username}' already exists")
            return
        
        password = getpass.getpass("Enter password (min 6 chars): ")
        password_confirm = getpass.getpass("Confirm password: ")
        
        if len(password) < 6:
            print("❌ Password must be at least 6 characters")
            return
        
        if password != password_confirm:
            print("❌ Passwords do not match")
            return
        
        try:
            user = User(username=username, role='admin')
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            
            print(f"\n✅ Admin user '{username}' created successfully!")
            print(f"📱 2FA Secret: {user.totp_secret}")
            print("💡 Save this secret key in your authenticator app\n")
        except Exception as e:
            print(f"❌ Error creating user: {str(e)}")
            db.session.rollback()


def list_users():
    """List all users"""
    with app.app_context():
        users = User.query.all()
        
        if not users:
            print("\n❌ No users found\n")
            return
        
        print("\n=== PhishGuard Users ===\n")
        print(f"{'Username':<15} {'Role':<10} {'Active':<8} {'2FA Secret':<20}")
        print("-" * 53)
        
        for user in users:
            status = "✓" if user.is_active else "✗"
            print(f"{user.username:<15} {user.role:<10} {status:<8} {user.totp_secret[:16]}...")
        
        print()


def promote_to_admin(username):
    """Promote a user to admin"""
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        
        if not user:
            print(f"❌ User '{username}' not found")
            return
        
        if user.role == 'admin':
            print(f"⚠️  User '{username}' is already admin")
            return
        
        user.role = 'admin'
        db.session.commit()
        print(f"✅ User '{username}' promoted to admin")


def demote_to_analyst(username):
    """Demote an admin user to analyst"""
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        
        if not user:
            print(f"❌ User '{username}' not found")
            return
        
        if user.role == 'analyst':
            print(f"⚠️  User '{username}' is already analyst")
            return
        
        # Check if this is the last admin
        admin_count = User.query.filter_by(role='admin').count()
        if admin_count <= 1:
            print("❌ Cannot demote the last admin user")
            return
        
        user.role = 'analyst'
        db.session.commit()
        print(f"✅ User '{username}' demoted to analyst")


def deactivate_user(username):
    """Deactivate a user"""
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        
        if not user:
            print(f"❌ User '{username}' not found")
            return
        
        user.is_active = False
        db.session.commit()
        print(f"✅ User '{username}' deactivated")


def activate_user(username):
    """Activate a user"""
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        
        if not user:
            print(f"❌ User '{username}' not found")
            return
        
        user.is_active = True
        db.session.commit()
        print(f"✅ User '{username}' activated")


def show_help():
    """Show help message"""
    print("""
PhishGuard CLI Utility

Usage:
    python cli.py create-admin       Create a new admin user
    python cli.py list-users         List all users
    python cli.py promote <username>  Promote user to admin
    python cli.py demote <username>   Demote admin to analyst
    python cli.py deactivate <user>   Deactivate a user
    python cli.py activate <user>     Activate a user
    python cli.py help              Show this help message

Examples:
    python cli.py create-admin
    python cli.py promote john_doe
    python cli.py deactivate jane_smith
    """)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        show_help()
        sys.exit(0)
    
    command = sys.argv[1].lower()
    
    if command == 'create-admin':
        create_admin_user()
    elif command == 'list-users':
        list_users()
    elif command == 'promote':
        if len(sys.argv) < 3:
            print("❌ Username required: python cli.py promote <username>")
            sys.exit(1)
        promote_to_admin(sys.argv[2])
    elif command == 'demote':
        if len(sys.argv) < 3:
            print("❌ Username required: python cli.py demote <username>")
            sys.exit(1)
        demote_to_analyst(sys.argv[2])
    elif command == 'deactivate':
        if len(sys.argv) < 3:
            print("❌ Username required: python cli.py deactivate <username>")
            sys.exit(1)
        deactivate_user(sys.argv[2])
    elif command == 'activate':
        if len(sys.argv) < 3:
            print("❌ Username required: python cli.py activate <username>")
            sys.exit(1)
        activate_user(sys.argv[2])
    elif command == 'help':
        show_help()
    else:
        print(f"❌ Unknown command: {command}")
        show_help()
        sys.exit(1)
