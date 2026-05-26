# app/decorators.py
from functools import wraps
from flask import abort, redirect, url_for
from flask_login import current_user


def require_role(*roles):
    """Decorator to restrict access to specific user roles
    
    Usage: @require_role('admin', 'analyst')
    
    Note: Must be used AFTER @login_required decorator
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('auth.login'))
            
            if current_user.role not in roles:
                abort(403)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def require_admin(f):
    """Shortcut decorator to require admin role
    
    Usage: @require_admin
    
    Note: Must be used AFTER @login_required decorator
    """
    return require_role('admin')(f)

