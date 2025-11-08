from functools import wraps
from flask import session, redirect, url_for, jsonify, request

def login_required(template_redirect=True):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if "user_id" not in session:
                if request.path.startswith("/api/") or request.is_json:
                    return jsonify({"status": "error", "message": "Login required"}), 401
                if template_redirect:
                    return redirect(url_for("auth.login_page"))
                return jsonify({"status": "error", "message": "Unauthorized"}), 401
            return func(*args, **kwargs)
        return wrapper
    return decorator