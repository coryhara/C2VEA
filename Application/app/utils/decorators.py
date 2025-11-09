from functools import wraps
from flask import session, jsonify, redirect, url_for, request

# === 로그인 여부 검사 ===
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "nickname" not in session:
            if request.path.startswith("/api/"):
                return jsonify({"status": "error", "message": "Login required."}), 401
            return redirect(url_for("index.index"))
        return f(*args, **kwargs)
    return decorated_function


# === 이메일 인증 여부 검사 ===
def email_verified_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("email_verified"):
            if request.path.startswith("/api/"):
                return jsonify({"status": "error", "message": "Email verification required."}), 403
            return redirect(url_for("index.index"))
        return f(*args, **kwargs)
    return decorated_function


# === GitHub 인증 여부 검사 ===
def github_verified_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("github_verified"):
            if request.path.startswith("/api/"):
                return jsonify({"status": "error", "message": "GitHub verification required."}), 403
            return redirect(url_for("index.index"))
        return f(*args, **kwargs)
    return decorated_function


# === 본인(전화번호) 인증 여부 검사 ===
def phone_verified_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("phone_verified"):
            if request.path.startswith("/api/"):
                return jsonify({"status": "error", "message": "Phone verification required."}), 403
            return redirect(url_for("index.index"))
        return f(*args, **kwargs)
    return decorated_function


# === 관리자 권한 검사 ===
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("admin_permission"):
            if request.path.startswith("/api/"):
                return jsonify({"status": "error", "message": "Admin permission required."}), 403
            return redirect(url_for("index.index"))
        return f(*args, **kwargs)
    return decorated_function