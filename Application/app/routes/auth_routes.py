import hashlib
import secrets
import smtplib
from email.mime.text import MIMEText
from flask import Blueprint, request, jsonify, render_template, session, current_app
from app.db import get_conn, get_cursor
from datetime import datetime
import os

auth_bp = Blueprint("auth", __name__)

# === Email Sender ===
def send_verification_email(email, token):
    base_url = current_app.config.get("ALLOWED_ORIGINS", [])
    verify_link = f"{base_url}/verify?token={token}"

    subject = "[Coharas] Please verify your email"
    body = f"""
    Hello!

    Thank you for signing up for Coharas.
    Please verify your email by clicking the link below:

    🔗 {verify_link}

    This link will confirm your account and activate email-verified features.
    """

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = "administrator@coharas.com"
    msg["To"] = email

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as smtp:
            smtp.starttls()
            smtp.login(
                current_app.config.get("SMTP_USER"),
                current_app.config.get("SMTP_PASS")
            )
            smtp.send_message(msg)
        print(f"✅ Verification email sent to {email}")
    except Exception as e:
        print(f"❌ Failed to send verification email to {email}: {e}")


# === Pages ===
@auth_bp.get("/signup")
def signup_page():
    return render_template("signup.html")


@auth_bp.get("/login")
def login_page():
    return render_template("login.html")


@auth_bp.get("/verify")
def verify_email():
    """Email verification endpoint"""
    token = request.args.get("token")
    if not token:
        return render_template("verify_result.html", message="❌ Invalid verification link.")

    conn = get_conn()
    with get_cursor(conn) as cur:
        cur.execute("SELECT email FROM coharas WHERE email_token=%s", (token,))
        user = cur.fetchone()

        if not user:
            return render_template("verify_result.html", message="⚠️ Invalid or expired verification token.")

        cur.execute("""
            UPDATE coharas
            SET email_verified=1, email_token=NULL
            WHERE email=%s
        """, (user["email"],))
        conn.commit()
    conn.close()

    return render_template("verify_result.html", message="✅ Your email has been successfully verified!")


# === Sign-up API ===
@auth_bp.post("/api/signup")
def signup_api():
    data = request.json
    user_id = data.get("id")
    password = data.get("password")
    name = data.get("name")
    nickname = data.get("nickname")
    email = data.get("email")
    phone = data.get("phone")
    github_token = data.get("github_token")

    # ✅ 필수 필드 검사
    if not all([user_id, password, name, nickname, email, phone, github_token]):
        return jsonify({"status": "error", "message": "All fields are required."}), 400

    # ✅ 패스워드 및 이메일 토큰 생성
    hashed_pw = hashlib.sha512(password.encode()).hexdigest()
    email_token = secrets.token_urlsafe(32)

    print(f"[DEBUG] Generated email_token: {email_token}")  # ← 반드시 값이 찍혀야 함

    query = """
        INSERT INTO coharas (id, password, name, nickname, email, phone, github_token, email_token)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """

    try:
        conn = get_conn()
        with get_cursor(conn) as cur:
            cur.execute(query, (user_id, hashed_pw, name, nickname, email, phone, github_token, email_token))
            conn.commit()

        # ✅ 인증 메일 전송
        send_verification_email(email, email_token)

        return jsonify({
            "status": "success",
            "message": "Sign-up successful. Please check your email for verification."
        })

    except Exception as e:
        print(f"[ERROR] Database insert failed: {e}")
        if "Duplicate entry" in str(e):
            if "PRIMARY" in str(e):
                msg = "This ID is already in use."
            elif "email" in str(e):
                msg = "This email is already registered."
            elif "phone" in str(e):
                msg = "This phone number is already registered."
            elif "github_token" in str(e):
                msg = "This GitHub token is already registered."
            elif "nickname" in str(e):
                msg = "This nickname is already taken."
            else:
                msg = "Duplicate entry found."
            return jsonify({"status": "error", "message": msg}), 409
        return jsonify({"status": "error", "message": f"Database error: {str(e)}"}), 500
    finally:
        if 'conn' in locals():
            conn.close()


# === Login API ===
@auth_bp.post("/api/login")
def login_api():
    data = request.json
    user_id = data.get("id")
    password = data.get("password")

    if not user_id or not password:
        return jsonify({"status": "error", "message": "Please enter both ID and password."}), 400

    hashed_pw = hashlib.sha512(password.encode()).hexdigest()
    query = "SELECT * FROM coharas WHERE id = %s AND password = %s"

    conn = get_conn()
    with get_cursor(conn) as cur:
        cur.execute(query, (user_id, hashed_pw))
        user = cur.fetchone()
    conn.close()

    if not user:
        return jsonify({"status": "error", "message": "Invalid ID or password."}), 401
    if not user["email_verified"]:
        return jsonify({"status": "error", "message": "Email not verified. Please check your inbox."}), 403

    session["nickname"] = user["nickname"]
    session["admin_permission"] = user["admin_permission"]
    session["phone_verified"] = user["phone_verified"]
    session["email_verified"] = user["email_verified"]
    session["github_verified"] = user["github_verified"]

    return jsonify({"status": "success", "message": "Login successful."}), 200


# === Logout API ===
@auth_bp.post("/api/logout")
def logout_api():
    session.clear()
    return jsonify({"status": "success", "message": "Logged out successfully."})
