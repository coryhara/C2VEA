import base64
import hashlib
import re
import secrets
import smtplib
from email.mime.text import MIMEText

from cryptography.fernet import Fernet
from flask import Blueprint, current_app, jsonify, render_template, request, session
from werkzeug.security import check_password_hash, generate_password_hash

from app.db import get_conn, get_cursor

auth_bp = Blueprint("auth", __name__)

LEGACY_SHA512_RE = re.compile(r"^[a-f0-9]{128}$")


def _build_verify_base_url() -> str:
    explicit = (current_app.config.get("PUBLIC_BASE_URL") or "").strip()
    if explicit:
        return explicit.rstrip("/")

    raw = current_app.config.get("ALLOWED_ORIGINS", "")
    first = raw.replace(";", ",").split(",")[0].strip()
    return first.rstrip("/")


def _get_token_fernet() -> Fernet:
    explicit = (current_app.config.get("GITHUB_TOKEN_ENCRYPTION_KEY") or "").strip()
    material = explicit or current_app.config["SECRET_KEY"]
    key = base64.urlsafe_b64encode(hashlib.sha256(material.encode("utf-8")).digest())
    return Fernet(key)


def _encrypt_github_token(token: str) -> str:
    encrypted = _get_token_fernet().encrypt(token.encode("utf-8"))
    return encrypted.decode("utf-8")


def _github_token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _is_legacy_sha512_hash(value: str) -> bool:
    return bool(value and LEGACY_SHA512_RE.fullmatch(value))


def _verify_and_upgrade_password(user: dict, plain_password: str) -> bool:
    stored = user.get("password") or ""

    if _is_legacy_sha512_hash(stored):
        legacy_hash = hashlib.sha512(plain_password.encode("utf-8")).hexdigest()
        if legacy_hash != stored:
            return False

        upgraded = generate_password_hash(plain_password, method="scrypt")
        conn = get_conn()
        try:
            with get_cursor(conn) as cur:
                cur.execute(
                    "UPDATE coharas SET password=%s WHERE id=%s",
                    (upgraded, user["id"])
                )
            conn.commit()
            user["password"] = upgraded
        finally:
            conn.close()
        return True

    try:
        return check_password_hash(stored, plain_password)
    except Exception:
        return False


def send_verification_email(email: str, token: str):
    base_url = _build_verify_base_url()
    verify_link = f"{base_url}/verify?token={token}"

    subject = "[Coharas] Please verify your email"
    body = (
        "Hello,\n\n"
        "Thank you for signing up for Coharas.\n"
        "Please verify your email by clicking the link below:\n\n"
        f"{verify_link}\n\n"
        "This link will activate email-verified features."
    )

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = "administrator@coharas.com"
    msg["To"] = email

    with smtplib.SMTP("smtp.gmail.com", 587) as smtp:
        smtp.starttls()
        smtp.login(
            current_app.config.get("SMTP_USER"),
            current_app.config.get("SMTP_PASS")
        )
        smtp.send_message(msg)


@auth_bp.get("/signup")
def signup_page():
    return render_template("signup.html")


@auth_bp.get("/login")
def login_page():
    return render_template("login.html")


@auth_bp.get("/verify")
def verify_email():
    token = (request.args.get("token") or "").strip()
    if not token:
        return render_template("verify_result.html", message="Invalid verification link.")

    conn = get_conn()
    try:
        with get_cursor(conn) as cur:
            cur.execute("SELECT email FROM coharas WHERE email_token=%s", (token,))
            user = cur.fetchone()
            if not user:
                return render_template("verify_result.html", message="Invalid or expired verification token.")

            cur.execute(
                """
                UPDATE coharas
                SET email_verified=1, email_token=NULL
                WHERE email=%s
                """,
                (user["email"],)
            )
        conn.commit()
    finally:
        conn.close()

    return render_template("verify_result.html", message="Your email has been successfully verified.")


@auth_bp.post("/api/signup")
def signup_api():
    data = request.json or {}
    user_id = (data.get("id") or "").strip()
    password = data.get("password") or ""
    name = (data.get("name") or "").strip()
    nickname = (data.get("nickname") or "").strip()
    email = (data.get("email") or "").strip()
    phone = (data.get("phone") or "").strip()
    github_token = (data.get("github_token") or "").strip()

    if not all([user_id, password, name, nickname, email, phone, github_token]):
        return jsonify({"status": "error", "message": "All fields are required."}), 400

    hashed_pw = generate_password_hash(password, method="scrypt")
    email_token = secrets.token_urlsafe(32)
    github_token_enc = _encrypt_github_token(github_token)
    github_token_hash = _github_token_hash(github_token)

    conn = get_conn()
    try:
        with get_cursor(conn) as cur:
            cur.execute(
                "SELECT 1 FROM coharas WHERE github_token_hash=%s LIMIT 1",
                (github_token_hash,)
            )
            if cur.fetchone():
                return jsonify({"status": "error", "message": "This GitHub token is already registered."}), 409

            cur.execute(
                """
                INSERT INTO coharas
                (id, password, name, nickname, email, phone, github_token, github_token_hash, email_token)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    user_id,
                    hashed_pw,
                    name,
                    nickname,
                    email,
                    phone,
                    github_token_enc,
                    github_token_hash,
                    email_token,
                ),
            )
        conn.commit()

        try:
            send_verification_email(email, email_token)
        except Exception as e:
            current_app.logger.exception("Verification email send failed: %s", e)
            return jsonify({
                "status": "success",
                "message": "Sign-up successful, but verification email delivery failed. Please contact admin."
            }), 202

        return jsonify({
            "status": "success",
            "message": "Sign-up successful. Please check your email for verification."
        })
    except Exception as e:
        conn.rollback()
        msg = str(e)
        if "Duplicate entry" in msg:
            if "PRIMARY" in msg:
                out = "This ID is already in use."
            elif "email" in msg:
                out = "This email is already registered."
            elif "phone" in msg:
                out = "This phone number is already registered."
            elif "nickname" in msg:
                out = "This nickname is already taken."
            elif "github_token_hash" in msg:
                out = "This GitHub token is already registered."
            else:
                out = "Duplicate entry found."
            return jsonify({"status": "error", "message": out}), 409
        current_app.logger.exception("Sign-up failed: %s", e)
        return jsonify({"status": "error", "message": "Database error occurred."}), 500
    finally:
        conn.close()


@auth_bp.post("/api/login")
def login_api():
    data = request.json or {}
    user_id = (data.get("id") or "").strip()
    password = data.get("password") or ""

    if not user_id or not password:
        return jsonify({"status": "error", "message": "Please enter both ID and password."}), 400

    conn = get_conn()
    try:
        with get_cursor(conn) as cur:
            cur.execute("SELECT * FROM coharas WHERE id = %s", (user_id,))
            user = cur.fetchone()
    finally:
        conn.close()

    if not user or not _verify_and_upgrade_password(user, password):
        return jsonify({"status": "error", "message": "Invalid ID or password."}), 401
    if not user.get("email_verified"):
        return jsonify({"status": "error", "message": "Email not verified. Please check your inbox."}), 403

    session["user_id"] = user["id"]
    session["nickname"] = user["nickname"]
    session["admin_permission"] = user["admin_permission"]
    session["phone_verified"] = user["phone_verified"]
    session["email_verified"] = user["email_verified"]
    session["github_verified"] = user["github_verified"]

    return jsonify({"status": "success", "message": "Login successful."}), 200


@auth_bp.post("/api/logout")
def logout_api():
    session.clear()
    return jsonify({"status": "success", "message": "Logged out successfully."})
