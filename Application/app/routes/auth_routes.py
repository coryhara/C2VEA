from flask import Blueprint, request, jsonify, render_template, session
from app.db import get_conn, get_cursor
import hashlib

auth_bp = Blueprint("auth", __name__)

# === Pages ===
@auth_bp.get("/signup")
def signup_page():
    return render_template("signup.html")

@auth_bp.get("/login")
def login_page():
    return render_template("login.html")

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

    if not all([user_id, password, name, nickname, email, phone, github_token]):
        return jsonify({"status": "error", "message": "All fields are required."}), 400

    hashed_pw = hashlib.sha256(password.encode()).hexdigest()

    query = """
        INSERT INTO coharas (id, password, name, nickname, email, phone, github_token)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """

    try:
        conn = get_conn()
        with get_cursor(conn) as cur:
            cur.execute(query, (user_id, hashed_pw, name, nickname, email, phone, github_token))
            conn.commit()
        return jsonify({"status": "success", "message": "Sign-up completed successfully."})
    except Exception as e:
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
        conn.close()

# === Login API ===
@auth_bp.post("/api/login")
def login_api():
    data = request.json
    user_id = data.get("id")
    password = data.get("password")

    if not user_id or not password:
        return jsonify({"status": "error", "message": "Please enter both ID and password."}), 400

    hashed_pw = hashlib.sha256(password.encode()).hexdigest()

    query = "SELECT * FROM coharas WHERE id = %s AND password = %s"

    conn = get_conn()
    with get_cursor(conn) as cur:
        cur.execute(query, (user_id, hashed_pw))
        user = cur.fetchone()

    conn.close()

    if not user:
        return jsonify({"status": "error", "message": "Invalid ID or password."}), 401

    # Register session
    session["user_id"] = user["id"]
    session["user_name"] = user["name"]
    session["nickname"] = user["nickname"]

    return jsonify({
        "status": "success",
        "message": "Login successful.",
        "user": {
            "id": user["id"],
            "name": user["name"],
            "nickname": user["nickname"],
            "email": user["email"]
        }
    })

# === Logout API ===
@auth_bp.post("/api/logout")
def logout_api():
    session.clear()
    return jsonify({"status": "success", "message": "Logged out successfully."})