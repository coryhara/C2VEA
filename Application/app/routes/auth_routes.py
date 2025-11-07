from flask import Blueprint, render_template, request, jsonify
from app.db import get_conn, get_cursor

auth_bp = Blueprint("auth", __name__)

@auth_bp.get("/login")
def auth():
    return render_template("login.html")   # ✅ CVE 리스트 페이지

@auth_bp.get("/register")
def register():
    return render_template("register.html")

@auth_bp.get("/email_verify")
def email_verify():
    return render_template("email_verify.html")

@auth_bp.get("/send_email")
def send_email():
    return render_template("send_email.html")

@auth_bp.get("/forgot_password")
def forgot_password():
    return render_template("forgot_password.html")