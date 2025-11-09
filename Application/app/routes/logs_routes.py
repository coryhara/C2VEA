from flask import Blueprint, jsonify, render_template
from app.db import get_conn, get_cursor
from app.utils.decorators import (
    login_required,
    email_verified_required,
    github_verified_required,
    phone_verified_required,
    admin_required,
)

logs_bp = Blueprint("logs", __name__)

@logs_bp.get("/logs")
@login_required
@email_verified_required
@admin_required
def logs_page():
    return render_template("logs.html")

@logs_bp.get("/api/logs/latest")
@login_required
@email_verified_required
@admin_required
def logs_latest():
    conn = get_conn()
    with get_cursor(conn) as cur:
        cur.execute("""
            SELECT id, status, message, log_time
            FROM logs
            ORDER BY id DESC
            LIMIT 100
        """)
        rows = cur.fetchall()
    conn.close()
    return jsonify(rows)