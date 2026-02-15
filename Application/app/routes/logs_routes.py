from flask import Blueprint, jsonify, render_template, request
from app.db import get_conn, get_cursor
from app.utils.decorators import (
    login_required,
    email_verified_required,
    github_verified_required,
    phone_verified_required,
    admin_required,
)

logs_bp = Blueprint("logs", __name__)


def _serialize_log_row(row):
    return {
        "id": row["id"],
        "status": row["status"],
        "message": row["message"],
        "log_time": row["log_time"].strftime("%Y-%m-%d %H:%M:%S") if row.get("log_time") else None,
    }


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
    return jsonify([_serialize_log_row(row) for row in rows])


@logs_bp.get("/api/logs/since")
@login_required
@email_verified_required
@admin_required
def logs_since():
    raw_last_id = 0
    try:
        raw_last_id = int(request.args.get("last_id", 0))
    except (TypeError, ValueError):
        raw_last_id = 0

    conn = get_conn()
    with get_cursor(conn) as cur:
        cur.execute(
            """
            SELECT id, status, message, log_time
            FROM (
              SELECT id, status, message, log_time
              FROM logs
              WHERE id > %s
              ORDER BY id DESC
              LIMIT 1000
            ) t
            ORDER BY id ASC
            """,
            (raw_last_id,),
        )
        rows = cur.fetchall()
    conn.close()
    return jsonify([_serialize_log_row(row) for row in rows])
