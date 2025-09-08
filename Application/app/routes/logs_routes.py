from flask import Blueprint, jsonify
from app.db import get_conn, get_cursor

logs_bp = Blueprint("logs", __name__)

@logs_bp.get("/api/logs/latest")
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