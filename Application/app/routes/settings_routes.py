from flask import Blueprint, render_template, request, redirect
from app.db import get_conn, get_cursor
from app import socketio
from app.utils.decorators import (
    login_required,
    email_verified_required,
    github_verified_required,
    phone_verified_required,
    admin_required,
)

settings_bp = Blueprint("settings", __name__)

@settings_bp.get("/settings")
@login_required
@email_verified_required
@admin_required
def get_settings():
    conn = get_conn()
    with get_cursor(conn) as cur:
        cur.execute("SELECT config_key, config_value FROM app_config ORDER BY id ASC")
        rows = cur.fetchall()
        settings = {row["config_key"]: row["config_value"] for row in rows}
    conn.close()
    return render_template("settings.html", settings=settings)

@settings_bp.post("/settings")
@login_required
@email_verified_required
@admin_required
def update_settings():
    conn = get_conn()
    try:
        with get_cursor(conn) as cur:
            for key, value in request.form.to_dict().items():
                cur.execute("""
                    INSERT INTO app_config (config_key, config_value)
                    VALUES (%s, %s)
                    ON DUPLICATE KEY UPDATE config_value = VALUES(config_value)
                """, (key, value))
        conn.commit()
        socketio.emit("notify", {"type": "success", "label": "Settings", "message": "✅ Settings updated successfully"})
        return redirect("/settings")
    except Exception as e:
        conn.rollback()
        socketio.emit("notify", {"type": "error", "label": "Settings", "message": f"❌ Failed to update settings: {e}"})
        return redirect("/settings")
    finally:
        conn.close()
