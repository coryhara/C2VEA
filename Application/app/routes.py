from flask import Blueprint, render_template, jsonify, current_app
from .services import call_fastapi
from . import socketio
from .sockets import start_task, finish_task  # ⬅️ use active-task registry

bp = Blueprint("main", __name__)

@bp.get("/")
def index():
    return render_template("index.html")

@bp.get("/run-main")
def run_main():
    _dispatch("/run-main", "Main")
    return jsonify({"status":"started","label":"Main","message":"Main request started"}), 202

@bp.get("/run-cve")
def run_cve():
    _dispatch("/run-cve", "CVE")
    return jsonify({"status":"started","label":"CVE","message":"CVE request started"}), 202

@bp.get("/run-github")
def run_github():
    _dispatch("/run-github", "GitHub")
    return jsonify({"status":"started","label":"GitHub","message":"GitHub request started"}), 202

@bp.get("/run-backup")
def run_backup():
    _dispatch("/run-backup", "Backup")
    return jsonify({"status":"started","label":"Backup","message":"Backup request started"}), 202


def _dispatch(endpoint: str, label: str):
    # ⚠️ capture app context object
    app = current_app._get_current_object()

    # 🔑 normalize label (lowercase) for server/client consistency
    key = (label or "").strip().lower() or "task"

    # ✅ mark active immediately + push snapshot to any connected clients
    start_task(key)
    socketio.emit("active", [{"type": "active", "label": key, "progress": None}])

    def _task():
        with app.app_context():
            final = False
            try:
                msg = call_fastapi(endpoint, key)
                # ✅ only treat as finished if message looks final/successful
                final = _is_final_message(msg)
            except Exception as e:
                # ⛔ on error/timeout keep task active (DO NOT finish here)
                msg = f"❌ {label} → {e}"
            finally:
                if final:
                    finish_task(key)
                # notify clients (client decides whether to clear loading)
                socketio.emit("notify", {"type":"notify","label":label,"message":msg})

    socketio.start_background_task(_task)


def _is_final_message(message: str) -> bool:
    m = (message or "").lower()
    finals = (
        " done", " completed", " finished", " success", "successfully",
        "all tasks complete", "backup complete", "cve job complete", "cve sync complete"
    )
    return any(k in m for k in finals)