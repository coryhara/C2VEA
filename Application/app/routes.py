from flask import Blueprint, render_template, jsonify, current_app
from .services import call_fastapi
from . import socketio

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
    # ⚠️ app 컨텍스트 캡쳐
    app = current_app._get_current_object()

    def _task():
        # ✅ 백그라운드 그린스레드에서 앱 컨텍스트 푸시
        with app.app_context():
            try:
                msg = call_fastapi(endpoint, label)
            except Exception as e:
                msg = f"❌ {label} → {e}"
            # flask-socketio 최신 버전: broadcast 인자 X
            socketio.emit("notify", {"type":"notify","label":label,"message":msg})

    socketio.start_background_task(_task)