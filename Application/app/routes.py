# app/routes.py
from flask import Blueprint, render_template, jsonify, current_app, request, redirect
from werkzeug.utils import secure_filename
from pathlib import Path
from datetime import datetime
import json
import os
import pdfkit

from .services import call_fastapi
from . import socketio
from .sockets import start_task, finish_task
from .db import get_conn

bp = Blueprint("main", __name__)

# =========================
# 기본 라우트 (로그 뷰어 UI)
# =========================
@bp.get("/")
def index():
    return render_template("index.html")

# =========================
# 작업 실행 버튼들
# =========================
@bp.get("/run-main")
def run_main():
    _dispatch("/run-main", "Main")
    return jsonify({"status": "started", "label": "Main", "message": "Main request started"}), 202

@bp.get("/run-cve")
def run_cve():
    _dispatch("/run-cve", "CVE")
    return jsonify({"status": "started", "label": "CVE", "message": "CVE request started"}), 202

@bp.get("/run-github")
def run_github():
    _dispatch("/run-github", "GitHub")
    return jsonify({"status": "started", "label": "GitHub", "message": "GitHub request started"}), 202

@bp.get("/run-backup")
def run_backup():
    _dispatch("/run-backup", "Backup")
    return jsonify({"status": "started", "label": "Backup", "message": "Backup request started"}), 202


# ==========================================================
# PoC Insert
# ==========================================================
@bp.get("/poc")
def poc_form():
    return render_template("poc_form.html")

@bp.post("/poc")
def poc_upload():
    cve_id = (request.form.get("cve_id") or "").strip()
    source_identifier = (request.form.get("source_identifier") or "").strip()
    poc_url = (request.form.get("poc_url") or "").strip()
    poc_file = request.files.get("poc_file")

    if not cve_id or not source_identifier:
        socketio.emit("notify", {
            "type": "error",
            "label": "PoC",
            "message": "⚠️ CVE ID와 Source Identifier는 필수입니다."
        })
        return render_template("poc_form.html", cve_id=cve_id, source_identifier=source_identifier)

    base_dir = Path(os.getenv("POC_SAVE_DIR", "/tmp/poc_sources"))
    upload_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    upload_dir = base_dir / upload_time
    upload_dir.mkdir(parents=True, exist_ok=True)

    wkhtmltopdf_cmd = os.getenv("WKHTMLTOPDF_CMD")
    pdfkit_config = pdfkit.configuration(wkhtmltopdf=wkhtmltopdf_cmd) if wkhtmltopdf_cmd else None

    downloaded_files = []
    conn = get_conn()
    cur = conn.cursor()

    try:
        if poc_url:
            pdf_path = upload_dir / f"{secure_filename(cve_id)}_poc.pdf"
            if pdfkit_config:
                pdfkit.from_url(poc_url, str(pdf_path), configuration=pdfkit_config)
            else:
                pdfkit.from_url(poc_url, str(pdf_path))
            downloaded_files.append(str(pdf_path))

            cur.execute("""
                INSERT INTO cve_poc_sources (cve_id, source_identifier, url, downloaded_files)
                VALUES (%s, %s, %s, %s)
            """, (cve_id, source_identifier, poc_url, json.dumps(downloaded_files)))

        elif poc_file and poc_file.filename:
            filename = secure_filename(poc_file.filename)
            file_path = upload_dir / filename
            poc_file.save(file_path)
            downloaded_files.append(str(file_path))

            cur.execute("""
                INSERT INTO cve_poc_sources (cve_id, source_identifier, downloaded_files)
                VALUES (%s, %s, %s)
            """, (cve_id, source_identifier, json.dumps(downloaded_files)))
        else:
            socketio.emit("notify", {
                "type": "error",
                "label": "PoC",
                "message": "⚠️ URL 또는 파일 중 하나를 입력하세요."
            })
            return render_template("poc_form.html", cve_id=cve_id, source_identifier=source_identifier)

        cur.execute("""
            INSERT INTO logs (status, message)
            VALUES (%s, %s)
        """, ("INFO", f"PoC for {cve_id} saved from {source_identifier} at {upload_time}"))

        conn.commit()

        socketio.emit("notify", {
            "type": "success",
            "label": "PoC",
            "message": f"✅ PoC for {cve_id} saved successfully"
        })

        return redirect("/")  # 성공 시 이동

    except Exception as e:
        conn.rollback()
        socketio.emit("notify", {
            "type": "error",
            "label": "PoC",
            "message": f"❌ 저장 실패: {e}"
        })
        return render_template("poc_form.html", cve_id=cve_id, source_identifier=source_identifier)
    finally:
        cur.close()
        conn.close()

# =========================
# 내부: 작업 디스패처
# =========================
def _dispatch(endpoint: str, label: str):
    app = current_app._get_current_object()

    key = (label or "").strip().lower() or "task"

    start_task(key)
    socketio.emit("active", [{"type": "active", "label": key, "progress": None}])

    def _task():
        with app.app_context():
            final = False
            try:
                msg = call_fastapi(endpoint, key)
                final = _is_final_message(msg)
            except Exception as e:
                msg = f"❌ {label} → {e}"
            finally:
                if final:
                    finish_task(key)
                socketio.emit("notify", {"type": "notify", "label": label, "message": msg})

    from . import socketio as _socketio
    _socketio.start_background_task(_task)


def _is_final_message(message: str) -> bool:
    m = (message or "").lower()
    finals = (
        " done", " completed", " finished", " success", "successfully",
        "all tasks complete", "backup complete", "cve job complete", "cve sync complete"
    )
    return any(k in m for k in finals)
