from flask import Blueprint, render_template, jsonify, current_app, request, redirect
from werkzeug.utils import secure_filename
from pathlib import Path
from datetime import datetime
import json
import os
import pdfkit

from . import socketio
from .db import get_conn

bp = Blueprint("main", __name__)

@bp.get("/")
def index():
    return render_template("index.html")

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

@bp.get("/settings")
def get_settings():
    """DB에 저장된 설정값을 불러오기"""
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute("SELECT config_key, config_value FROM app_config")
        rows = cur.fetchall()
        settings = {row[0]: row[1] for row in rows}
        return render_template("settings.html", settings=settings)
    finally:
        cur.close()
        conn.close()

@bp.post("/settings")
def update_settings():
    """설정값 수정"""
    data = request.form.to_dict()
    conn = get_conn()
    cur = conn.cursor()
    try:
        for key, value in data.items():
            cur.execute("""
                INSERT INTO app_config (config_key, config_value)
                VALUES (%s, %s)
                ON DUPLICATE KEY UPDATE config_value = VALUES(config_value)
            """, (key, value))
        conn.commit()

        socketio.emit("notify", {
            "type": "success",
            "label": "Settings",
            "message": "✅ Settings updated successfully"
        })
        return redirect("/settings")

    except Exception as e:
        conn.rollback()
        socketio.emit("notify", {
            "type": "error",
            "label": "Settings",
            "message": f"❌ Failed to update settings: {e}"
        })
        return redirect("/settings")
    finally:
        cur.close()
        conn.close()