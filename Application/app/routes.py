from flask import Blueprint, render_template, request, redirect, jsonify
from werkzeug.utils import secure_filename
from pathlib import Path
from datetime import datetime
import json
import os
import pdfkit

from . import socketio
from .db import get_conn, get_cursor

bp = Blueprint("main", __name__)

# =========================================================
# 기본 페이지 라우트
# =========================================================

@bp.get("/")
def index():
    return render_template("index.html")


@bp.get("/poc")
def poc_form():
    return render_template("poc_form.html")


@bp.post("/poc")
def poc_upload():
    cve_id = (request.form.get("cve_id") or "").strip()
    source_id = (request.form.get("source_identifier") or "").strip()
    poc_url = (request.form.get("poc_url") or "").strip()
    poc_file = request.files.get("poc_file")

    if not cve_id or not source_id:
        _notify("error", "PoC", "⚠️ CVE ID와 Source Identifier는 필수입니다.")
        return render_template("poc_form.html", cve_id=cve_id, source_identifier=source_id)

    base_dir = Path(os.getenv("POC_SAVE_DIR", "/tmp/poc_sources"))
    upload_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    upload_dir = base_dir / upload_time
    upload_dir.mkdir(parents=True, exist_ok=True)

    wkhtmltopdf = os.getenv("WKHTMLTOPDF_CMD")
    pdfkit_config = pdfkit.configuration(wkhtmltopdf=wkhtmltopdf) if wkhtmltopdf else None

    downloaded_files = []

    conn, cur = get_conn(), None
    try:
        cur = get_cursor(conn)

        if poc_url:
            pdf_path = upload_dir / f"{secure_filename(cve_id)}_poc.pdf"
            pdfkit.from_url(poc_url, str(pdf_path), configuration=pdfkit_config)
            downloaded_files.append(str(pdf_path))

            cur.execute("""
                INSERT INTO cve_poc_sources (cve_id, source_identifier, url, downloaded_files)
                VALUES (%s, %s, %s, %s)
            """, (cve_id, source_id, poc_url, json.dumps(downloaded_files)))

        elif poc_file and poc_file.filename:
            filename = secure_filename(poc_file.filename)
            file_path = upload_dir / filename
            poc_file.save(file_path)
            downloaded_files.append(str(file_path))

            cur.execute("""
                INSERT INTO cve_poc_sources (cve_id, source_identifier, downloaded_files)
                VALUES (%s, %s, %s)
            """, (cve_id, source_id, json.dumps(downloaded_files)))

        else:
            _notify("error", "PoC", "⚠️ URL 또는 파일 중 하나를 입력하세요.")
            return render_template("poc_form.html", cve_id=cve_id, source_identifier=source_id)

        # 로그 기록
        cur.execute("""
            INSERT INTO logs (status, message)
            VALUES (%s, %s)
        """, ("INFO", f"PoC for {cve_id} saved from {source_id} at {upload_time}"))

        conn.commit()
        _notify("success", "PoC", f"✅ PoC for {cve_id} saved successfully")
        return redirect("/")

    except Exception as e:
        conn.rollback()
        _notify("error", "PoC", f"❌ 저장 실패: {e}")
        return render_template("poc_form.html", cve_id=cve_id, source_identifier=source_id)

    finally:
        if cur:
            cur.close()
        conn.close()


@bp.get("/settings")
def get_settings():
    """DB에 저장된 설정값을 불러오기"""
    conn = get_conn()
    with get_cursor(conn) as cur:
        cur.execute("SELECT config_key, config_value FROM app_config")
        rows = cur.fetchall()
        settings = {row["config_key"]: row["config_value"] for row in rows}
    conn.close()
    return render_template("settings.html", settings=settings)


@bp.post("/settings")
def update_settings():
    """설정값 수정"""
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

        _notify("success", "Settings", "✅ Settings updated successfully")
        return redirect("/settings")

    except Exception as e:
        conn.rollback()
        _notify("error", "Settings", f"❌ Failed to update settings: {e}")
        return redirect("/settings")

    finally:
        conn.close()


def _notify(type_: str, label: str, message: str):
    socketio.emit("notify", {"type": type_, "label": label, "message": message})


# =========================================================
# CVE 분석 API (데이터 시각화용)
# =========================================================
@bp.get("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@bp.get("/api/cve/summary")
def cve_summary():
    conn = get_conn()
    with get_cursor(conn) as cur:
        cur.execute("SELECT COUNT(*) AS total FROM cve_vulnerabilities")
        total = cur.fetchone()["total"]

        cur.execute("""
            SELECT COUNT(*) AS recent_7d 
            FROM cve_vulnerabilities 
            WHERE published >= NOW() - INTERVAL 7 DAY
        """)
        recent_7d = cur.fetchone()["recent_7d"]

        cur.execute("SELECT COALESCE(AVG(base_score), 0) AS avg_score FROM cvss_metrics")
        avg_score = cur.fetchone()["avg_score"]

    conn.close()
    return jsonify({
        "total": total,
        "recent_7d": recent_7d,
        "avg_score": round(avg_score, 2) if avg_score else None
    })


@bp.get("/api/cve/severity")
def cve_severity():
    conn = get_conn()
    with get_cursor(conn) as cur:
        cur.execute("""
            SELECT base_severity AS severity, COUNT(*) AS count
            FROM cvss_metrics
            GROUP BY base_severity
            ORDER BY FIELD(base_severity, 'Critical','High','Medium','Low')
        """)
        rows = cur.fetchall()
    conn.close()
    return jsonify(rows)


@bp.get("/api/cve/scores")
def cve_scores():
    conn = get_conn()
    with get_cursor(conn) as cur:
        query = """
            SELECT 
              CASE 
                WHEN base_score < 4 THEN '0-3'
                WHEN base_score < 7 THEN '4-6'
                WHEN base_score < 9 THEN '7-8.9'
                ELSE '9-10'
              END AS range_label,
              COUNT(*) AS count
            FROM cvss_metrics
            GROUP BY range_label
            ORDER BY FIELD(range_label, '0-3','4-6','7-8.9','9-10');
        """
        cur.execute(query)
        rows = cur.fetchall()
    conn.close()
    return jsonify(rows)


@bp.get("/api/cve/attack-vector")
def cve_attack_vector():
    conn = get_conn()
    with get_cursor(conn) as cur:
        cur.execute("""
            SELECT attack_vector, COUNT(*) AS count
            FROM cvss_metrics
            GROUP BY attack_vector
        """)
        rows = cur.fetchall()
    conn.close()
    return jsonify(rows)


@bp.get("/api/cve/impact")
def cve_impact():
    conn = get_conn()
    with get_cursor(conn) as cur:
        cur.execute("""
            SELECT confidentiality_impact AS type, COUNT(*) AS count
            FROM cvss_metrics
            GROUP BY confidentiality_impact
        """)
        conf = cur.fetchall()

        cur.execute("""
            SELECT integrity_impact AS type, COUNT(*) AS count
            FROM cvss_metrics
            GROUP BY integrity_impact
        """)
        integ = cur.fetchall()

        cur.execute("""
            SELECT availability_impact AS type, COUNT(*) AS count
            FROM cvss_metrics
            GROUP BY availability_impact
        """)
        avail = cur.fetchall()

    conn.close()
    return jsonify({
        "confidentiality": conf,
        "integrity": integ,
        "availability": avail
    })


@bp.get("/api/cve/tags")
def cve_tags():
    conn = get_conn()
    with get_cursor(conn) as cur:
        cur.execute("""
            SELECT tag, COUNT(*) AS count
            FROM cve_tags
            GROUP BY tag
            ORDER BY count DESC
            LIMIT 20
        """)
        rows = cur.fetchall()
    conn.close()
    return jsonify(rows)


@bp.get("/api/cve/poc-sources")
def cve_poc_sources():
    conn = get_conn()
    with get_cursor(conn) as cur:
        cur.execute("""
            SELECT source_identifier, COUNT(*) AS count
            FROM cve_poc_sources
            GROUP BY source_identifier
            ORDER BY count DESC
        """)
        rows = cur.fetchall()
    conn.close()
    return jsonify(rows)


@bp.get("/api/logs/latest")
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
