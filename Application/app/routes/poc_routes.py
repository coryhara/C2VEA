from flask import Blueprint, render_template, request, redirect, jsonify, send_file, abort
from werkzeug.utils import secure_filename
from pathlib import Path
from datetime import datetime
import os, json, pdfkit

from app import socketio
from app.db import get_conn, get_cursor

poc_bp = Blueprint("poc", __name__)

# =========================
# 페이지 라우트
# =========================
@poc_bp.get("/pocs")
def poc_page():
    return render_template("pocs.html")   # ✅ PoC 리스트 페이지


# =========================
# PoC 업로드
# =========================
@poc_bp.get("/poc/upload")
def poc_form():
    return render_template("poc_form.html")


@poc_bp.post("/poc/upload")
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


# =========================
# 다운로드 기능 추가
# =========================
@poc_bp.get("/poc/download/<int:poc_id>")
def poc_download(poc_id):
    conn = get_conn()
    with get_cursor(conn) as cur:
        cur.execute("SELECT downloaded_files FROM cve_poc_sources WHERE id=%s", (poc_id,))
        row = cur.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "PoC not found"}), 404

    try:
        files_data = json.loads(row["downloaded_files"] or "[]")
        if not files_data:
            return jsonify({"error": "No files found"}), 404

        first_item = files_data[0]
        if isinstance(first_item, dict):
            file_path = first_item.get("path") or list(first_item.values())[0]
        else:
            file_path = first_item

        # ✅ 절대 경로 보정
        if not os.path.isabs(file_path):
            base_dir = os.getenv("POC_SAVE_DIR", "/app/poc_sources")  # 실제 파일 저장 루트
            file_path = os.path.join(base_dir, os.path.relpath(file_path, "./poc_sources"))

        if not os.path.exists(file_path):
            return jsonify({"error": f"File not found on server: {file_path}"}), 404

        return send_file(file_path, as_attachment=True)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =========================
# PoC 리스트 API
# =========================
@poc_bp.get("/api/pocs")
def api_pocs():
    args = request.args
    page = int(args.get("page", 1))
    size = 100
    offset = (page - 1) * size

    base_query = "FROM cve_poc_sources WHERE 1=1"
    conditions = []
    params = []

    search_type = args.get("search_type")
    keyword = args.get("keyword")
    if search_type in ["title", "source", "author"] and keyword:
        if search_type == "title":
            conditions.append("cve_id LIKE %s")
        elif search_type == "source":
            conditions.append("source_identifier LIKE %s")
        elif search_type == "author":
            conditions.append("url LIKE %s")
        params.append(f"%{keyword}%")

    if conditions:
        base_query += " AND " + " AND ".join(conditions)

    # ✅ downloaded_files 컬럼 추가
    data_query = f"""
        SELECT id, cve_id, source_identifier, url, created_at, downloaded_files
        {base_query}
    """

    sort = args.get("sort", "created_at")
    order = args.get("order", "DESC").upper()
    if sort not in ["id", "cve_id", "source_identifier", "url", "created_at"]:
        sort = "created_at"
    if order not in ["ASC", "DESC"]:
        order = "DESC"

    data_query += f" ORDER BY {sort} {order} LIMIT %s OFFSET %s"
    params_data = params + [size, offset]

    count_query = f"SELECT COUNT(*) AS total {base_query}"

    with get_conn() as conn, get_cursor(conn) as cur:
        cur.execute(data_query, params_data)
        rows = cur.fetchall()

        cur.execute(count_query, params)
        total = cur.fetchone()["total"]

    # ✅ downloaded_files를 JSON 문자열로 안전하게 직렬화
    for r in rows:
        if isinstance(r.get("downloaded_files"), (list, dict)):
            r["downloaded_files"] = json.dumps(r["downloaded_files"])
        elif r.get("downloaded_files") is None:
            r["downloaded_files"] = "[]"

    return jsonify({
        "page": page,
        "size": size,
        "total": total,
        "pages": (total + size - 1) // size,
        "items": rows
    })


# =========================
# 소스 통계
# =========================
@poc_bp.get("/api/cve/poc-sources")
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


def _notify(type_: str, label: str, message: str):
    socketio.emit("notify", {"type": type_, "label": label, "message": message})
