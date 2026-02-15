import ipaddress
import json
import os
import socket
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import pdfkit
from flask import Blueprint, jsonify, redirect, render_template, request, send_file
from werkzeug.utils import secure_filename

from app import socketio
from app.db import get_conn, get_cursor
from app.utils.decorators import admin_required, email_verified_required, login_required

poc_bp = Blueprint("poc", __name__)


def _notify(type_: str, label: str, message: str):
    socketio.emit("notify", {"type": type_, "label": label, "message": message})


def _get_allowlisted_hosts():
    raw = os.getenv("POC_URL_ALLOWLIST", "")
    return [h.strip().lower() for h in raw.replace(";", ",").split(",") if h.strip()]


def _is_host_allowlisted(hostname: str, allowlist: list[str]) -> bool:
    if not allowlist:
        return True
    host = hostname.lower()
    return any(host == allowed or host.endswith(f".{allowed}") for allowed in allowlist)


def _validate_public_url(url: str) -> str | None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return "Only http/https URLs are allowed."

    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        return "URL hostname is required."
    if hostname in {"localhost", "127.0.0.1", "::1"}:
        return "Localhost URLs are not allowed."
    if not _is_host_allowlisted(hostname, _get_allowlisted_hosts()):
        return "URL hostname is not in the allowlist."

    try:
        infos = socket.getaddrinfo(hostname, parsed.port or 80, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return "URL hostname could not be resolved."

    for info in infos:
        ip_str = info[4][0]
        ip = ipaddress.ip_address(ip_str)
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return "Private or local network addresses are not allowed."

    return None


def _resolve_download_path(raw_path: str) -> Path:
    base_dir = Path(os.getenv("POC_SAVE_DIR", "/app/poc_sources")).resolve()
    candidate = Path(raw_path)

    # Fix for paths stored as relative starting with ./poc_sources/ or poc_sources/
    # This prevents path duplication (e.g., /app/poc_sources/poc_sources/...)
    parts = candidate.parts
    if len(parts) > 0 and parts[0] == ".":
        parts = parts[1:]
    if len(parts) > 0 and parts[0] == "poc_sources":
        parts = parts[1:]
    candidate = Path(*parts)

    if not candidate.is_absolute():
        candidate = (base_dir / candidate).resolve()
    else:
        candidate = candidate.resolve()

    if os.path.commonpath([str(candidate), str(base_dir)]) != str(base_dir):
        raise ValueError("Invalid file path.")
    return candidate


@poc_bp.get("/pocs")
@login_required
@email_verified_required
def poc_page():
    return render_template("pocs.html")


@poc_bp.get("/poc/upload")
@login_required
@email_verified_required
@admin_required
def poc_form():
    return render_template("poc_form.html")


@poc_bp.post("/poc/upload")
@login_required
@email_verified_required
@admin_required
def poc_upload():
    cve_id = (request.form.get("cve_id") or "").strip()
    source_id = (request.form.get("source_identifier") or "").strip()
    poc_url = (request.form.get("poc_url") or "").strip()
    poc_file = request.files.get("poc_file")

    if not cve_id or not source_id:
        _notify("error", "PoC", "CVE ID and Source Identifier are required.")
        return render_template("poc_form.html", cve_id=cve_id, source_identifier=source_id)

    base_dir = Path(os.getenv("POC_SAVE_DIR", "/app/poc_sources"))
    upload_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    upload_dir = base_dir / upload_time
    upload_dir.mkdir(parents=True, exist_ok=True)

    wkhtmltopdf = os.getenv("WKHTMLTOPDF_CMD")
    pdfkit_config = pdfkit.configuration(wkhtmltopdf=wkhtmltopdf) if wkhtmltopdf else None
    downloaded_files = []

    conn = get_conn()
    cur = None
    try:
        cur = get_cursor(conn)

        if poc_url:
            error = _validate_public_url(poc_url)
            if error:
                _notify("error", "PoC", error)
                return render_template("poc_form.html", cve_id=cve_id, source_identifier=source_id)

            pdf_path = upload_dir / f"{secure_filename(cve_id)}_poc.pdf"
            pdfkit.from_url(poc_url, str(pdf_path), configuration=pdfkit_config)
            downloaded_files.append(str(pdf_path))

            cur.execute(
                """
                INSERT INTO cve_poc_sources (cve_id, source_identifier, url, downloaded_files)
                VALUES (%s, %s, %s, %s)
                """,
                (cve_id, source_id, poc_url, json.dumps(downloaded_files))
            )
        elif poc_file and poc_file.filename:
            filename = secure_filename(poc_file.filename)
            file_path = upload_dir / filename
            poc_file.save(file_path)
            downloaded_files.append(str(file_path))

            cur.execute(
                """
                INSERT INTO cve_poc_sources (cve_id, source_identifier, downloaded_files)
                VALUES (%s, %s, %s)
                """,
                (cve_id, source_id, json.dumps(downloaded_files))
            )
        else:
            _notify("error", "PoC", "Provide either PoC URL or PoC file.")
            return render_template("poc_form.html", cve_id=cve_id, source_identifier=source_id)

        cur.execute(
            """
            INSERT INTO logs (status, message)
            VALUES (%s, %s)
            """,
            ("INFO", f"PoC for {cve_id} saved from {source_id} at {upload_time}")
        )

        conn.commit()
        _notify("success", "PoC", f"PoC for {cve_id} saved successfully")
        return redirect("/")
    except Exception as e:
        conn.rollback()
        _notify("error", "PoC", f"Save failed: {e}")
        return render_template("poc_form.html", cve_id=cve_id, source_identifier=source_id)
    finally:
        if cur:
            cur.close()
        conn.close()


@poc_bp.get("/poc/download/<int:poc_id>")
@login_required
@email_verified_required
def poc_download(poc_id):
    conn = get_conn()
    try:
        with get_cursor(conn) as cur:
            cur.execute("SELECT downloaded_files FROM cve_poc_sources WHERE id=%s", (poc_id,))
            row = cur.fetchone()
    finally:
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

        resolved = _resolve_download_path(file_path)
        if not resolved.exists():
            return jsonify({"error": f"File not found on server: {resolved}"}), 404

        return send_file(str(resolved), as_attachment=True)
    except ValueError as e:
        return jsonify({"error": str(e)}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@poc_bp.get("/api/pocs")
@login_required
@email_verified_required
def api_pocs():
    args = request.args
    page = max(int(args.get("page", 1)), 1)
    allowed_sizes = {10, 50, 100, 200}
    try:
        size = int(args.get("size", 100))
    except (TypeError, ValueError):
        size = 100
    if size not in allowed_sizes:
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

    for row in rows:
        if isinstance(row.get("downloaded_files"), (list, dict)):
            row["downloaded_files"] = json.dumps(row["downloaded_files"])
        elif row.get("downloaded_files") is None:
            row["downloaded_files"] = "[]"

    return jsonify({
        "page": page,
        "size": size,
        "total": total,
        "pages": (total + size - 1) // size,
        "items": rows
    })


@poc_bp.get("/api/cve/poc-sources")
@login_required
@email_verified_required
def cve_poc_sources():
    conn = get_conn()
    try:
        with get_cursor(conn) as cur:
            cur.execute(
                """
                SELECT source_identifier, COUNT(*) AS count
                FROM cve_poc_sources
                GROUP BY source_identifier
                ORDER BY count DESC
                """
            )
            rows = cur.fetchall()
    finally:
        conn.close()
    return jsonify(rows)
