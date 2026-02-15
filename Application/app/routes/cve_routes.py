import json

from flask import Blueprint, abort, jsonify, render_template, request
from app.db import get_conn, get_cursor
from app.utils.decorators import (
    login_required,
    email_verified_required,
    github_verified_required,
    phone_verified_required,
    admin_required,
)

cve_bp = Blueprint("cve", __name__)


def _safe_load_json(value, default):
    if value in (None, ""):
        return default
    if isinstance(value, (list, dict)):
        return value
    try:
        loaded = json.loads(value)
        return loaded
    except Exception:
        return default


def _build_cve_count_query(args):
    joins = []
    where = ["1=1"]
    params = []

    if args.get("start") and args.get("end"):
        where.append("v.published BETWEEN %s AND %s")
        params.extend([args["start"], args["end"]])

    need_metrics = bool(args.get("severity") or (args.get("min_score") and args.get("max_score")) or args.get("vector"))
    need_tags = bool(args.get("tag"))
    need_desc = bool(args.get("search"))

    if need_metrics:
        joins.append("INNER JOIN cvss_metrics m ON v.cve_id = m.cve_id")
    if need_tags:
        joins.append("INNER JOIN cve_tags t ON v.cve_id = t.cve_id")
    if need_desc:
        joins.append("INNER JOIN cve_descriptions d ON v.cve_id = d.cve_id")

    if args.get("severity"):
        where.append("m.base_severity = %s")
        params.append(args["severity"])
    if args.get("min_score") and args.get("max_score"):
        where.append("m.base_score BETWEEN %s AND %s")
        params.extend([args["min_score"], args["max_score"]])
    if args.get("tag"):
        where.append("t.tag LIKE %s")
        params.append(f"%{args['tag']}%")
    if args.get("vector"):
        where.append("m.attack_vector = %s")
        params.append(args["vector"])
    if args.get("search"):
        where.append("(v.cve_id LIKE %s OR d.description_value LIKE %s)")
        keyword = f"%{args['search']}%"
        params.extend([keyword, keyword])

    has_poc = (args.get("has_poc") or "").strip().lower()
    if has_poc in {"yes", "1", "true", "y"}:
        where.append("EXISTS (SELECT 1 FROM cve_poc_sources p2 WHERE p2.cve_id = v.cve_id)")
    elif has_poc in {"no", "0", "false", "n"}:
        where.append("NOT EXISTS (SELECT 1 FROM cve_poc_sources p2 WHERE p2.cve_id = v.cve_id)")

    query = f"""
        SELECT COUNT(DISTINCT v.cve_id) AS total
        FROM cve_vulnerabilities v
        {' '.join(joins)}
        WHERE {' AND '.join(where)}
    """
    return query, params

@cve_bp.get("/cves")
@login_required
@email_verified_required
def cve_page():
    return render_template("cves.html")   # ??CVE 由ъ뒪???섏씠吏

@cve_bp.get("/cves/<cve_id>")
@login_required
@email_verified_required
def cve_detail_page(cve_id):
    return_to = (request.args.get("return") or "").strip()
    if not return_to.startswith("/cves"):
        return_to = "/cves"

    with get_conn() as conn, get_cursor(conn) as cur:
        cur.execute(
            """
            SELECT
              v.cve_id,
              v.source_identifier,
              v.published,
              v.last_modified,
              v.vuln_status,
              e.epss_score,
              e.epss_percentile,
              e.score_date
            FROM cve_vulnerabilities v
            LEFT JOIN cve_epss e ON v.cve_id = e.cve_id
            WHERE v.cve_id = %s
            LIMIT 1
            """,
            (cve_id,),
        )
        vuln = cur.fetchone()
        if not vuln:
            abort(404)

        cur.execute(
            """
            SELECT description_lang, description_value
            FROM cve_descriptions
            WHERE cve_id = %s
            ORDER BY CASE WHEN description_lang='en' THEN 0 ELSE 1 END, description_lang
            """,
            (cve_id,),
        )
        descriptions = cur.fetchall()

        cur.execute(
            """
            SELECT
              version, vector_string, base_score, base_severity, attack_vector,
              attack_complexity, privileges_required, user_interaction, scope,
              confidentiality_impact, integrity_impact, availability_impact
            FROM cvss_metrics
            WHERE cve_id = %s
            ORDER BY base_score DESC, version DESC
            """,
            (cve_id,),
        )
        metrics = cur.fetchall()

        cur.execute(
            """
            SELECT source_identifier, tag
            FROM cve_tags
            WHERE cve_id = %s
            ORDER BY tag ASC
            """,
            (cve_id,),
        )
        tags = cur.fetchall()

        cur.execute(
            """
            SELECT source, type, description_lang, description_value
            FROM cve_weaknesses
            WHERE cve_id = %s
            ORDER BY source, type, description_lang
            """,
            (cve_id,),
        )
        weaknesses = cur.fetchall()

        cur.execute(
            """
            SELECT operator, cpe_match
            FROM cve_configurations
            WHERE cve_id = %s
            """,
            (cve_id,),
        )
        configurations = cur.fetchall()

        cur.execute(
            """
            SELECT url, source, tags
            FROM cve_references
            WHERE cve_id = %s
            ORDER BY source, url
            """,
            (cve_id,),
        )
        references = cur.fetchall()

        cur.execute(
            """
            SELECT id, source_identifier, url, created_at, downloaded_files
            FROM cve_poc_sources
            WHERE cve_id = %s
            ORDER BY created_at DESC, id DESC
            """,
            (cve_id,),
        )
        pocs = cur.fetchall()

    for row in configurations:
        row["cpe_match"] = _safe_load_json(row.get("cpe_match"), [])

    for row in references:
        row["tags"] = _safe_load_json(row.get("tags"), [])

    for row in pocs:
        files = _safe_load_json(row.get("downloaded_files"), [])
        row["downloaded_files"] = files if isinstance(files, list) else []
        row["download_count"] = len(row["downloaded_files"])

    return render_template(
        "cve_detail.html",
        cve_id=cve_id,
        return_to=return_to,
        vuln=vuln,
        descriptions=descriptions,
        metrics=metrics,
        tags=tags,
        weaknesses=weaknesses,
        configurations=configurations,
        references=references,
        pocs=pocs,
    )


@cve_bp.get("/dashboard")
@login_required
@email_verified_required
def dashboard():
    return render_template("dashboard.html")

@cve_bp.get("/api/cves")
@login_required
@email_verified_required
def api_cves():
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

    # === 湲곕낯 SELECT 荑쇰━ ===
    base_query = """
        FROM cve_vulnerabilities v
        LEFT JOIN cve_descriptions d ON v.cve_id = d.cve_id
        LEFT JOIN cvss_metrics m ON v.cve_id = m.cve_id
        LEFT JOIN cve_tags t ON v.cve_id = t.cve_id
        LEFT JOIN cve_epss e ON v.cve_id = e.cve_id
        WHERE 1=1
    """
    conditions = []
    params = []

    # === ?꾪꽣 ===
    if args.get("start") and args.get("end"):
        conditions.append("v.published BETWEEN %s AND %s")
        params.extend([args["start"], args["end"]])
    if args.get("severity"):
        conditions.append("m.base_severity = %s")
        params.append(args["severity"])
    if args.get("min_score") and args.get("max_score"):
        conditions.append("m.base_score BETWEEN %s AND %s")
        params.extend([args["min_score"], args["max_score"]])
    if args.get("tag"):
        conditions.append("t.tag LIKE %s")
        params.append(f"%{args['tag']}%")
    if args.get("vector"):
        conditions.append("m.attack_vector = %s")
        params.append(args["vector"])
    if args.get("search"):
        conditions.append("(v.cve_id LIKE %s OR d.description_value LIKE %s)")
        keyword = f"%{args['search']}%"
        params.extend([keyword, keyword])
    has_poc = (args.get("has_poc") or "").strip().lower()
    if has_poc in {"yes", "1", "true", "y"}:
        conditions.append("EXISTS (SELECT 1 FROM cve_poc_sources p2 WHERE p2.cve_id = v.cve_id)")
    elif has_poc in {"no", "0", "false", "n"}:
        conditions.append("NOT EXISTS (SELECT 1 FROM cve_poc_sources p2 WHERE p2.cve_id = v.cve_id)")

    if conditions:
        base_query += " AND " + " AND ".join(conditions)

    # === ?곗씠??荑쇰━ ===
    data_query = f"""
        SELECT v.cve_id, d.description_value, m.base_score, m.base_severity, m.attack_vector,
               e.epss_score, e.epss_percentile,
               GROUP_CONCAT(DISTINCT t.tag ORDER BY t.tag SEPARATOR ', ') AS tags,
               EXISTS(SELECT 1 FROM cve_poc_sources p3 WHERE p3.cve_id = v.cve_id) AS has_poc
        {base_query}
        GROUP BY v.cve_id
    """

    # === ?뺣젹 ===
    sort = args.get("sort", "v.cve_id")
    order = args.get("order", "DESC").upper()
    if sort not in ["v.cve_id", "d.description_value", "m.base_score", "m.base_severity", "m.attack_vector", "e.epss_score", "tags", "has_poc"]:
        sort = "v.cve_id"
    if order not in ["ASC", "DESC"]:
        order = "DESC"

    data_query += f" ORDER BY {sort} {order} LIMIT %s OFFSET %s"
    params_data = params + [size, offset]

    # === total 荑쇰━ (議곌굔 ?ы븿) ===
    count_query, count_params = _build_cve_count_query(args)

    with get_conn() as conn, get_cursor(conn) as cur:
        cur.execute(data_query, params_data)
        rows = cur.fetchall()

        cur.execute(count_query, count_params)
        total = cur.fetchone()["total"]

    return jsonify({
        "page": page,
        "size": size,
        "total": total,
        "pages": (total + size - 1) // size,
        "items": rows
    })

@cve_bp.get("/api/cve/summary")
@login_required
@email_verified_required
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


@cve_bp.get("/api/cve/severity")
@login_required
@email_verified_required
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


@cve_bp.get("/api/cve/scores")
@login_required
@email_verified_required
def cve_scores():
    conn = get_conn()
    with get_cursor(conn) as cur:
        query = """
            SELECT 
            CASE 
                WHEN base_score IS NULL THEN 'Unknown'
                WHEN base_score < 4 THEN '0-3'
                WHEN base_score < 7 THEN '4-6'
                WHEN base_score < 9 THEN '7-8'
                ELSE '9-10'
            END AS range_label,
            COUNT(*) AS count
            FROM cvss_metrics
            GROUP BY range_label
            ORDER BY FIELD(range_label, '0-3','4-6','7-8','9-10','Unknown');
        """
        cur.execute(query)
        rows = cur.fetchall()
    conn.close()
    return jsonify(rows)


@cve_bp.get("/api/cve/attack-vector")
@login_required
@email_verified_required
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


@cve_bp.get("/api/cve/impact")
@login_required
@email_verified_required
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


@cve_bp.get("/api/cve/tags")
@login_required
@email_verified_required
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


@cve_bp.get("/api/cve/poc-stats")
@login_required
@email_verified_required
def cve_poc_stats():
    conn = get_conn()
    with get_cursor(conn) as cur:
        # PoC媛 議댁옱?섎뒗 CVE ??
        cur.execute("""
            SELECT COUNT(DISTINCT p.cve_id) AS poc_count
            FROM cve_poc_sources p
            INNER JOIN cve_vulnerabilities v ON v.cve_id = p.cve_id
        """)
        poc_count = cur.fetchone()["poc_count"]

        # PoC媛 議댁옱?섏? ?딅뒗 CVE ??
        cur.execute("""
            SELECT COUNT(DISTINCT v.cve_id) AS no_poc_count
            FROM cve_vulnerabilities v
            LEFT JOIN cve_poc_sources p ON v.cve_id = p.cve_id
            WHERE p.cve_id IS NULL
        """)
        no_poc_count = cur.fetchone()["no_poc_count"]

    conn.close()

    return jsonify({
        "poc_count": poc_count,
        "no_poc_count": no_poc_count,
        "total": poc_count + no_poc_count
    })


