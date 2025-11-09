from flask import Blueprint, render_template, request, jsonify
from app.db import get_conn, get_cursor
from app.utils.decorators import (
    login_required,
    email_verified_required,
    github_verified_required,
    phone_verified_required,
    admin_required,
)

cve_bp = Blueprint("cve", __name__)

@cve_bp.get("/cves")
@login_required
@email_verified_required
def cve_page():
    return render_template("cves.html")   # ✅ CVE 리스트 페이지

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
    page = int(args.get("page", 1))
    size = 100
    offset = (page - 1) * size

    # === 기본 SELECT 쿼리 ===
    base_query = """
        FROM cve_vulnerabilities v
        LEFT JOIN cve_descriptions d ON v.cve_id = d.cve_id
        LEFT JOIN cvss_metrics m ON v.cve_id = m.cve_id
        LEFT JOIN cve_tags t ON v.cve_id = t.cve_id
        WHERE 1=1
    """
    conditions = []
    params = []

    # === 필터 ===
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
        conditions.append("d.description_value LIKE %s")
        params.append(f"%{args['search']}%")

    if conditions:
        base_query += " AND " + " AND ".join(conditions)

    # === 데이터 쿼리 ===
    data_query = f"""
        SELECT v.cve_id, d.description_value, m.base_score, m.base_severity, m.attack_vector,
               GROUP_CONCAT(t.tag) AS tags
        {base_query}
        GROUP BY v.cve_id
    """

    # === 정렬 ===
    sort = args.get("sort", "v.cve_id")
    order = args.get("order", "DESC").upper()
    if sort not in ["v.cve_id", "d.description_value", "m.base_score", "m.base_severity", "m.attack_vector", "tags"]:
        sort = "v.cve_id"
    if order not in ["ASC", "DESC"]:
        order = "DESC"

    data_query += f" ORDER BY {sort} {order} LIMIT %s OFFSET %s"
    params_data = params + [size, offset]

    # === total 쿼리 (조건 포함) ===
    count_query = f"SELECT COUNT(DISTINCT v.cve_id) AS total {base_query}"

    with get_conn() as conn, get_cursor(conn) as cur:
        cur.execute(data_query, params_data)
        rows = cur.fetchall()

        cur.execute(count_query, params)
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
        # PoC가 존재하는 CVE 수
        cur.execute("""
            SELECT COUNT(DISTINCT p.cve_id) AS poc_count
            FROM cve_poc_sources p
            INNER JOIN cve_vulnerabilities v ON v.cve_id = p.cve_id
        """)
        poc_count = cur.fetchone()["poc_count"]

        # PoC가 존재하지 않는 CVE 수
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