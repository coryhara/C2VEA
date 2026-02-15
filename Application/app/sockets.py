import json

from flask import request
from flask_socketio import emit

from .db import get_conn, get_cursor


def register_socket_handlers(socketio, app):
    poll_ms = app.config.get("POLL_INTERVAL_MS", 1000)
    dashboard_poll_ms = app.config.get("DASHBOARD_POLL_INTERVAL_MS", 5000)
    active_log_subscribers = set()
    active_dashboard_subscribers = set()

    def _fetch_dashboard_snapshot():
        conn = None
        cur = None
        try:
            conn = get_conn()
            cur = get_cursor(conn)

            cur.execute("SELECT COUNT(*) AS total FROM cve_vulnerabilities")
            total = (cur.fetchone() or {}).get("total", 0)

            cur.execute(
                """
                SELECT COUNT(*) AS recent_7d
                FROM cve_vulnerabilities
                WHERE published >= NOW() - INTERVAL 7 DAY
                """
            )
            recent_7d = (cur.fetchone() or {}).get("recent_7d", 0)

            cur.execute("SELECT COALESCE(AVG(base_score), 0) AS avg_score FROM cvss_metrics")
            avg_score = (cur.fetchone() or {}).get("avg_score", 0)

            cur.execute(
                """
                SELECT base_severity AS severity, COUNT(*) AS count
                FROM cvss_metrics
                GROUP BY base_severity
                ORDER BY FIELD(base_severity, 'Critical','High','Medium','Low')
                """
            )
            severity = cur.fetchall()

            cur.execute(
                """
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
                ORDER BY FIELD(range_label, '0-3','4-6','7-8','9-10','Unknown')
                """
            )
            scores = cur.fetchall()

            cur.execute(
                """
                SELECT attack_vector, COUNT(*) AS count
                FROM cvss_metrics
                GROUP BY attack_vector
                """
            )
            attack_vector = cur.fetchall()

            cur.execute(
                """
                SELECT tag, COUNT(*) AS count
                FROM cve_tags
                GROUP BY tag
                ORDER BY count DESC
                LIMIT 20
                """
            )
            tags = cur.fetchall()

            cur.execute(
                """
                SELECT COUNT(DISTINCT p.cve_id) AS poc_count
                FROM cve_poc_sources p
                INNER JOIN cve_vulnerabilities v ON v.cve_id = p.cve_id
                """
            )
            poc_count = (cur.fetchone() or {}).get("poc_count", 0)

            cur.execute(
                """
                SELECT COUNT(DISTINCT v.cve_id) AS no_poc_count
                FROM cve_vulnerabilities v
                LEFT JOIN cve_poc_sources p ON v.cve_id = p.cve_id
                WHERE p.cve_id IS NULL
                """
            )
            no_poc_count = (cur.fetchone() or {}).get("no_poc_count", 0)

            return {
                "summary": {
                    "total": total,
                    "recent_7d": recent_7d,
                    "avg_score": round(float(avg_score or 0), 2),
                },
                "severity": severity,
                "scores": scores,
                "attack_vector": attack_vector,
                "tags": tags,
                "poc_stats": {
                    "poc_count": poc_count,
                    "no_poc_count": no_poc_count,
                    "total": int(poc_count or 0) + int(no_poc_count or 0),
                },
            }
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    @socketio.on("connect")
    def on_connect():
        emit("hello", {"ok": True})

    @socketio.on("disconnect")
    def on_disconnect():
        active_log_subscribers.discard(request.sid)
        active_dashboard_subscribers.discard(request.sid)

    @socketio.on("subscribe_logs")
    def on_subscribe_logs(data=None):
        sid = request.sid
        active_log_subscribers.add(sid)

        last_id = 0
        if isinstance(data, dict):
            try:
                last_id = int(data.get("last_id", 0))
            except (TypeError, ValueError):
                last_id = 0

        while sid in active_log_subscribers:
            rows = []
            conn = None
            cur = None

            try:
                conn = get_conn()
                cur = get_cursor(conn)
                cur.execute(
                    """
                    SELECT id, status, message, log_time
                    FROM (
                      SELECT id, status, message, log_time
                      FROM logs
                      WHERE id > %s
                      ORDER BY id DESC
                      LIMIT 1000
                    ) t
                    ORDER BY id ASC
                    """,
                    (last_id,),
                )

                for row in cur:
                    last_id = max(last_id, int(row["id"]))
                    rows.append(
                        {
                            "type": "log",
                            "id": row["id"],
                            "status": row["status"],
                            "message": row["message"],
                            "log_time": row["log_time"].strftime("%Y-%m-%d %H:%M:%S")
                            if row["log_time"]
                            else None,
                        }
                    )
            except Exception as e:
                socketio.emit(
                    "notify",
                    {"type": "error", "label": "Logs", "message": f"Stream error: {e}"},
                    to=sid,
                )
            finally:
                if cur:
                    cur.close()
                if conn:
                    conn.close()

            if rows:
                socketio.emit("logs", rows, to=sid)

            socketio.sleep(poll_ms / 1000)

    @socketio.on("unsubscribe_logs")
    def on_unsubscribe_logs():
        active_log_subscribers.discard(request.sid)

    @socketio.on("subscribe_dashboard")
    def on_subscribe_dashboard(data=None):
        sid = request.sid
        active_dashboard_subscribers.add(sid)

        interval_ms = dashboard_poll_ms
        if isinstance(data, dict):
            try:
                interval_ms = max(1000, int(data.get("interval_ms", dashboard_poll_ms)))
            except (TypeError, ValueError):
                interval_ms = dashboard_poll_ms

        last_hash = None
        while sid in active_dashboard_subscribers:
            try:
                snapshot = _fetch_dashboard_snapshot()
                current_hash = json.dumps(snapshot, sort_keys=True, default=str)

                if last_hash != current_hash:
                    last_hash = current_hash
                    socketio.emit("dashboard_snapshot", snapshot, to=sid)
            except Exception as e:
                socketio.emit(
                    "notify",
                    {"type": "error", "label": "Dashboard", "message": f"Stream error: {e}"},
                    to=sid,
                )

            socketio.sleep(interval_ms / 1000)

    @socketio.on("unsubscribe_dashboard")
    def on_unsubscribe_dashboard():
        active_dashboard_subscribers.discard(request.sid)
