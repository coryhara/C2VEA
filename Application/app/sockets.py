from flask import request
from flask_socketio import emit

from .db import get_conn, get_cursor


def register_socket_handlers(socketio, app):
    poll_ms = app.config.get("POLL_INTERVAL_MS", 1000)
    active_subscribers = set()

    @socketio.on("connect")
    def on_connect():
        emit("hello", {"ok": True})

    @socketio.on("disconnect")
    def on_disconnect():
        active_subscribers.discard(request.sid)

    @socketio.on("subscribe_logs")
    def on_subscribe_logs(data=None):
        sid = request.sid
        active_subscribers.add(sid)

        last_id = 0
        if isinstance(data, dict):
            try:
                last_id = int(data.get("last_id", 0))
            except (TypeError, ValueError):
                last_id = 0

        while sid in active_subscribers:
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
