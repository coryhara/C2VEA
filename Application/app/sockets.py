import time
from flask_socketio import emit
from .db import get_conn, get_cursor


def register_socket_handlers(socketio, app):
    """Register socket.io event handlers"""
    poll_ms = app.config.get("POLL_INTERVAL_MS", 1000)

    @socketio.on("connect")
    def on_connect():
        emit("hello", {"ok": True})

    @socketio.on("subscribe_logs")
    def on_subscribe_logs(data=None):
        """실시간 로그 구독"""
        last_id = 0
        if isinstance(data, dict):
            try:
                last_id = int(data.get("last_id", 0))
            except (TypeError, ValueError):
                last_id = 0

        while True:
            rows = []
            conn, cur = None, None

            try:
                conn = get_conn()
                cur = get_cursor(conn)   # ✅ 무조건 DictCursor 반환

                cur.execute("""
                    SELECT id, status, message, log_time
                    FROM (
                      SELECT id, status, message, log_time
                      FROM logs
                      WHERE id > %s
                      ORDER BY id DESC
                      LIMIT 1000
                    ) t
                    ORDER BY id ASC
                """, (last_id,))

                for row in cur:
                    last_id = max(last_id, int(row["id"]))
                    rows.append({
                        "type": "log",
                        "id": row["id"],
                        "status": row["status"],
                        "message": row["message"],
                        "log_time": row["log_time"].strftime("%Y-%m-%d %H:%M:%S")
                        if row["log_time"] else None
                    })

            except Exception as e:
                emit("notify", {
                    "type": "error",
                    "label": "Logs",
                    "message": f"❌ Stream error: {e}"
                })

            finally:
                if cur:
                    cur.close()
                if conn:
                    conn.close()

            if rows:
                emit("logs", rows)

            socketio.sleep(poll_ms / 1000)
