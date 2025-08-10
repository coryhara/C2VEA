from zoneinfo import ZoneInfo
from flask_socketio import emit
from .db import get_conn

def register_socket_handlers(socketio, app):
    tz = ZoneInfo(app.config["TIMEZONE"])
    poll_ms = app.config["POLL_INTERVAL_MS"]

    @socketio.on("connect")
    def on_connect():
        emit("hello", {"ok": True})

    @socketio.on("subscribe_logs")
    def on_subscribe_logs(data=None):
        last_id = 0
        if isinstance(data, dict) and "last_id" in data:
            try:
                last_id = int(data["last_id"])
            except Exception:
                last_id = 0

        while True:
            rows = []
            try:
                conn = get_conn()
                cur = conn.cursor(dictionary=True)
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
                    (last_id,)
                )
                for row in cur:
                    last_id = max(last_id, int(row["id"]))
                    ts = row["log_time"]
                    # mysql-connector 결과가 naive datetime일 수 있어 바로 문자열로
                    ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if ts else None
                    rows.append({
                        "type": "log",
                        "id": row["id"],
                        "status": row["status"],
                        "message": row["message"],
                        "log_time": ts_str
                    })
                cur.close()
                conn.close()
            except Exception as e:
                emit("notify", {"type":"notify","label":"error","message":f"❌ stream error → {e}"})
                socketio.sleep(poll_ms/1000)
                continue

            if rows:
                emit("logs", rows)

            socketio.sleep(poll_ms/1000)
