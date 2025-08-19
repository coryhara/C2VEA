import time
from zoneinfo import ZoneInfo
from flask_socketio import emit
from .db import get_conn

# 🔸 in-memory active task map: key(label-lower) -> {label, progress, updated}
_active_tasks = {}

def _norm(label: str) -> str:
    return (label or "").strip().lower() or "task"

def start_task(label: str):
    k = _norm(label)
    _active_tasks[k] = {"label": k, "progress": None, "updated": time.time()}

def set_progress(label: str, pct: int | None):
    k = _norm(label)
    if k in _active_tasks:
        _active_tasks[k]["progress"] = None if pct is None else max(0, min(100, int(pct)))
        _active_tasks[k]["updated"] = time.time()

def finish_task(label: str):
    k = _norm(label)
    _active_tasks.pop(k, None)


def register_socket_handlers(socketio, app):
    tz = ZoneInfo(app.config["TIMEZONE"])
    poll_ms = app.config["POLL_INTERVAL_MS"]

    @socketio.on("connect")
    def on_connect():
        emit("hello", {"ok": True})

    @socketio.on("request_active")
    def on_request_active():
        snapshot = []
        for v in sorted(_active_tasks.values(), key=lambda x: x["updated"], reverse=True):
            snapshot.append({"type": "active", "label": v["label"], "progress": v["progress"]})
        emit("active", snapshot)

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
                    (last_id,),
                )
                for row in cur:
                    last_id = max(last_id, int(row["id"]))
                    ts = row["log_time"]
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