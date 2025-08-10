from flask import Flask
from flask_socketio import SocketIO
from dataclasses import asdict
from .config import load_config
from pathlib import Path

socketio = SocketIO(
    cors_allowed_origins=[],
    async_mode="eventlet",
    logger=False, engineio_logger=False
)

def create_app():
    app = Flask(__name__, template_folder="templates")

    cfg = load_config()
    app.config.update(asdict(cfg))  # dataclass → dict

    # ALLOWED_ORIGINS 파싱(콤마/세미콜론/공백)
    raw = app.config["ALLOWED_ORIGINS"]
    allowed = [o.strip() for o in raw.replace(";", ",").split(",") if o.strip()]
    cors = allowed if allowed else None  # None이면 same-origin만 허용

    socketio.init_app(app, cors_allowed_origins=cors)

    # DB 커넥션 풀 초기화(재시도 포함)
    from .db import init_pool
    init_pool(app)

    # 라우트 등록
    from .routes import bp as routes_bp
    app.register_blueprint(routes_bp)

    # 소켓 핸들러 등록
    from .sockets import register_socket_handlers
    register_socket_handlers(socketio, app)

    return app
