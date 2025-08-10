from flask import Flask
from flask_socketio import SocketIO
from dataclasses import asdict
from .config import load_config

from dotenv import load_dotenv
from pathlib import Path

socketio = SocketIO(
    cors_allowed_origins=[],
    async_mode="eventlet",
    logger=False, engineio_logger=False
)

def create_app():
    # 프로젝트 루트(/app) 기준 .env 자동 로드
    # __file__ = /app/app/__init__.py → parents[2] = /app
    project_root = Path(__file__).resolve().parents[2]
    env_path = project_root / ".env"
    if env_path.exists():
        load_dotenv(dotenv_path=env_path, override=False)
        print(f"[dotenv] loaded: {env_path}")

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
