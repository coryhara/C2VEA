import os
from flask import Flask
from flask_socketio import SocketIO
from dataclasses import asdict
from .config import load_config
from .utils.session_helper import current_user

socketio = SocketIO(
    cors_allowed_origins=[],
    async_mode="gevent",
    logger=False, engineio_logger=False
)

def create_app():
    app = Flask(__name__, template_folder="templates")
    app.secret_key = os.urandom(32)

    cfg = load_config()
    app.config.update(asdict(cfg))

    raw = app.config["ALLOWED_ORIGINS"]
    allowed = [o.strip() for o in raw.replace(";", ",").split(",") if o.strip()]
    cors = allowed if allowed else None
    socketio.init_app(app, cors_allowed_origins=cors)

    from .db import init_pool
    init_pool(app)

    @app.context_processor
    def inject_global_config():
        return dict(ALLOWED_ORIGINS=app.config.get("ALLOWED_ORIGINS", []))

    @app.context_processor
    def inject_user():
        return {"current_user": current_user()}

    # ✅ 분리된 블루프린트 등록
    from app.routes.cve_routes import cve_bp
    from app.routes.poc_routes import poc_bp
    from app.routes.settings_routes import settings_bp
    from app.routes.logs_routes import logs_bp
    from app.routes.index_routes import index_bp
    from app.routes.auth_routes import auth_bp
    
    app.register_blueprint(index_bp)
    app.register_blueprint(cve_bp)
    app.register_blueprint(poc_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(logs_bp)
    app.register_blueprint(auth_bp)

    from .sockets import register_socket_handlers
    register_socket_handlers(socketio, app)

    return app