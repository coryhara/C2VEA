from flask import Flask
from flask_socketio import SocketIO
from dataclasses import asdict
from .config import load_config

socketio = SocketIO(
    cors_allowed_origins=[],
    async_mode="gevent",
    logger=False, engineio_logger=False
)

def create_app():
    app = Flask(__name__, template_folder="templates")

    cfg = load_config()
    app.config.update(asdict(cfg))
    app.secret_key = app.config["SECRET_KEY"]

    # Socket updates should work even when dashboard is accessed by local IP.
    # Keep HTTP origin restrictions in app config; relax only socket origin checks.
    socketio.init_app(app, cors_allowed_origins="*")

    from .db import (
        init_pool,
        ensure_auth_schema,
        ensure_epss_schema,
        ensure_job_progress_schema,
        ensure_performance_indexes,
        ensure_cve_list_meta_schema,
    )
    init_pool(app)
    ensure_auth_schema(app)
    ensure_epss_schema(app)
    ensure_job_progress_schema(app)
    ensure_performance_indexes(app)
    ensure_cve_list_meta_schema(app)

    @app.context_processor
    def inject_global_config():
        return dict(
            ALLOWED_ORIGINS=app.config.get("ALLOWED_ORIGINS", ""),
            PUBLIC_BASE_URL=app.config.get("PUBLIC_BASE_URL", "")
        )

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
