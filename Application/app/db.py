import time
import mysql.connector
from mysql.connector import pooling, errors

_pool = None

def init_pool(app):
    """Flask app 초기화 시 DB 풀 생성"""
    global _pool
    cfg = app.config
    params = dict(
        pool_name="logs_pool",
        pool_size=5,
        pool_reset_session=True,
        host=cfg["DB_HOST"],
        port=int(cfg["DB_PORT"]),
        user=cfg["DB_USER"],
        password=cfg["DB_PASSWORD"],
        database=cfg["DB_NAME"],
        charset=cfg.get("DB_CHARSET", "utf8mb4"),
        collation="utf8mb4_unicode_ci",
        allow_local_infile=False,
        autocommit=True,
        use_pure=True,
        connection_timeout=5,
    )

    for attempt in range(1, 30 + 1):
        try:
            _pool = pooling.MySQLConnectionPool(**params)
            app.logger.info("DB pool created (attempt %d)", attempt)
            return
        except (errors.InterfaceError, errors.DatabaseError) as e:
            app.logger.warning("DB not ready (attempt %d/30): %s", attempt, e)
            time.sleep(1)
        except Exception as e:
            app.logger.exception("Unexpected DB init error: %s", e)
            time.sleep(1)

    raise RuntimeError("DB connection pool init failed after retries")


def get_conn():
    global _pool
    if _pool is None:
        raise RuntimeError("DB pool not initialized")

    conn = _pool.get_connection()
    try:
        conn.ping(reconnect=True, attempts=2, delay=1)
    except Exception:
        conn.reconnect(attempts=2, delay=1)
    return conn


def get_cursor(conn):
    return conn.cursor(dictionary=True)
