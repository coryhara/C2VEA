import time
import hashlib
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


def ensure_auth_schema(app):
    """Apply lightweight auth schema migrations required by the application."""
    conn = None
    cur = None
    try:
        conn = get_conn()
        cur = get_cursor(conn)

        # Modern password hashes (scrypt/pbkdf2) can exceed 128 chars.
        cur.execute("ALTER TABLE coharas MODIFY COLUMN password VARCHAR(255) NOT NULL")

        cur.execute("""
            SELECT COUNT(*) AS cnt
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA=%s
              AND TABLE_NAME='coharas'
              AND COLUMN_NAME='github_token_hash'
        """, (app.config["DB_NAME"],))
        has_token_hash = (cur.fetchone() or {}).get("cnt", 0) > 0

        if not has_token_hash:
            cur.execute("ALTER TABLE coharas ADD COLUMN github_token_hash CHAR(64) NULL AFTER github_token")

        cur.execute("""
            SELECT id, github_token
            FROM coharas
            WHERE github_token_hash IS NULL OR github_token_hash = ''
        """)
        for row in cur.fetchall():
            token = row.get("github_token") or ""
            token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
            cur.execute(
                "UPDATE coharas SET github_token_hash=%s WHERE id=%s",
                (token_hash, row["id"])
            )

        cur.execute("""
            SELECT COUNT(*) AS cnt
            FROM information_schema.STATISTICS
            WHERE TABLE_SCHEMA=%s
              AND TABLE_NAME='coharas'
              AND INDEX_NAME='uq_coharas_github_token_hash'
        """, (app.config["DB_NAME"],))
        has_index = (cur.fetchone() or {}).get("cnt", 0) > 0

        if not has_index:
            cur.execute("ALTER TABLE coharas ADD UNIQUE KEY uq_coharas_github_token_hash (github_token_hash)")

        conn.commit()
        app.logger.info("Auth schema migration check completed")
    except Exception as e:
        if conn:
            conn.rollback()
        app.logger.exception("Auth schema migration failed: %s", e)
        raise
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


def ensure_epss_schema(app):
    """Create EPSS storage table used by CVE list/detail pages."""
    conn = None
    cur = None
    try:
        conn = get_conn()
        cur = get_cursor(conn)

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS cve_epss (
                cve_id VARCHAR(50) PRIMARY KEY,
                epss_score DOUBLE NULL,
                epss_percentile DOUBLE NULL,
                score_date DATE NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                CONSTRAINT fk_cve_epss_cve
                    FOREIGN KEY (cve_id)
                    REFERENCES cve_vulnerabilities (cve_id)
                    ON DELETE CASCADE
            )
            """
        )

        cur.execute(
            """
            SELECT COUNT(*) AS cnt
            FROM information_schema.STATISTICS
            WHERE TABLE_SCHEMA=%s
              AND TABLE_NAME='cve_epss'
              AND INDEX_NAME='idx_cve_epss_score'
            """,
            (app.config["DB_NAME"],),
        )
        has_score_index = (cur.fetchone() or {}).get("cnt", 0) > 0
        if not has_score_index:
            cur.execute("ALTER TABLE cve_epss ADD INDEX idx_cve_epss_score (epss_score)")

        conn.commit()
        app.logger.info("EPSS schema migration check completed")
    except Exception as e:
        if conn:
            conn.rollback()
        app.logger.exception("EPSS schema migration failed: %s", e)
        raise
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


def ensure_performance_indexes(app):
    """Create missing non-breaking indexes used by list APIs."""
    conn = None
    cur = None
    schema = app.config["DB_NAME"]
    try:
        conn = get_conn()
        cur = get_cursor(conn)

        index_specs = [
            ("cve_vulnerabilities", "idx_cve_vuln_published_cve", "ALTER TABLE cve_vulnerabilities ADD INDEX idx_cve_vuln_published_cve (published, cve_id)"),
            ("cvss_metrics", "idx_cvss_metrics_severity_cve", "ALTER TABLE cvss_metrics ADD INDEX idx_cvss_metrics_severity_cve (base_severity, cve_id)"),
            ("cvss_metrics", "idx_cvss_metrics_score_cve", "ALTER TABLE cvss_metrics ADD INDEX idx_cvss_metrics_score_cve (base_score, cve_id)"),
            ("cvss_metrics", "idx_cvss_metrics_vector_cve", "ALTER TABLE cvss_metrics ADD INDEX idx_cvss_metrics_vector_cve (attack_vector, cve_id)"),
            ("cve_descriptions", "idx_cve_desc_cve_lang", "ALTER TABLE cve_descriptions ADD INDEX idx_cve_desc_cve_lang (cve_id, description_lang)"),
            ("cve_tags", "idx_cve_tags_cve_tag", "ALTER TABLE cve_tags ADD INDEX idx_cve_tags_cve_tag (cve_id, tag)"),
            ("cve_poc_sources", "idx_cve_poc_created_id", "ALTER TABLE cve_poc_sources ADD INDEX idx_cve_poc_created_id (created_at, id)"),
            ("cve_poc_sources", "idx_cve_poc_source_id", "ALTER TABLE cve_poc_sources ADD INDEX idx_cve_poc_source_id (source_identifier, id)"),
            ("cve_poc_sources", "idx_cve_poc_cve_id", "ALTER TABLE cve_poc_sources ADD INDEX idx_cve_poc_cve_id (cve_id)"),
            ("cve_epss", "idx_cve_epss_score", "ALTER TABLE cve_epss ADD INDEX idx_cve_epss_score (epss_score)"),
        ]

        for table_name, index_name, ddl in index_specs:
            cur.execute(
                """
                SELECT COUNT(*) AS cnt
                FROM information_schema.STATISTICS
                WHERE TABLE_SCHEMA=%s
                  AND TABLE_NAME=%s
                  AND INDEX_NAME=%s
                """,
                (schema, table_name, index_name),
            )
            exists = (cur.fetchone() or {}).get("cnt", 0) > 0
            if not exists:
                cur.execute(ddl)

        conn.commit()
        app.logger.info("Performance index check completed")
    except Exception as e:
        if conn:
            conn.rollback()
        app.logger.exception("Performance index migration failed: %s", e)
        raise
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
