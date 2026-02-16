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


def ensure_job_progress_schema(app):
    """Create table used for daemon job progress tracking."""
    conn = None
    cur = None
    try:
        conn = get_conn()
        cur = get_cursor(conn)

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS job_progress (
                job_key VARCHAR(100) PRIMARY KEY,
                job_type VARCHAR(60) NOT NULL,
                job_label VARCHAR(120) NOT NULL,
                status VARCHAR(20) NOT NULL,
                progress_percent DECIMAL(6,2) NOT NULL DEFAULT 0,
                current_step BIGINT NOT NULL DEFAULT 0,
                total_steps BIGINT NOT NULL DEFAULT 0,
                detail VARCHAR(255) NULL,
                started_at TIMESTAMP NULL,
                finished_at TIMESTAMP NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
            """
        )

        cur.execute(
            """
            SELECT COUNT(*) AS cnt
            FROM information_schema.STATISTICS
            WHERE TABLE_SCHEMA=%s
              AND TABLE_NAME='job_progress'
              AND INDEX_NAME='idx_job_progress_status_updated'
            """,
            (app.config["DB_NAME"],),
        )
        has_status_index = (cur.fetchone() or {}).get("cnt", 0) > 0
        if not has_status_index:
            cur.execute(
                "ALTER TABLE job_progress ADD INDEX idx_job_progress_status_updated (status, updated_at)"
            )

        conn.commit()
        app.logger.info("Job progress schema migration check completed")
    except Exception as e:
        if conn:
            conn.rollback()
        app.logger.exception("Job progress schema migration failed: %s", e)
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
            ("cvss_metrics", "idx_cvss_metrics_cve_score", "ALTER TABLE cvss_metrics ADD INDEX idx_cvss_metrics_cve_score (cve_id, base_score)"),
            ("cvss_metrics", "idx_cvss_metrics_cve_score_id", "ALTER TABLE cvss_metrics ADD INDEX idx_cvss_metrics_cve_score_id (cve_id, base_score, id)"),
            ("cve_descriptions", "idx_cve_desc_cve_lang", "ALTER TABLE cve_descriptions ADD INDEX idx_cve_desc_cve_lang (cve_id, description_lang)"),
            ("cve_descriptions", "idx_cve_desc_cve_lang_id", "ALTER TABLE cve_descriptions ADD INDEX idx_cve_desc_cve_lang_id (cve_id, description_lang, id)"),
            ("cve_tags", "idx_cve_tags_cve_tag", "ALTER TABLE cve_tags ADD INDEX idx_cve_tags_cve_tag (cve_id, tag)"),
            ("cve_poc_sources", "idx_cve_poc_created_id", "ALTER TABLE cve_poc_sources ADD INDEX idx_cve_poc_created_id (created_at, id)"),
            ("cve_poc_sources", "idx_cve_poc_source_id", "ALTER TABLE cve_poc_sources ADD INDEX idx_cve_poc_source_id (source_identifier, id)"),
            ("cve_poc_sources", "idx_cve_poc_cve_id", "ALTER TABLE cve_poc_sources ADD INDEX idx_cve_poc_cve_id (cve_id)"),
            ("cve_poc_sources", "idx_cve_poc_cve_id_id", "ALTER TABLE cve_poc_sources ADD INDEX idx_cve_poc_cve_id_id (cve_id, id)"),
            ("cve_poc_sources", "idx_cve_poc_source_identifier_id", "ALTER TABLE cve_poc_sources ADD INDEX idx_cve_poc_source_identifier_id (source_identifier, id)"),
            ("cve_poc_sources", "idx_cve_poc_url_id", "ALTER TABLE cve_poc_sources ADD INDEX idx_cve_poc_url_id (url(191), id)"),
            ("cve_epss", "idx_cve_epss_score", "ALTER TABLE cve_epss ADD INDEX idx_cve_epss_score (epss_score)"),
            ("job_progress", "idx_job_progress_status_updated", "ALTER TABLE job_progress ADD INDEX idx_job_progress_status_updated (status, updated_at)"),
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


def ensure_cve_list_meta_schema(app):
    """
    Build a lightweight per-CVE projection table used by list sorting.
    This removes expensive per-request aggregate subqueries from /api/cves.
    """
    conn = None
    cur = None
    schema = app.config["DB_NAME"]
    try:
        conn = get_conn()
        cur = get_cursor(conn)

        def _execute_with_retry(sql, params=None, retries=4):
            for attempt in range(1, retries + 1):
                try:
                    cur.execute(sql, params or ())
                    return True
                except errors.InternalError as e:
                    msg = str(e).lower()
                    is_lock_issue = ("deadlock found" in msg) or ("lock wait timeout exceeded" in msg)
                    if not is_lock_issue:
                        raise
                    if attempt >= retries:
                        app.logger.warning("cve_list_meta sync skipped after lock retries: %s", e)
                        return False
                    time.sleep(0.4 * attempt)

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS cve_list_meta (
                cve_id VARCHAR(50) PRIMARY KEY,
                description_value MEDIUMTEXT NULL,
                description_sort VARCHAR(512) NULL,
                description_sort_key VARCHAR(191) NULL,
                base_score DOUBLE NULL,
                base_severity VARCHAR(20) NULL,
                attack_vector VARCHAR(20) NULL,
                tags TEXT NULL,
                tags_sort VARCHAR(512) NULL,
                tags_sort_key VARCHAR(191) NULL,
                has_poc TINYINT(1) NOT NULL DEFAULT 0,
                epss_score DOUBLE NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                CONSTRAINT fk_cve_list_meta_cve
                    FOREIGN KEY (cve_id)
                    REFERENCES cve_vulnerabilities (cve_id)
                    ON DELETE CASCADE
            )
            """
        )

        # Backward-compatible column adds for existing deployments.
        column_specs = [
            ("description_sort_key", "ALTER TABLE cve_list_meta ADD COLUMN description_sort_key VARCHAR(191) NULL AFTER description_sort"),
            ("tags_sort_key", "ALTER TABLE cve_list_meta ADD COLUMN tags_sort_key VARCHAR(191) NULL AFTER tags_sort"),
        ]
        for column_name, ddl in column_specs:
            cur.execute(
                """
                SELECT COUNT(*) AS cnt
                FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=%s
                  AND TABLE_NAME='cve_list_meta'
                  AND COLUMN_NAME=%s
                """,
                (schema, column_name),
            )
            exists = (cur.fetchone() or {}).get("cnt", 0) > 0
            if not exists:
                cur.execute(ddl)

        index_specs = [
            ("cve_list_meta", "idx_cve_list_meta_desc_sort", "ALTER TABLE cve_list_meta ADD INDEX idx_cve_list_meta_desc_sort (description_sort(191), cve_id)"),
            ("cve_list_meta", "idx_cve_list_meta_desc_key_cve", "ALTER TABLE cve_list_meta ADD INDEX idx_cve_list_meta_desc_key_cve (description_sort_key, cve_id)"),
            ("cve_list_meta", "idx_cve_list_meta_score_cve", "ALTER TABLE cve_list_meta ADD INDEX idx_cve_list_meta_score_cve (base_score, cve_id)"),
            ("cve_list_meta", "idx_cve_list_meta_severity_cve", "ALTER TABLE cve_list_meta ADD INDEX idx_cve_list_meta_severity_cve (base_severity, cve_id)"),
            ("cve_list_meta", "idx_cve_list_meta_vector_cve", "ALTER TABLE cve_list_meta ADD INDEX idx_cve_list_meta_vector_cve (attack_vector, cve_id)"),
            ("cve_list_meta", "idx_cve_list_meta_tags_sort", "ALTER TABLE cve_list_meta ADD INDEX idx_cve_list_meta_tags_sort (tags_sort(191), cve_id)"),
            ("cve_list_meta", "idx_cve_list_meta_tags_key_cve", "ALTER TABLE cve_list_meta ADD INDEX idx_cve_list_meta_tags_key_cve (tags_sort_key, cve_id)"),
            ("cve_list_meta", "idx_cve_list_meta_has_poc_cve", "ALTER TABLE cve_list_meta ADD INDEX idx_cve_list_meta_has_poc_cve (has_poc, cve_id)"),
            ("cve_list_meta", "idx_cve_list_meta_epss_cve", "ALTER TABLE cve_list_meta ADD INDEX idx_cve_list_meta_epss_cve (epss_score, cve_id)"),
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

        # Ensure all CVEs are present in the projection table.
        _execute_with_retry(
            """
            INSERT INTO cve_list_meta (cve_id)
            SELECT v.cve_id
            FROM cve_vulnerabilities v
            ON DUPLICATE KEY UPDATE cve_id = VALUES(cve_id)
            """
        )

        # Keep projection table clean.
        _execute_with_retry(
            """
            DELETE m
            FROM cve_list_meta m
            LEFT JOIN cve_vulnerabilities v ON v.cve_id = m.cve_id
            WHERE v.cve_id IS NULL
            """
        )

        # Full projection rebuild is expensive. Run only when cache has missing key fields.
        cur.execute(
            """
            SELECT EXISTS(
                SELECT 1
                FROM cve_list_meta
                WHERE description_sort_key IS NULL
                LIMIT 1
            ) AS needed
            """
        )
        need_desc_refresh = bool((cur.fetchone() or {}).get("needed"))

        cur.execute(
            """
            SELECT EXISTS(
                SELECT 1
                FROM cve_list_meta m
                JOIN cvss_metrics cm ON cm.cve_id = m.cve_id
                WHERE m.base_score IS NULL
                LIMIT 1
            ) AS needed
            """
        )
        need_metric_refresh = bool((cur.fetchone() or {}).get("needed"))

        cur.execute(
            """
            SELECT EXISTS(
                SELECT 1
                FROM cve_list_meta
                WHERE tags IS NOT NULL
                  AND tags_sort_key IS NULL
                LIMIT 1
            ) AS needed
            """
        )
        need_tag_refresh = bool((cur.fetchone() or {}).get("needed"))

        if need_desc_refresh or need_metric_refresh or need_tag_refresh:
            # Preferred description: English first, otherwise the first available.
            _execute_with_retry(
                """
                INSERT INTO cve_list_meta (cve_id, description_value, description_sort, description_sort_key)
                SELECT
                    d.cve_id,
                    COALESCE(
                        MAX(CASE WHEN d.description_lang='en' THEN d.description_value END),
                        MIN(d.description_value)
                    ) AS description_value,
                    LEFT(
                        COALESCE(
                            MAX(CASE WHEN d.description_lang='en' THEN d.description_value END),
                            MIN(d.description_value)
                        ),
                        512
                    ) AS description_sort,
                    LEFT(
                        COALESCE(
                            MAX(CASE WHEN d.description_lang='en' THEN d.description_value END),
                            MIN(d.description_value)
                        ),
                        191
                    ) AS description_sort_key
                FROM cve_descriptions d
                GROUP BY d.cve_id
                ON DUPLICATE KEY UPDATE
                    description_value = VALUES(description_value),
                    description_sort = VALUES(description_sort),
                    description_sort_key = VALUES(description_sort_key)
                """
            )

            # Highest-score CVSS row per CVE (tie-break: lowest id).
            _execute_with_retry(
                """
                INSERT INTO cve_list_meta (cve_id, base_score, base_severity, attack_vector)
                SELECT
                    m.cve_id,
                    m.base_score,
                    m.base_severity,
                    m.attack_vector
                FROM cvss_metrics m
                JOIN (
                    SELECT cve_id, MAX(base_score) AS max_score
                    FROM cvss_metrics
                    GROUP BY cve_id
                ) mx ON mx.cve_id = m.cve_id AND mx.max_score = m.base_score
                LEFT JOIN cvss_metrics tie
                    ON tie.cve_id = m.cve_id
                   AND tie.base_score = m.base_score
                   AND tie.id < m.id
                WHERE tie.id IS NULL
                ON DUPLICATE KEY UPDATE
                    base_score = VALUES(base_score),
                    base_severity = VALUES(base_severity),
                    attack_vector = VALUES(attack_vector)
                """
            )

            # Aggregated tags for quick display/sorting.
            _execute_with_retry(
                """
                INSERT INTO cve_list_meta (cve_id, tags, tags_sort, tags_sort_key)
                SELECT
                    t.cve_id,
                    GROUP_CONCAT(DISTINCT t.tag ORDER BY t.tag SEPARATOR ', ') AS tags,
                    LEFT(GROUP_CONCAT(DISTINCT t.tag ORDER BY t.tag SEPARATOR ', '), 512) AS tags_sort,
                    LEFT(GROUP_CONCAT(DISTINCT t.tag ORDER BY t.tag SEPARATOR ', '), 191) AS tags_sort_key
                FROM cve_tags t
                GROUP BY t.cve_id
                ON DUPLICATE KEY UPDATE
                    tags = VALUES(tags),
                    tags_sort = VALUES(tags_sort),
                    tags_sort_key = VALUES(tags_sort_key)
                """
            )

        # PoC presence + EPSS mirror.
        _execute_with_retry(
            """
            UPDATE cve_list_meta m
            LEFT JOIN (
                SELECT DISTINCT cve_id, 1 AS has_poc
                FROM cve_poc_sources
            ) p ON p.cve_id = m.cve_id
            LEFT JOIN cve_epss e ON e.cve_id = m.cve_id
            SET
                m.has_poc = COALESCE(p.has_poc, 0),
                m.epss_score = e.epss_score
            """
        )

        conn.commit()
        app.logger.info("CVE list meta cache check completed")
    except Exception as e:
        if conn:
            conn.rollback()
        app.logger.exception("CVE list meta cache migration failed: %s", e)
        raise
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
