from datetime import datetime
import time

import pymysql


class JobProgressReporter:
    def __init__(self, db_config, max_retries=3, retry_delay_sec=1.0):
        self.db_config = db_config
        self.max_retries = max_retries
        self.retry_delay_sec = retry_delay_sec
        self.ensure_schema()

    def ensure_schema(self):
        ddl_table = """
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
        ddl_index = (
            "ALTER TABLE job_progress "
            "ADD INDEX idx_job_progress_status_updated (status, updated_at)"
        )
        self._execute(ddl_table)
        exists_row = self._fetchone(
            """
            SELECT COUNT(*) AS cnt
            FROM information_schema.STATISTICS
            WHERE TABLE_SCHEMA = DATABASE()
              AND TABLE_NAME = 'job_progress'
              AND INDEX_NAME = 'idx_job_progress_status_updated'
            """
        )
        exists = (exists_row or {}).get("cnt", 0) > 0
        if not exists:
            self._execute(ddl_index)

    def _connect(self):
        return pymysql.connect(**self.db_config)

    def _execute(self, query, params=None):
        for attempt in range(1, self.max_retries + 1):
            conn = None
            try:
                conn = self._connect()
                with conn.cursor() as cur:
                    cur.execute(query, params or ())
                conn.commit()
                return
            except Exception:
                if conn:
                    try:
                        conn.rollback()
                    except Exception:
                        pass
                if attempt < self.max_retries:
                    time.sleep(self.retry_delay_sec * attempt)
                    continue
                return
            finally:
                if conn:
                    try:
                        conn.close()
                    except Exception:
                        pass

    def _fetchone(self, query, params=None):
        for attempt in range(1, self.max_retries + 1):
            conn = None
            try:
                conn = self._connect()
                with conn.cursor() as cur:
                    cur.execute(query, params or ())
                    row = cur.fetchone()
                return row if isinstance(row, dict) else {}
            except Exception:
                if attempt < self.max_retries:
                    time.sleep(self.retry_delay_sec * attempt)
                    continue
                return {}
            finally:
                if conn:
                    try:
                        conn.close()
                    except Exception:
                        pass

    def _upsert(self, job_key, job_type, job_label, status, percent, current_step, total_steps, detail):
        percent = float(max(0.0, min(100.0, percent)))
        current_step = int(max(0, current_step))
        total_steps = int(max(0, total_steps))
        self._execute(
            """
            INSERT INTO job_progress (
                job_key, job_type, job_label, status,
                progress_percent, current_step, total_steps,
                detail, started_at, finished_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW(), NULL)
            ON DUPLICATE KEY UPDATE
                job_type = VALUES(job_type),
                job_label = VALUES(job_label),
                status = VALUES(status),
                progress_percent = VALUES(progress_percent),
                current_step = VALUES(current_step),
                total_steps = VALUES(total_steps),
                detail = VALUES(detail),
                started_at = CASE
                    WHEN job_progress.started_at IS NULL OR VALUES(status) = 'RUNNING'
                    THEN IFNULL(job_progress.started_at, NOW())
                    ELSE job_progress.started_at
                END,
                finished_at = CASE
                    WHEN VALUES(status) IN ('SUCCESS', 'ERROR') THEN NOW()
                    ELSE NULL
                END,
                updated_at = CURRENT_TIMESTAMP
            """,
            (job_key, job_type, job_label, status, percent, current_step, total_steps, (detail or "")[:255]),
        )

    def start(self, job_key, job_type, job_label, total_steps=0, detail="Starting"):
        self._upsert(job_key, job_type, job_label, "RUNNING", 0.0, 0, total_steps, detail)

    def update(self, job_key, job_type, job_label, current_step, total_steps, detail=""):
        if total_steps > 0:
            percent = (float(current_step) / float(total_steps)) * 100.0
        else:
            percent = 0.0
        self._upsert(job_key, job_type, job_label, "RUNNING", percent, current_step, total_steps, detail)

    def complete(self, job_key, job_type, job_label, current_step=0, total_steps=0, detail="Completed"):
        if total_steps > 0:
            current_step = max(current_step, total_steps)
        self._upsert(job_key, job_type, job_label, "SUCCESS", 100.0, current_step, total_steps, detail)

    def fail(self, job_key, job_type, job_label, detail="Failed"):
        # Keep the last known progress values while marking failure.
        row = self._fetchone(
            "SELECT current_step, total_steps, progress_percent FROM job_progress WHERE job_key=%s",
            (job_key,),
        )
        current = int((row or {}).get("current_step", 0) or 0)
        total = int((row or {}).get("total_steps", 0) or 0)
        percent = float((row or {}).get("progress_percent", 0) or 0)
        self._upsert(job_key, job_type, job_label, "ERROR", percent, current, total, detail)

    def reset_running_to_error(self, detail="Interrupted by restart"):
        self._execute(
            """
            UPDATE job_progress
            SET status='ERROR',
                detail=%s,
                finished_at=NOW(),
                updated_at=CURRENT_TIMESTAMP
            WHERE status='RUNNING'
            """,
            ((detail or "")[:255],),
        )
