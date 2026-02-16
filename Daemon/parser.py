import json
import os
import time
from datetime import datetime, timedelta

import pymysql
import requests


class CVEParser:
    def __init__(
        self,
        db_config,
        json_base_dir_path,
        start_year,
        parse_progress_callback=None,
        epss_progress_callback=None,
    ):
        self.db_config = db_config
        self.json_base_dir_path = json_base_dir_path
        self.start_year = start_year
        self.max_retries = 3
        self.retry_delay_sec = 2
        self.epss_api_url = os.getenv("EPSS_API_URL", "https://api.first.org/data/v1/epss")
        self.epss_timeout_sec = float(os.getenv("EPSS_TIMEOUT_SEC", "20"))
        self.epss_batch_size = max(1, min(200, int(os.getenv("EPSS_BATCH_SIZE", "100"))))
        self.epss_max_retries = max(1, int(os.getenv("EPSS_MAX_RETRIES", "3")))
        self.epss_retry_delay_sec = float(os.getenv("EPSS_RETRY_DELAY_SEC", "1.5"))
        self.epss_refresh_days = max(0, int(os.getenv("EPSS_REFRESH_DAYS", "7")))
        self._epss_api_online = True
        self.conn = None
        self.cursor = None
        self._epss_session = requests.Session()
        self.parse_progress_callback = parse_progress_callback
        self.epss_progress_callback = epss_progress_callback
        self._connect()
        self.ensure_epss_schema()

    def _connect(self):
        self.conn = pymysql.connect(**self.db_config)
        self.cursor = self.conn.cursor()

    def _is_retryable_db_error(self, err):
        msg = str(err).lower()
        if isinstance(err, pymysql.err.OperationalError):
            code = err.args[0] if err.args else None
            if code in (2006, 2013, 2055):
                return True
        return ("lost connection" in msg) or ("server has gone away" in msg)

    def _reconnect(self):
        try:
            if self.cursor:
                self.cursor.close()
        except Exception:
            pass
        try:
            if self.conn:
                self.conn.close()
        except Exception:
            pass
        self._connect()

    def _safe_rollback(self):
        try:
            if self.conn:
                self.conn.rollback()
        except Exception:
            pass

    # =========================
    # Logging
    # =========================
    def log(self, status: str, message: str):
        conn = None
        try:
            conn = pymysql.connect(**self.db_config)
            with conn.cursor() as cursor:
                cursor.execute("INSERT INTO logs (status, message) VALUES (%s, %s)", (status, message))
            conn.commit()
        except Exception:
            pass
        finally:
            try:
                if conn:
                    conn.close()
            except Exception:
                pass

    def _emit_parse_progress(self, current_step, total_steps, detail):
        if not callable(self.parse_progress_callback):
            return
        try:
            self.parse_progress_callback(int(current_step), int(total_steps), str(detail))
        except Exception:
            pass

    def _emit_epss_progress(self, current_step, total_steps, detail):
        if not callable(self.epss_progress_callback):
            return
        try:
            self.epss_progress_callback(int(current_step), int(total_steps), str(detail))
        except Exception:
            pass

    # =========================
    # JSON loading
    # =========================
    def iter_json_data_from_year_dirs(self):
        current_year = datetime.now().year
        for year in range(self.start_year, current_year + 1):
            year_dir_path = os.path.join(self.json_base_dir_path, str(year))
            if not os.path.isdir(year_dir_path):
                continue
            for filename in os.listdir(year_dir_path):
                if not filename.endswith(".json"):
                    continue
                file_path = os.path.join(year_dir_path, filename)
                with open(file_path, "r", encoding="utf-8") as f:
                    try:
                        yield json.load(f)
                    except json.JSONDecodeError:
                        self.log("ERROR", f"Invalid JSON format: {file_path}")

    def count_total_cves_from_year_dirs(self):
        total = 0
        for file_data in self.iter_json_data_from_year_dirs():
            if isinstance(file_data, list):
                total += len(file_data)
        return total

    def ensure_epss_schema(self):
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS cve_epss (
                cve_id VARCHAR(50) PRIMARY KEY,
                epss_score DOUBLE NULL,
                epss_percentile DOUBLE NULL,
                score_date DATE NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (cve_id) REFERENCES cve_vulnerabilities (cve_id) ON DELETE CASCADE
            )
            """
        )
        self.cursor.execute(
            """
            SELECT COUNT(*) AS cnt
            FROM information_schema.STATISTICS
            WHERE TABLE_SCHEMA = DATABASE()
              AND TABLE_NAME = 'cve_epss'
              AND INDEX_NAME = 'idx_cve_epss_score'
            """
        )
        result = self.cursor.fetchone()
        has_index = False
        if isinstance(result, dict):
            has_index = (result.get("cnt", 0) or 0) > 0
        elif isinstance(result, (list, tuple)) and result:
            has_index = (result[0] or 0) > 0
        if not has_index:
            self.cursor.execute("ALTER TABLE cve_epss ADD INDEX idx_cve_epss_score (epss_score)")
        self.conn.commit()

    def _chunked(self, values, size):
        for i in range(0, len(values), size):
            yield values[i:i + size]

    def _parse_epss_float(self, value):
        if value in (None, ""):
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def _parse_epss_date(self, value):
        if not value:
            return None
        if isinstance(value, datetime):
            return value.date()
        text = str(value).strip()
        if not text:
            return None
        try:
            return datetime.strptime(text[:10], "%Y-%m-%d").date()
        except ValueError:
            return None

    def _epss_api_get(self, params):
        for attempt in range(1, self.epss_max_retries + 1):
            try:
                response = self._epss_session.get(
                    self.epss_api_url,
                    params=params,
                    timeout=self.epss_timeout_sec,
                )
                if response.status_code == 200:
                    self._epss_api_online = True
                    return response.json()
                if response.status_code in (429, 500, 502, 503, 504) and attempt < self.epss_max_retries:
                    time.sleep(self.epss_retry_delay_sec * attempt)
                    continue
                self.log("WARNING", f"EPSS API returned {response.status_code} for params={params}")
                self._epss_api_online = False
                return None
            except requests.RequestException as err:
                if attempt < self.epss_max_retries:
                    time.sleep(self.epss_retry_delay_sec * attempt)
                    continue
                self.log("WARNING", f"EPSS API request failed for params={params}: {err}")
                self._epss_api_online = False
                return None
        return None

    def _fetch_epss_for_batch(self, cve_ids):
        if not cve_ids:
            return {}
        payload = self._epss_api_get({"cve": ",".join(cve_ids)})
        if not isinstance(payload, dict):
            return {}
        rows = payload.get("data") or []
        results = {}
        for row in rows:
            cve_id = (row.get("cve") or "").strip().upper()
            if not cve_id:
                continue
            results[cve_id] = {
                "epss_score": self._parse_epss_float(row.get("epss")),
                "epss_percentile": self._parse_epss_float(row.get("percentile")),
                "score_date": self._parse_epss_date(row.get("date")),
            }
        return results

    def _fetch_epss_for_single(self, cve_id):
        if not cve_id:
            return None
        payload = self._epss_api_get({"cve": cve_id})
        if not isinstance(payload, dict):
            return None
        rows = payload.get("data") or []
        if not rows:
            return None
        row = rows[0]
        return {
            "epss_score": self._parse_epss_float(row.get("epss")),
            "epss_percentile": self._parse_epss_float(row.get("percentile")),
            "score_date": self._parse_epss_date(row.get("date")),
        }

    def _load_epss_snapshot(self, cve_ids):
        snapshot = {}
        if not cve_ids:
            return snapshot
        with pymysql.connect(**self.db_config) as conn:
            with conn.cursor() as cursor:
                for chunk in self._chunked(cve_ids, 1000):
                    placeholders = ", ".join(["%s"] * len(chunk))
                    cursor.execute(
                        f"""
                        SELECT cve_id, score_date, updated_at
                        FROM cve_epss
                        WHERE cve_id IN ({placeholders})
                        """,
                        chunk,
                    )
                    for row in cursor.fetchall():
                        if isinstance(row, dict):
                            cve_id = (row.get("cve_id") or "").upper()
                            record = row
                        elif isinstance(row, (list, tuple)) and len(row) >= 3:
                            cve_id = (row[0] or "").upper()
                            record = {"cve_id": row[0], "score_date": row[1], "updated_at": row[2]}
                        else:
                            continue
                        if cve_id:
                            snapshot[cve_id] = record
        return snapshot

    def _cves_needing_epss_refresh(self, cve_ids):
        if not cve_ids:
            return []
        snapshot = self._load_epss_snapshot(cve_ids)
        if self.epss_refresh_days == 0:
            return cve_ids
        threshold = datetime.utcnow() - timedelta(days=self.epss_refresh_days)
        needed = []
        for cve_id in cve_ids:
            record = snapshot.get(cve_id)
            if not record:
                needed.append(cve_id)
                continue
            updated_at = record.get("updated_at")
            if not updated_at or updated_at <= threshold:
                needed.append(cve_id)
        return needed

    def _upsert_epss_records(self, epss_records):
        for cve_id, record in epss_records.items():
            self.cursor.execute(
                """
                INSERT INTO cve_epss (cve_id, epss_score, epss_percentile, score_date)
                VALUES (%s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    epss_score = VALUES(epss_score),
                    epss_percentile = VALUES(epss_percentile),
                    score_date = VALUES(score_date),
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    cve_id,
                    record.get("epss_score"),
                    record.get("epss_percentile"),
                    record.get("score_date"),
                ),
            )

    def _upsert_epss_records_with_retry(self, epss_records):
        for attempt in range(1, self.max_retries + 1):
            try:
                self.conn.ping(reconnect=True)
                self._upsert_epss_records(epss_records)
                self.conn.commit()
                return
            except Exception as err:
                self._safe_rollback()
                retryable = self._is_retryable_db_error(err)
                if retryable and attempt < self.max_retries:
                    self.log(
                        "WARNING",
                        f"EPSS upsert reconnect attempt {attempt}/{self.max_retries} after error: {err}",
                    )
                    self._reconnect()
                    time.sleep(self.retry_delay_sec * attempt)
                    continue
                raise

    def refresh_epss_scores(self, cve_ids):
        normalized = sorted({(cve_id or "").strip().upper() for cve_id in cve_ids if cve_id})
        if not normalized:
            self._emit_epss_progress(0, 0, "No CVEs to refresh")
            return

        targets = self._cves_needing_epss_refresh(normalized)
        if not targets:
            self.log("INFO", "EPSS refresh skipped: all parsed CVEs are up-to-date")
            self._emit_epss_progress(len(normalized), len(normalized), "EPSS already up-to-date")
            return

        self.log(
            "INFO",
            f"EPSS refresh started for {len(targets)} CVEs (parsed={len(normalized)}, refresh_days={self.epss_refresh_days})",
        )
        self._emit_epss_progress(0, len(targets), "Starting EPSS refresh")

        updated = 0
        for chunk in self._chunked(targets, self.epss_batch_size):
            records = self._fetch_epss_for_batch(chunk)
            missing = [cve_id for cve_id in chunk if cve_id not in records]

            if self._epss_api_online:
                for cve_id in missing:
                    single = self._fetch_epss_for_single(cve_id)
                    if single is not None:
                        records[cve_id] = single
                    else:
                        # Persist null row to avoid hammering API on every run.
                        records[cve_id] = {
                            "epss_score": None,
                            "epss_percentile": None,
                            "score_date": None,
                        }
            else:
                for cve_id in missing:
                    records[cve_id] = {
                        "epss_score": None,
                        "epss_percentile": None,
                        "score_date": None,
                    }

            if records:
                self._upsert_epss_records_with_retry(records)
                updated += len(records)
                self._emit_epss_progress(updated, len(targets), f"EPSS refreshed {updated}/{len(targets)}")

            if updated and updated % 1000 == 0:
                self.log("INFO", f"EPSS upsert progress: {updated}/{len(targets)}")

        self._emit_epss_progress(len(targets), len(targets), "EPSS refresh completed")
        self.log("SUCCESS", f"EPSS refresh completed. updated={updated}, targets={len(targets)}")

    # =========================
    # Upsert queries
    # =========================
    def insert_cve_vulnerabilities(self, cve):
        self.cursor.execute(
            """
            INSERT INTO cve_vulnerabilities (
                cve_id, source_identifier, published, last_modified, vuln_status
            )
            VALUES (%s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                source_identifier = VALUES(source_identifier),
                published = VALUES(published),
                last_modified = VALUES(last_modified),
                vuln_status = VALUES(vuln_status)
            """,
            (
                cve["id"],
                cve.get("sourceIdentifier", ""),
                cve.get("published"),
                cve.get("lastModified"),
                cve.get("vulnStatus", ""),
            ),
        )

    def insert_cve_descriptions(self, cve):
        for desc in cve.get("descriptions", []):
            self.cursor.execute(
                """
                INSERT INTO cve_descriptions (cve_id, description_lang, description_value)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    description_value = VALUES(description_value)
                """,
                (cve["id"], desc.get("lang", ""), desc.get("value", "")),
            )

    def insert_cve_tags(self, cve):
        for tag_entry in cve.get("cveTags", []):
            for tag in tag_entry.get("tags", []):
                self.cursor.execute(
                    """
                    INSERT INTO cve_tags (cve_id, source_identifier, tag)
                    VALUES (%s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        source_identifier = VALUES(source_identifier)
                    """,
                    (cve["id"], tag_entry.get("sourceIdentifier", ""), tag),
                )

    def insert_cvss_metrics(self, cve):
        if "metrics" not in cve:
            return
        for metrics in cve["metrics"].values():
            for metric in metrics:
                cvss = metric.get("cvssData", {})
                self.cursor.execute(
                    """
                    INSERT INTO cvss_metrics (
                        cve_id, version, vector_string, base_score, base_severity,
                        attack_vector, attack_complexity, privileges_required,
                        user_interaction, scope, confidentiality_impact,
                        integrity_impact, availability_impact
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        version = VALUES(version),
                        vector_string = VALUES(vector_string),
                        base_score = VALUES(base_score),
                        base_severity = VALUES(base_severity),
                        attack_vector = VALUES(attack_vector),
                        attack_complexity = VALUES(attack_complexity),
                        privileges_required = VALUES(privileges_required),
                        user_interaction = VALUES(user_interaction),
                        scope = VALUES(scope),
                        confidentiality_impact = VALUES(confidentiality_impact),
                        integrity_impact = VALUES(integrity_impact),
                        availability_impact = VALUES(availability_impact)
                    """,
                    (
                        cve["id"],
                        cvss.get("version", ""),
                        cvss.get("vectorString", ""),
                        cvss.get("baseScore", 0),
                        cvss.get("baseSeverity", ""),
                        cvss.get("attackVector", ""),
                        cvss.get("attackComplexity", ""),
                        cvss.get("privilegesRequired", ""),
                        cvss.get("userInteraction", ""),
                        cvss.get("scope", ""),
                        cvss.get("confidentialityImpact", ""),
                        cvss.get("integrityImpact", ""),
                        cvss.get("availabilityImpact", ""),
                    ),
                )

    def insert_cve_weaknesses(self, cve):
        for weakness in cve.get("weaknesses", []):
            for desc in weakness.get("description", []):
                self.cursor.execute(
                    """
                    INSERT INTO cve_weaknesses (cve_id, source, type, description_lang, description_value)
                    VALUES (%s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        source = VALUES(source),
                        type = VALUES(type),
                        description_value = VALUES(description_value)
                    """,
                    (
                        cve["id"],
                        weakness.get("source", ""),
                        weakness.get("type", ""),
                        desc.get("lang", ""),
                        desc.get("value", ""),
                    ),
                )

    def insert_cve_configurations(self, cve):
        for config in cve.get("configurations", []):
            operator = config.get("operator", "OR")
            for node in config.get("nodes", []):
                cpe_match = node.get("cpeMatch", [])
                self.cursor.execute(
                    """
                    INSERT INTO cve_configurations (cve_id, operator, cpe_match)
                    VALUES (%s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        operator = VALUES(operator),
                        cpe_match = VALUES(cpe_match)
                    """,
                    (cve["id"], operator, json.dumps(cpe_match)),
                )

    def insert_cve_references(self, cve):
        for ref in cve.get("references", []):
            self.cursor.execute(
                """
                INSERT INTO cve_references (cve_id, url, source, tags)
                VALUES (%s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    source = VALUES(source),
                    tags = VALUES(tags)
                """,
                (
                    cve["id"],
                    ref.get("url", ""),
                    ref.get("source", ""),
                    json.dumps(ref.get("tags", [])),
                ),
            )

    def _upsert_single_cve(self, cve):
        self.insert_cve_vulnerabilities(cve)
        self.insert_cve_descriptions(cve)
        self.insert_cve_tags(cve)
        self.insert_cvss_metrics(cve)
        self.insert_cve_weaknesses(cve)
        self.insert_cve_configurations(cve)
        self.insert_cve_references(cve)

    def _upsert_single_cve_with_retry(self, cve):
        cve_id = cve.get("id", "UNKNOWN")
        for attempt in range(1, self.max_retries + 1):
            try:
                self.conn.ping(reconnect=True)
                self._upsert_single_cve(cve)
                self.conn.commit()
                return
            except Exception as err:
                self._safe_rollback()
                retryable = self._is_retryable_db_error(err)
                if retryable and attempt < self.max_retries:
                    self.log(
                        "WARNING",
                        f"{cve_id}: DB reconnect attempt {attempt}/{self.max_retries} after error: {err}",
                    )
                    self._reconnect()
                    time.sleep(self.retry_delay_sec * attempt)
                    continue
                raise

    # =========================
    # Processing
    # =========================
    def process_data(self):
        processed = 0
        processed_cve_ids = set()
        total_cves = 0
        try:
            total_cves = self.count_total_cves_from_year_dirs()
            self._emit_parse_progress(0, max(1, total_cves), f"Starting CVE upsert (total={total_cves})")

            for file_data in self.iter_json_data_from_year_dirs():
                for item in file_data:
                    cve = item.get("cve")
                    if not isinstance(cve, dict) or not cve.get("id"):
                        continue
                    self._upsert_single_cve_with_retry(cve)
                    processed_cve_ids.add(cve["id"])
                    processed += 1
                    if processed % 250 == 0:
                        self._emit_parse_progress(processed, max(1, total_cves), f"CVE upsert {processed}/{total_cves}")
                    if processed % 1000 == 0:
                        self.log("INFO", f"CVE upsert progress: {processed}")

            self._emit_parse_progress(max(processed, total_cves), max(1, total_cves), "CVE upsert completed")

            try:
                self.refresh_epss_scores(processed_cve_ids)
            except Exception as epss_err:
                self.log("ERROR", f"EPSS refresh failed: {epss_err}")

            self.log("SUCCESS", f"CVE data upserted successfully. total={processed}")
        except Exception as err:
            self.log("FAILURE", f"CVE data processing failed after {processed} CVEs: {err}")
            raise

    # =========================
    # Close
    # =========================
    def commit_and_close(self):
        try:
            try:
                self._epss_session.close()
            except Exception:
                pass
            if self.cursor:
                self.cursor.close()
        except Exception:
            pass
        finally:
            try:
                if self.conn:
                    self.conn.close()
            finally:
                self.log("INFO", "Database connection closed.")
