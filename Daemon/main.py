import os
import threading
import time
from datetime import datetime

import pymysql
import schedule
from dotenv import load_dotenv

from backup import DatabaseBackup
from parser import CVEParser
from processor import CVEProcessor
from progress import JobProgressReporter
from research import GitHubPoCCollector

load_dotenv()

DB_CONFIG = {
    "host": os.getenv("DB_HOST"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "database": os.getenv("DB_NAME"),
    "port": int(os.getenv("DB_PORT")),
    "charset": os.getenv("DB_CHARSET"),
    "cursorclass": pymysql.cursors.DictCursor,
}

cve_job_lock = threading.Lock()
research_job_lock = threading.Lock()
progress_lock = threading.Lock()
progress_reporter = None

JOB_CVE_FETCH = ("cve_fetch", "CVE", "NVD CVE Fetch")
JOB_CVE_PARSE = ("cve_parse", "CVE", "CVE DB Upsert")
JOB_EPSS_REFRESH = ("epss_refresh", "CVE", "EPSS Refresh")
JOB_POC_RESEARCH = ("poc_research", "POC", "GitHub PoC Research")


def log_runtime(status: str, message: str):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {status}: {message}", flush=True)
    conn = None
    try:
        conn = pymysql.connect(**DB_CONFIG)
        with conn.cursor() as cursor:
            cursor.execute(
                "INSERT INTO logs (status, message) VALUES (%s, %s)",
                (status, message),
            )
        conn.commit()
    except Exception:
        pass
    finally:
        if conn:
            conn.close()


def get_config():
    conn = None
    try:
        conn = pymysql.connect(**DB_CONFIG)
        with conn.cursor() as cursor:
            cursor.execute("SELECT config_key, config_value FROM app_config ORDER BY id ASC")
            rows = cursor.fetchall()
            return {row["config_key"]: row["config_value"] for row in rows}
    except pymysql.err.OperationalError as e:
        print(f"[{datetime.now()}] Database not ready: {e}")
        print("Exiting for now. Docker will restart this container...")
        time.sleep(5)
        os._exit(1)
    finally:
        if conn:
            conn.close()


def get_progress_reporter():
    global progress_reporter
    if progress_reporter is not None:
        return progress_reporter
    with progress_lock:
        if progress_reporter is None:
            progress_reporter = JobProgressReporter(DB_CONFIG)
    return progress_reporter


def run_cve_task(config):
    reporter = get_progress_reporter()
    start_year = int(config.get("CVE_START_YEAR"))
    start_month = int(config.get("CVE_START_MONTH"))
    interval = float(config.get("CVE_INTERVAL"))

    processor = CVEProcessor(
        start_year=start_year,
        start_month=start_month,
        db_config=DB_CONFIG,
        interval=interval,
        progress_callback=lambda cur, total, detail: reporter.update(
            JOB_CVE_FETCH[0], JOB_CVE_FETCH[1], JOB_CVE_FETCH[2], cur, total, detail
        ),
    )
    reporter.start(
        JOB_CVE_FETCH[0],
        JOB_CVE_FETCH[1],
        JOB_CVE_FETCH[2],
        total_steps=max(1, processor._total_month_count()),
        detail="Starting NVD monthly fetch",
    )

    reporter.start(JOB_CVE_PARSE[0], JOB_CVE_PARSE[1], JOB_CVE_PARSE[2], detail="Waiting for download stage")
    reporter.start(JOB_EPSS_REFRESH[0], JOB_EPSS_REFRESH[1], JOB_EPSS_REFRESH[2], detail="Waiting for parse stage")

    cve_base_dir = processor.cve_base_dir
    cve_parser = None
    try:
        processor.run()
        reporter.complete(JOB_CVE_FETCH[0], JOB_CVE_FETCH[1], JOB_CVE_FETCH[2], detail="NVD monthly fetch completed")
        cve_parser = CVEParser(
            DB_CONFIG,
            json_base_dir_path=cve_base_dir,
            start_year=start_year,
            parse_progress_callback=lambda cur, total, detail: reporter.update(
                JOB_CVE_PARSE[0], JOB_CVE_PARSE[1], JOB_CVE_PARSE[2], cur, total, detail
            ),
            epss_progress_callback=lambda cur, total, detail: reporter.update(
                JOB_EPSS_REFRESH[0], JOB_EPSS_REFRESH[1], JOB_EPSS_REFRESH[2], cur, total, detail
            ),
        )
        cve_parser.process_data()
        reporter.complete(JOB_CVE_PARSE[0], JOB_CVE_PARSE[1], JOB_CVE_PARSE[2], detail="CVE DB upsert completed")
        reporter.complete(JOB_EPSS_REFRESH[0], JOB_EPSS_REFRESH[1], JOB_EPSS_REFRESH[2], detail="EPSS refresh completed")
    except Exception as err:
        reporter.fail(JOB_CVE_FETCH[0], JOB_CVE_FETCH[1], JOB_CVE_FETCH[2], f"Failed: {err}")
        reporter.fail(JOB_CVE_PARSE[0], JOB_CVE_PARSE[1], JOB_CVE_PARSE[2], f"Failed: {err}")
        reporter.fail(JOB_EPSS_REFRESH[0], JOB_EPSS_REFRESH[1], JOB_EPSS_REFRESH[2], f"Failed: {err}")
        raise
    finally:
        if cve_parser:
            cve_parser.commit_and_close()


def run_github_task(config):
    reporter = get_progress_reporter()
    token = config.get("RESEARCH_GITHUB_TOKEN")
    request_interval = float(config.get("RESEARCH_REQUEST_INTERVAL"))
    download_interval = float(config.get("RESEARCH_DOWNLOAD_INTERVAL"))
    retry_interval = float(config.get("RESEARCH_RETRY_INTERVAL"))
    max_retries = int(config.get("RESEARCH_MAX_RETRIES"))

    collector = GitHubPoCCollector(
        token,
        DB_CONFIG,
        start_year=int(config.get("RESEARCH_START_YEAR")),
        start_month=int(config.get("RESEARCH_START_MONTH")),
        request_interval=request_interval,
        download_interval=download_interval,
        retry_interval=retry_interval,
        max_retries=max_retries,
        max_threads=int(config.get("RESEARCH_MAX_THREADS")),
        research_wait_minutes=int(config.get("RESEARCH_WAIT_MINUTES")),
        rate_limit_threshold=int(config.get("RESEARCH_RATE_LIMIT_THRESHOLD")),
        progress_callback=lambda cur, total, detail: reporter.update(
            JOB_POC_RESEARCH[0], JOB_POC_RESEARCH[1], JOB_POC_RESEARCH[2], cur, total, detail
        ),
    )
    reporter.start(JOB_POC_RESEARCH[0], JOB_POC_RESEARCH[1], JOB_POC_RESEARCH[2], detail="Starting GitHub PoC research")
    try:
        collector.process()
        reporter.complete(JOB_POC_RESEARCH[0], JOB_POC_RESEARCH[1], JOB_POC_RESEARCH[2], detail="GitHub PoC research completed")
    except Exception as err:
        reporter.fail(JOB_POC_RESEARCH[0], JOB_POC_RESEARCH[1], JOB_POC_RESEARCH[2], f"Failed: {err}")
        raise


def _run_cve_job():
    try:
        cfg = get_config()
        log_runtime(
            "INFO",
            f"CVE schedule triggered (every {cfg.get('CVE_INTERVAL_HOURS')}h at :{int(cfg.get('CVE_MINUTE')):02d})",
        )
        run_cve_task(cfg)
        log_runtime("SUCCESS", "CVE schedule finished")
    except Exception as e:
        log_runtime("ERROR", f"CVE schedule failed: {e}")
    finally:
        cve_job_lock.release()


def run_cve_async():
    if not cve_job_lock.acquire(blocking=False):
        log_runtime("INFO", "CVE schedule skipped: previous CVE job still running")
        return
    threading.Thread(target=_run_cve_job, daemon=True).start()


def _run_research_job():
    try:
        cfg = get_config()
        log_runtime("INFO", f"Research schedule triggered at {cfg.get('RESEARCH_SCHEDULE_TIME')}")
        run_github_task(cfg)
        log_runtime("SUCCESS", "Research schedule finished")
    except Exception as e:
        log_runtime("ERROR", f"Research schedule failed: {e}")
    finally:
        research_job_lock.release()


def run_research_async():
    if not research_job_lock.acquire(blocking=False):
        log_runtime("INFO", "Research schedule skipped: previous research job still running")
        return
    threading.Thread(target=_run_research_job, daemon=True).start()


def run_backup_task():
    backup = DatabaseBackup(DB_CONFIG)
    backup.run_backup()


def run_backup():
    if datetime.now().day == 1:
        run_backup_task()


def _apply_schedule(config):
    research_time = str(config.get("RESEARCH_SCHEDULE_TIME"))
    cve_interval = int(config.get("CVE_INTERVAL_HOURS"))
    cve_minute = int(config.get("CVE_MINUTE"))

    schedule.clear()
    schedule.every().day.at(research_time).do(run_research_async)
    schedule.every(cve_interval).hours.at(f":{cve_minute:02d}").do(run_cve_async)
    schedule.every().day.at("00:00").do(run_backup)

    log_runtime(
        "INFO",
        f"Schedule applied: research={research_time}, cve=every {cve_interval}h at :{cve_minute:02d}, backup=00:00",
    )
    return research_time, cve_interval, cve_minute


def update_schedule_if_needed(prev_research_time, prev_cve_interval, prev_cve_minute, config):
    new_research_time = str(config.get("RESEARCH_SCHEDULE_TIME"))
    new_cve_interval = int(config.get("CVE_INTERVAL_HOURS"))
    new_cve_minute = int(config.get("CVE_MINUTE"))

    if (
        new_research_time != prev_research_time
        or new_cve_interval != prev_cve_interval
        or new_cve_minute != prev_cve_minute
    ):
        return _apply_schedule(config)

    return prev_research_time, prev_cve_interval, prev_cve_minute


if __name__ == "__main__":
    config = get_config()
    try:
        get_progress_reporter().reset_running_to_error("Daemon restarted")
    except Exception:
        pass
    current_research_time, current_cve_interval, current_cve_minute = _apply_schedule(config)
    last_reload_minute = None

    while True:
        schedule.run_pending()

        minute_key = datetime.now().strftime("%Y%m%d%H%M")
        if minute_key != last_reload_minute:
            last_reload_minute = minute_key
            new_config = get_config()
            current_research_time, current_cve_interval, current_cve_minute = update_schedule_if_needed(
                current_research_time, current_cve_interval, current_cve_minute, new_config
            )

        time.sleep(1)
