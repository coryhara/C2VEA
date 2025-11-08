import pymysql
import os
import schedule
import time
from datetime import datetime
from research import GitHubPoCCollector
from parser import CVEParser
from processor import CVEProcessor
from backup import DatabaseBackup
from dotenv import load_dotenv
import threading

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

def get_config():
    try:
        conn = pymysql.connect(**DB_CONFIG)
        with conn.cursor() as cursor:
            cursor.execute("SELECT config_key, config_value FROM app_config ORDER BY id ASC")
            rows = cursor.fetchall()
            return {row["config_key"]: row["config_value"] for row in rows}
    except pymysql.err.OperationalError as e:
        print(f"[{datetime.now()}] ❌ Database not ready: {e}")
        print("⏳ Exiting for now. Docker will restart this container...")
        time.sleep(5)
        os._exit(1)
    finally:
        if 'conn' in locals() and conn:
            conn.close()

def run_cve_task(config):
    start_year = int(config.get("CVE_START_YEAR"))
    start_month = int(config.get("CVE_START_MONTH"))
    interval = float(config.get("CVE_INTERVAL"))

    processor = CVEProcessor(
        start_year=start_year,
        start_month=start_month,
        db_config=DB_CONFIG,
        interval=interval
    )
    cve_base_dir = processor.cve_base_dir
    cve_parser = CVEParser(DB_CONFIG, json_base_dir_path=cve_base_dir, start_year=start_year)

    processor.run()
    cve_parser.process_data()
    cve_parser.commit_and_close()

def run_github_task(config):
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
        rate_limit_threshold=int(config.get("RATE_LIMIT_THRESHOLD")),
    )
    collector.process()

def run_backup_task(config):
    backup = DatabaseBackup(config)
    backup.run_backup()

def run_backup(config):
    today = datetime.date.today()
    if today.day == 1:
        run_backup_task(config)

def run_cve(config):
    run_cve_task(config)

def run_research(config):
    run_github_task(config)
    run_backup_task()

def run_research_async(config):
    thread = threading.Thread(target=run_research, args=(config,))
    thread.start()

def update_schedule_if_needed(prev_research_time, prev_cve_interval, prev_cve_minute, config):
    new_research_time = str(config.get("RESEARCH_SCHEDULE_TIME"))
    new_cve_interval = int(config.get("CVE_INTERVAL_HOURS"))
    new_cve_minute = int(config.get("CVE_MINUTE"))

    if (new_research_time != prev_research_time or
        new_cve_interval != prev_cve_interval or
        new_cve_minute != prev_cve_minute):
        schedule.clear()
        schedule.every().day.at(new_research_time).do(run_research_async, config)
        schedule.every(new_cve_interval).hours.at(f":{new_cve_minute:02d}").do(run_cve, config)

        return new_research_time, new_cve_interval, new_cve_minute

    return prev_research_time, prev_cve_interval, prev_cve_minute


if __name__ == "__main__":
    config = get_config()

    current_research_time = str(config.get("RESEARCH_SCHEDULE_TIME"))
    current_cve_interval = int(config.get("CVE_INTERVAL_HOURS"))
    current_cve_minute = int(config.get("CVE_MINUTE"))

    schedule.every().day.at(current_research_time).do(run_research_async, config)
    schedule.every(current_cve_interval).hours.at(f":{current_cve_minute:02d}").do(run_cve, config)
    schedule.every().day.at("00:00").do(run_backup)

    while True:
        schedule.run_pending()

        if datetime.now().second == 0:
            new_config = get_config()
            current_research_time, current_cve_interval, current_cve_minute = update_schedule_if_needed(
                current_research_time, current_cve_interval, current_cve_minute, new_config
            )
            config = new_config

        time.sleep(1)
