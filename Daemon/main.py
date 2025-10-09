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
            cursor.execute("SELECT config_key, config_value FROM app_config")
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
    start_year = int(config.get("MAIN_START_YEAR"))
    start_month = int(config.get("MAIN_START_MONTH"))
    interval = float(config.get("INTERVAL"))

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
    token = config.get("GITHUB_TOKEN")
    request_interval = float(config.get("REQUEST_INTERVAL"))
    download_interval = float(config.get("DOWNLOAD_INTERVAL"))
    retry_interval = float(config.get("RETRY_INTERVAL"))
    max_retries = int(config.get("MAX_RETRIES"))

    collector = GitHubPoCCollector(
        token,
        DB_CONFIG,
        start_year=int(config.get("RESEARCH_START_YEAR")),
        start_month=int(config.get("RESEARCH_START_MONTH")),
        request_interval=request_interval,
        download_interval=download_interval,
        retry_interval=retry_interval,
        max_retries=max_retries,
    )
    collector.process()

def run_backup_task():
    backup = DatabaseBackup(DB_CONFIG)
    backup.run_backup()

def run_main(config):
    print(f"[{datetime.now()}] ▶️ Main task started")
    run_cve_task(config)
    run_github_task(config)
    run_backup_task()
    print(f"[{datetime.now()}] ✅ Main task finished")

def run_main_async(config):
    thread = threading.Thread(target=run_main, args=(config,))
    thread.start()

def update_schedule_if_needed(prev_time, config):
    """
    DB에서 스케줄 시간을 다시 확인하고 변경되었으면 재등록
    """
    new_time = str(config.get("SCHEDULE_TIME"))

    if new_time != prev_time:
        print(f"[{datetime.now()}] 🕒 Schedule time changed: {prev_time} → {new_time}")

        # 기존 스케줄 모두 초기화
        schedule.clear()

        # 새로운 시간으로 다시 등록
        schedule.every().day.at(new_time).do(run_main, config)
        print(f"[{datetime.now()}] ✅ Scheduler updated to run at {new_time}")

        return new_time
    return prev_time


if __name__ == "__main__":
    config = get_config()
    current_schedule_time = str(config.get("SCHEDULE_TIME"))

    schedule.every().day.at(current_schedule_time).do(run_main_async, config)
    print(f"✅ Scheduler started. Current run time: {current_schedule_time}")

    while True:
        schedule.run_pending()

        # 1분마다 설정 갱신 확인
        if datetime.now().second == 0:
            new_config = get_config()
            current_schedule_time = update_schedule_if_needed(current_schedule_time, new_config)
            config = new_config

        time.sleep(1)
