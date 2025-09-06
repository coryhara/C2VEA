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
    conn = pymysql.connect(**DB_CONFIG)
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT config_key, config_value FROM app_config")
            rows = cursor.fetchall()
            return {row["config_key"]: row["config_value"] for row in rows}
    finally:
        conn.close()

def run_cve_task():
    config = get_config()
    start_year = int(config.get("START_YEAR"))
    start_month = int(config.get("START_MONTH"))
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

def run_github_task():
    config = get_config()
    token = config.get("GITHUB_TOKEN")
    request_interval = float(config.get("REQUEST_INTERVAL"))
    download_interval = float(config.get("DOWNLOAD_INTERVAL"))
    retry_interval = float(config.get("RETRY_INTERVAL"))
    max_retries = int(config.get("MAX_RETRIES"))

    collector = GitHubPoCCollector(
        token,
        DB_CONFIG,
        request_interval=request_interval,
        download_interval=download_interval,
        retry_interval=retry_interval,
        max_retries=max_retries,
    )
    collector.process()

def run_backup_task():
    backup = DatabaseBackup(DB_CONFIG)
    backup.run_backup()

def run_main():
    print(f"[{datetime.now()}] ▶️ Main task started")
    run_cve_task()
    run_github_task()
    run_backup_task()
    print(f"[{datetime.now()}] ✅ Main task finished")

if __name__ == "__main__":
    # 매일 22:05에 run_main 실행
    schedule.every().day.at("22:05").do(run_main)

    print("✅ Scheduler started. Waiting for tasks...")
    while True:
        schedule.run_pending()
        time.sleep(1)