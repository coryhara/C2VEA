from fastapi import FastAPI
import os
from dotenv import load_dotenv
from research import GitHubPoCCollector
from parser import CVEParser
from processor import CVEProcessor
from backup import DatabaseBackup
import pymysql
import threading

load_dotenv()

app = FastAPI()
run_lock = threading.Lock()

# 환경 변수
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

DB_CONFIG = {
    'host': os.getenv("DB_HOST"),
    'user': os.getenv("DB_USER"),
    'password': os.getenv("DB_PASSWORD"),
    'database': os.getenv("DB_NAME"),
    'port': int(os.getenv("DB_PORT")),
    'charset': os.getenv("DB_CHARSET"),
    'cursorclass': pymysql.cursors.DictCursor
}

start_year = int(os.getenv("START_YEAR"))
start_month = int(os.getenv("START_MONTH"))
request_interval = float(os.getenv("REQUEST_INTERVAL"))
download_interval = float(os.getenv("DOWNLOAD_INTERVAL"))
retry_interval = float(os.getenv("RETRY_INTERVAL"))
max_retries = int(os.getenv("MAX_RETRIES"))

def is_busy():
    if not run_lock.acquire(blocking=False):
        return True
    return False

def release_lock():
    if run_lock.locked():
        run_lock.release()

# ✅ 메인 실행
@app.get("/run-main")
def run_main():
    if is_busy():
        return {
            "status": "error",
            "message": "Another user's request is currently being processed. Please try again later."
        }

    try:
        run_cve_internal()
        run_github_internal()
        run_backup_internal()
        return {"status": "success", "message": "Main process completed"}
    except Exception as e:
        return {"status": "error", "message": f"An error occurred: {str(e)}"}
    finally:
        release_lock()

# ✅ CVE 처리
@app.get("/run-cve")
def run_cve():
    if is_busy():
        return {
            "status": "error",
            "message": "Another user's request is currently being processed. Please try again later."
        }

    try:
        run_cve_internal()
        return {"status": "success", "message": "CVE processing completed"}
    except Exception as e:
        return {"status": "error", "message": f"CVE processing failed: {e}"}
    finally:
        release_lock()

# ✅ GitHub 수집
@app.get("/run-github")
def run_github():
    if is_busy():
        return {
            "status": "error",
            "message": "Another user's request is currently being processed. Please try again later."
        }

    try:
        run_github_internal()
        return {"status": "success", "message": "GitHub PoC collection completed"}
    except Exception as e:
        return {"status": "error", "message": f"GitHub PoC collection failed: {e}"}
    finally:
        release_lock()

# ✅ DB 백업
@app.get("/run-backup")
def run_backup():
    if is_busy():
        return {
            "status": "error",
            "message": "Another user's request is currently being processed. Please try again later."
        }

    try:
        run_backup_internal()
        return {"status": "success", "message": "Database backup completed"}
    except Exception as e:
        return {"status": "error", "message": f"Database backup failed: {e}"}
    finally:
        release_lock()

# 내부 실행 함수들
def run_cve_internal():
    cve_processor = CVEProcessor(start_year=start_year, start_month=start_month, db_config=DB_CONFIG)
    cve_base_dir = cve_processor.get_cve_base_dir()
    cve_parser = CVEParser(DB_CONFIG, json_base_dir_path=cve_base_dir, start_year=start_year)

    cve_processor.run()
    cve_parser.process_data()
    cve_parser.commit_and_close()

def run_github_internal():
    cve_collector = GitHubPoCCollector(
        GITHUB_TOKEN, DB_CONFIG,
        request_interval=request_interval,
        download_interval=download_interval,
        retry_interval=retry_interval,
        max_retries=max_retries
    )
    cve_collector.process()

def run_backup_internal():
    db_backup = DatabaseBackup(DB_CONFIG)
    db_backup.run_backup()
