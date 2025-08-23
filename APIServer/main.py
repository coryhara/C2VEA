from fastapi import FastAPI
import os
import threading
import pymysql
from dotenv import load_dotenv
from research import GitHubPoCCollector
from parser import CVEParser
from processor import CVEProcessor
from backup import DatabaseBackup

load_dotenv()

app = FastAPI()
run_lock = threading.Lock()

# 현재 실행 중인 객체
current_processor = None
current_collector = None
current_backup = None
stop_all = False   # ✅ 전체 중단 플래그

# DB 설정
DB_CONFIG = {
    "host": os.getenv("DB_HOST"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "database": os.getenv("DB_NAME"),
    "port": int(os.getenv("DB_PORT")),
    "charset": os.getenv("DB_CHARSET"),
    "cursorclass": pymysql.cursors.DictCursor,
}

# 환경 변수
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
start_year = int(os.getenv("START_YEAR"))
start_month = int(os.getenv("START_MONTH"))
request_interval = float(os.getenv("REQUEST_INTERVAL"))
download_interval = float(os.getenv("DOWNLOAD_INTERVAL"))
retry_interval = float(os.getenv("RETRY_INTERVAL"))
max_retries = int(os.getenv("MAX_RETRIES"))

# =========================
# 상태 확인
# =========================
@app.get("/status")
def get_status():
    running = []
    if current_processor and not current_processor._stop:
        running.append("CVE")
    if current_collector and not current_collector._stop:
        running.append("GitHub")
    if current_backup and not current_backup._stop:
        running.append("Backup")

    return {"status": "running" if running else "idle", "running": running}

# =========================
# STOP
# =========================
@app.get("/stop")
def stop_process():
    global current_processor, current_collector, current_backup, stop_all
    stop_all = True   # ✅ 앞으로 실행될 작업도 전부 스킵
    stopped = []
    if current_processor:
        current_processor.stop()
        stopped.append("CVE")
    if current_collector:
        current_collector.stop()
        stopped.append("GitHub")
    if current_backup:
        current_backup.stop()
        stopped.append("Backup")

    return {
        "status": "success" if stopped else "error",
        "message": f"Stopped: {', '.join(stopped) if stopped else 'None'}"
    }

# =========================
# 작업 실행 함수들
# =========================
def run_cve_task():
    global current_processor, stop_all
    if stop_all:  # ✅ stop 눌렸으면 시작 안 함
        return
    current_processor = CVEProcessor(start_year=start_year, start_month=start_month, db_config=DB_CONFIG)
    try:
        cve_base_dir = current_processor.get_cve_base_dir()
        cve_parser = CVEParser(DB_CONFIG, json_base_dir_path=cve_base_dir, start_year=start_year)

        current_processor.run()
        if not current_processor._stop and not stop_all:
            cve_parser.process_data()
            cve_parser.commit_and_close()
    finally:
        current_processor = None
        release_lock()

def run_github_task():
    global current_collector, stop_all
    if stop_all:
        return
    current_collector = GitHubPoCCollector(
        GITHUB_TOKEN,
        DB_CONFIG,
        request_interval=request_interval,
        download_interval=download_interval,
        retry_interval=retry_interval,
        max_retries=max_retries,
    )
    try:
        if not stop_all:
            current_collector.process()
    finally:
        current_collector = None
        release_lock()

def run_backup_task():
    global current_backup, stop_all
    if stop_all:
        return
    current_backup = DatabaseBackup(DB_CONFIG)
    try:
        if not stop_all:
            current_backup.run_backup()
    finally:
        current_backup = None
        release_lock()

# =========================
# API 엔드포인트
# =========================
def is_busy():
    return not run_lock.acquire(blocking=False)

def release_lock():
    if run_lock.locked():
        run_lock.release()

@app.get("/run-cve")
def run_cve():
    global stop_all
    stop_all = False  # ✅ 실행 전 초기화
    if is_busy():
        return {"status": "error", "message": "Another process is running."}

    def task():
        try:
            run_cve_task()
        finally:
            release_lock()

    threading.Thread(target=task, daemon=True).start()
    return {"status": "started", "message": "CVE task started"}

@app.get("/run-github")
def run_github():
    global stop_all
    stop_all = False
    if is_busy():
        return {"status": "error", "message": "Another process is running."}

    def task():
        try:
            run_github_task()
        finally:
            release_lock()

    threading.Thread(target=task, daemon=True).start()
    return {"status": "started", "message": "GitHub task started"}

@app.get("/run-backup")
def run_backup():
    global stop_all
    stop_all = False
    if is_busy():
        return {"status": "error", "message": "Another process is running."}

    def task():
        try:
            run_backup_task()
        finally:
            release_lock()

    threading.Thread(target=task, daemon=True).start()
    return {"status": "started", "message": "Backup task started"}

@app.get("/run-main")
def run_main():
    global stop_all
    stop_all = False  # ✅ 새 실행 시작 시 초기화

    if is_busy():
        return {"status": "error", "message": "Another process is running."}

    def task():
        try:
            run_cve_task()
            run_github_task()
            run_backup_task()
        finally:
            release_lock()

    threading.Thread(target=task, daemon=True).start()
    return {"status": "started", "message": "Main (All) tasks started"}
