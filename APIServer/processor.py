import requests
import os
import json
from datetime import datetime, timedelta
import time
import pymysql
from dotenv import load_dotenv

load_dotenv()

class CVEProcessor:
    def __init__(self, start_year, start_month, db_config, cve_dir="./cve"):
        self.start_year = start_year
        self.start_month = start_month
        self.cve_dir = cve_dir
        self.db_config = db_config

        self.timestamp_dir = datetime.now().strftime("%Y%m%d%H%M%S")
        self.cve_base_dir = os.path.join(self.cve_dir, self.timestamp_dir)
        os.makedirs(self.cve_base_dir, exist_ok=True)

        now = datetime.now()
        self.end_year = now.year
        self.end_month = now.month

        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0/"

        self.conn = None
        self.cursor = None

        self.interval = float(os.getenv("INTERVAL", 2.0))

        # ✅ stop flag
        self._stop = False

    def stop(self):
        """외부에서 실행 중단 요청"""
        self._stop = True
        self.log_to_db("INFO", "CVEProcessor stopped by user request.")

    def get_cve_base_dir(self):
        return self.cve_base_dir

    def open_db(self):
        self.conn = pymysql.connect(**self.db_config)
        self.cursor = self.conn.cursor()

    def close_db(self):
        if self.conn:
            self.conn.close()

    def log_to_db(self, status, message):
        log_time = datetime.now()
        insert_sql = "INSERT INTO logs (status, message, log_time) VALUES (%s, %s, %s)"
        self.cursor.execute(insert_sql, (status, message, log_time))
        self.conn.commit()

    def request_cve(self, year, month):
        start_date = datetime(year, month, 1)
        if month == 12:
            end_date = datetime(year + 1, 1, 1)
        else:
            end_date = datetime(year, month + 1, 1)

        pub_start = start_date.strftime("%Y-%m-%dT00:00:00.000Z")
        pub_end = (end_date - timedelta(milliseconds=1)).strftime("%Y-%m-%dT23:59:59.999Z")

        start_index = 0
        all_vulnerabilities = []

        while True:
            if self._stop:  # ✅ stop check
                self.log_to_db("INFO", "Stopped during request loop.")
                break

            params = {
                "pubStartDate": pub_start,
                "pubEndDate": pub_end,
                "resultsPerPage": 2000,
                "startIndex": start_index
            }

            response = requests.get(self.base_url, params=params)
            if response.status_code != 200:
                return response, None

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            all_vulnerabilities.extend(vulnerabilities)

            if len(vulnerabilities) < 2000:
                break
            start_index += 2000
            time.sleep(self.interval)

        return response, all_vulnerabilities

    def save_cves(self, year, month, vulnerabilities):
        year_dir = os.path.join(self.cve_base_dir, str(year))
        os.makedirs(year_dir, exist_ok=True)

        chunk_size = 2000
        for i in range(0, len(vulnerabilities), chunk_size):
            if self._stop:  # ✅ stop check
                self.log_to_db("INFO", "Stopped during save_cves.")
                break

            chunk = vulnerabilities[i:i + chunk_size]
            chunk_num = (i // chunk_size) + 1
            file_name = f"{year}-{month:02d}-{chunk_num:02d}_cves.json"
            file_path = os.path.join(year_dir, file_name)

            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(chunk, f, ensure_ascii=False, indent=2)

    def process_cves(self):
        fail_list = []
        year = self.start_year
        month = self.start_month

        while (year < self.end_year) or (year == self.end_year and month <= self.end_month):
            if self._stop:  # ✅ stop check
                self.log_to_db("INFO", "Processing stopped by user request.")
                break

            self.log_to_db("INFO", f"Processing {year}-{month:02d}...")
            response, vulnerabilities = self.request_cve(year, month)
            time.sleep(self.interval)

            if response is None or response.status_code != 200 or vulnerabilities is None:
                self.log_to_db("ERROR", f"Error {response.status_code if response else 'None'} for {year}-{month:02d}")
                fail_list.append((year, month))
            else:
                self.save_cves(year, month, vulnerabilities)
                self.log_to_db("INFO", f"Successfully processed {year}-{month:02d} ({len(vulnerabilities)} CVEs)")

            if month == 12:
                year += 1
                month = 1
            else:
                month += 1

        return fail_list

    def retry_failed_requests(self, fail_list):
        while fail_list:
            if self._stop:  # ✅ stop check
                self.log_to_db("INFO", "Retry loop stopped by user request.")
                break

            year, month = fail_list[0]
            self.log_to_db("INFO", f"Retrying {year}-{month:02d}...")
            response, vulnerabilities = self.request_cve(year, month)

            if response and response.status_code == 200 and vulnerabilities:
                self.log_to_db("INFO", f"Success: {year}-{month:02d}")
                self.save_cves(year, month, vulnerabilities)
                fail_list.pop(0)
                time.sleep(self.interval)
            else:
                self.log_to_db("ERROR", f"Still failed: {year}-{month:02d} (status {response.status_code if response else 'None'})")
                time.sleep(self.interval * 5)

    def run(self):
        self.open_db()
        self.log_to_db("INFO", "Starting CVE processing...")
        fail_list = self.process_cves()
        if not self._stop and fail_list:
            self.log_to_db("INFO", "Starting retries...")
            self.retry_failed_requests(fail_list)
        elif not self._stop:
            self.log_to_db("INFO", "All requests succeeded!")
        self.log_to_db("INFO", "Program finished.")
        self.close_db()
