import requests, os, json, time, pymysql
from datetime import datetime, timedelta

class CVEProcessor:
    def __init__(self, start_year, start_month, db_config, interval, cve_dir="./cve"):
        self.start_year, self.start_month, self.db_config, self.interval = start_year, start_month, db_config, interval
        self.timestamp_dir = datetime.now().strftime("%Y%m%d%H%M%S")
        self.cve_base_dir = os.path.join(cve_dir, self.timestamp_dir)
        os.makedirs(self.cve_base_dir, exist_ok=True)

        now = datetime.now()
        self.end_year, self.end_month = now.year, now.month
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0/"

        self._stop = False

    # =========================
    # 로깅
    # =========================
    def log(self, status: str, message: str):
        try:
            conn = pymysql.connect(**self.db_config)
            with conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO logs (status, message) VALUES (%s, %s)",
                    (status, message)
                )
            conn.commit()
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except:
                pass

    # =========================
    # CVE 요청
    # =========================
    def request_cve(self, year, month):
        start_date = datetime(year, month, 1)
        end_date = datetime(year + (month // 12), (month % 12) + 1, 1)
        pub_start = start_date.strftime("%Y-%m-%dT00:00:00.000Z")
        pub_end = (end_date - timedelta(milliseconds=1)).strftime("%Y-%m-%dT23:59:59.999Z")

        all_vulns, start_index = [], 0
        while not self._stop:
            params = {"pubStartDate": pub_start, "pubEndDate": pub_end, "resultsPerPage": 2000, "startIndex": start_index}
            resp = requests.get(self.base_url, params=params)
            if resp.status_code != 200: 
                return resp, None

            vulns = resp.json().get("vulnerabilities", [])
            all_vulns.extend(vulns)
            if len(vulns) < 2000: 
                break
            start_index += 2000
            time.sleep(self.interval)
        return resp, all_vulns

    # =========================
    # CVE 저장
    # =========================
    def save_cves(self, year, month, vulns):
        year_dir = os.path.join(self.cve_base_dir, str(year))
        os.makedirs(year_dir, exist_ok=True)

        for i in range(0, len(vulns), 2000):
            if self._stop: 
                break
            file_path = os.path.join(year_dir, f"{year}-{month:02d}-{(i//2000)+1:02d}_cves.json")
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(vulns[i:i+2000], f, ensure_ascii=False, indent=2)

    # =========================
    # 처리 & 재시도
    # =========================
    def process_cves(self):
        fail_list, y, m = [], self.start_year, self.start_month
        while (y < self.end_year) or (y == self.end_year and m <= self.end_month):
            if self._stop: break
            self.log("INFO", f"Processing {y}-{m:02d}")
            resp, vulns = self.request_cve(y, m)
            time.sleep(self.interval)

            if not resp or resp.status_code != 200 or vulns is None:
                self.log("ERROR", f"Failed {y}-{m:02d} ({resp.status_code if resp else 'None'})")
                fail_list.append((y, m))
            else:
                self.save_cves(y, m, vulns)
                self.log("SUCCESS", f"{y}-{m:02d} done ({len(vulns)} CVEs)")

            y, m = (y+1, 1) if m == 12 else (y, m+1)
        return fail_list

    def retry_failed_requests(self, fail_list):
        while fail_list and not self._stop:
            y, m = fail_list[0]
            self.log("INFO", f"Retrying {y}-{m:02d}")
            resp, vulns = self.request_cve(y, m)
            if resp and resp.status_code == 200 and vulns:
                self.save_cves(y, m, vulns)
                self.log("SUCCESS", f"Retry success {y}-{m:02d}")
                fail_list.pop(0)
                time.sleep(self.interval)
            else:
                self.log("ERROR", f"Retry failed {y}-{m:02d} ({resp.status_code if resp else 'None'})")
                time.sleep(self.interval * 5)

    # =========================
    # 실행
    # =========================
    def run(self):
        self.log("INFO", "Start CVE processing")
        fails = self.process_cves()
        if not self._stop and fails: 
            self.log("INFO", "Retrying failed months")
            self.retry_failed_requests(fails)
        elif not self._stop:
            self.log("INFO", "All requests succeeded")
        self.log("INFO", "CVEProcessor finished")
