import os, time, json, zipfile, requests, pymysql
from io import BytesIO
from datetime import datetime
from pymysql.cursors import DictCursor

class GitHubPoCCollector:
    def __init__(self, github_token, db_config, base_dir="./poc_sources",
                 request_interval=1, download_interval=2, retry_interval=10, max_retries=3):
        self.github_token = github_token
        self.db_config = db_config
        self.base_dir = base_dir
        self.start_time = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.download_dir = os.path.join(base_dir, self.start_time)
        os.makedirs(self.download_dir, exist_ok=True)
        self.request_interval = request_interval
        self.download_interval = download_interval
        self.retry_interval = retry_interval
        self.max_retries = max_retries

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
    # DB에서 CVE 목록 가져오기
    # =========================
    def get_recent_cves(self):
        try:
            with pymysql.connect(**self.db_config) as conn, conn.cursor(DictCursor) as cur:
                cur.execute("SELECT DISTINCT cve_id FROM cve_vulnerabilities")
                rows = [r["cve_id"] for r in cur.fetchall()]
            self.log("SUCCESS", f"Fetched {len(rows)} CVEs from DB")
            return rows
        except Exception as e:
            self.log("FAILURE", f"Fetch CVEs failed: {e}")
            return []

    def github_rate_limit_wait(self, res):
        if res.status_code == 403 and "X-RateLimit-Reset" in res.headers:
            wait_time = max(int(res.headers["X-RateLimit-Reset"]) - int(time.time()), 0)
            self.log("INFO", f"Rate limit hit, sleeping {wait_time}s")
            time.sleep(wait_time)
            return True
        return False

    def get_latest_commit_sha(self, owner, repo):
        headers = {"Authorization": f"token {self.github_token}"}
        url = f"https://api.github.com/repos/{owner}/{repo}/commits?per_page=1"
        try:
            res = requests.get(url, headers=headers)
            if self.github_rate_limit_wait(res):
                return self.get_latest_commit_sha(owner, repo)
            return res.json()[0]['sha'] if res.status_code == 200 else None
        except:
            return None

    def is_same_commit_sha(self, cve_id, url, sha):
        try:
            with pymysql.connect(**self.db_config) as conn, conn.cursor(DictCursor) as cur:
                cur.execute("""SELECT commit_sha FROM cve_poc_sources
                               WHERE cve_id=%s AND url=%s ORDER BY created_at DESC LIMIT 1""",
                            (cve_id, url))
                row = cur.fetchone()
                return row and row["commit_sha"] == sha
        except:
            return False

    def search_github_repos(self, cve_id):
        headers = {"Authorization": f"token {self.github_token}"}
        url = f"https://api.github.com/search/repositories?q='{cve_id}'"
        for _ in range(self.max_retries):
            res = requests.get(url, headers=headers)
            if self.github_rate_limit_wait(res):
                continue
            if res.status_code == 200:
                items = res.json().get("items", [])
                self.log("SUCCESS", f"{cve_id}: Found {len(items)} repos")
                return items
            time.sleep(self.retry_interval)
        return []

    def download_repo_zip(self, owner, name, dest_dir):
        headers = {"Authorization": f"token {self.github_token}"}
        repo_info_url = f"https://api.github.com/repos/{owner}/{name}"
        for _ in range(self.max_retries):
            info = requests.get(repo_info_url, headers=headers)
            if self.github_rate_limit_wait(info):
                continue
            if info.status_code != 200:
                time.sleep(self.retry_interval)
                continue

            branch = info.json().get("default_branch", "main")
            zip_url = f"https://github.com/{owner}/{name}/archive/refs/heads/{branch}.zip"
            res = requests.get(zip_url)
            if self.github_rate_limit_wait(res):
                continue
            if res.status_code != 200:
                time.sleep(self.retry_interval)
                continue

            repo_dir = os.path.join(dest_dir, f"{owner}__{name}")
            os.makedirs(repo_dir, exist_ok=True)
            zip_path = os.path.join(repo_dir, f"{name}.zip")
            with open(zip_path, "wb") as f:
                f.write(res.content)

            try:
                with zipfile.ZipFile(BytesIO(res.content)) as zf:
                    zf.extractall(repo_dir)
                return [os.path.join(r, f) for r, _, fs in os.walk(repo_dir) for f in fs]
            except:
                return [zip_path]
        return []

    def insert_poc_info(self, cve_id, url, files, sha):
        try:
            with pymysql.connect(**self.db_config) as conn, conn.cursor() as cur:
                cur.execute("""INSERT INTO cve_poc_sources
                               (cve_id, source_identifier, url, downloaded_files, commit_sha)
                               VALUES (%s,%s,%s,%s,%s)""",
                            (cve_id, "GitHub", url, json.dumps(files), sha))
                conn.commit()
        except Exception as e:
            self.log("FAILURE", f"{cve_id} insert_poc_info failed: {e}")

    def process(self):
        cves = self.get_recent_cves()
        self.log("INFO", f"Start processing {len(cves)} CVEs")
        for idx, cve in enumerate(cves, 1):
            self.log("INFO", f"[{idx}/{len(cves)}] Processing {cve}")
            for repo in self.search_github_repos(cve):
                owner, name, url = repo['owner']['login'], repo['name'], repo['html_url']
                sha = self.get_latest_commit_sha(owner, name)
                if not sha or self.is_same_commit_sha(cve, url, sha):
                    continue
                repo_dir = os.path.join(self.download_dir, cve.replace("/", "_"))
                files = self.download_repo_zip(owner, name, repo_dir)
                if files:
                    self.insert_poc_info(cve, url, files, sha)
                    self.log("SUCCESS", f"{cve}: stored PoC {name}")
                time.sleep(self.download_interval)
