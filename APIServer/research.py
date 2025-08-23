import os
import time
import json
import zipfile
import requests
import pymysql
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
        self._stop = False

    def _get_conn(self):
        return pymysql.connect(**self.db_config)

    def stop(self):
        """외부에서 실행 중단 요청"""
        self._stop = True
        self.log_to_db("INFO", "GitHubPoCCollector stop flag set.")

    def log_to_db(self, status, message):
        try:
            with self._get_conn() as conn, conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO logs (status, message)
                    VALUES (%s, %s)
                """, (status, message))
                conn.commit()
        except Exception as e:
            print(f"[Log Write Failed] {status}: {e}")

    def get_recent_cves(self):
        if self._stop:
            return []
        try:
            with self._get_conn() as conn, conn.cursor(DictCursor) as cursor:
                cursor.execute("SELECT DISTINCT cve_id FROM cve_vulnerabilities")
                results = [row["cve_id"] for row in cursor.fetchall()]
            self.log_to_db("SUCCESS", f"Fetched {len(results)} recent CVEs from DB.")
            return results
        except Exception as e:
            self.log_to_db("FAILURE", f"Failed to fetch recent CVEs: {e}")
            return []

    def github_rate_limit_wait(self, response):
        if response.status_code == 403 and "X-RateLimit-Reset" in response.headers:
            reset = int(response.headers["X-RateLimit-Reset"])
            wait_time = max(reset - int(time.time()), 0)
            self.log_to_db("INFO", f"Rate limit hit. Sleeping {wait_time}s.")
            for _ in range(wait_time + 1):
                if self._stop:   # ✅ 대기 중에도 중단 가능
                    return True
                time.sleep(1)
            return True
        return False

    def get_latest_commit_sha(self, owner, repo):
        if self._stop:
            return None
        headers = {"Authorization": f"token {self.github_token}"}
        url = f"https://api.github.com/repos/{owner}/{repo}/commits?per_page=1"

        try:
            res = requests.get(url, headers=headers)
            if self.github_rate_limit_wait(res):
                return self.get_latest_commit_sha(owner, repo)

            if res.status_code == 200:
                sha = res.json()[0]['sha']
                return sha
            else:
                self.log_to_db("FAILURE", f"Failed to fetch commit SHA for {owner}/{repo}")
                return None
        except Exception as e:
            self.log_to_db("FAILURE", f"Error fetching SHA for {owner}/{repo}: {e}")
            return None

    def is_same_commit_sha(self, cve_id, url, sha):
        if self._stop:
            return False
        try:
            with self._get_conn() as conn, conn.cursor(DictCursor) as cursor:
                cursor.execute("""
                    SELECT commit_sha FROM cve_poc_sources
                    WHERE cve_id = %s AND url = %s 
                    ORDER BY created_at DESC LIMIT 1;
                """, (cve_id, url))
                row = cursor.fetchone()
                if row is None:
                    return False
                return row['commit_sha'] == sha
        except Exception as e:
            self.log_to_db("FAILURE", f"SHA compare failed: {e}")
            return False

    def search_github_repos(self, cve_id):
        if self._stop:
            return []
        headers = {"Authorization": f"token {self.github_token}"}
        url = f"https://api.github.com/search/repositories?q='{cve_id}'"
        retries = 0

        while retries < self.max_retries:
            if self._stop:   # ✅ 중간에 끊기
                return []
            try:
                res = requests.get(url, headers=headers)
                if self.github_rate_limit_wait(res):
                    continue

                time.sleep(self.request_interval)
                if self._stop:
                    return []

                if res.status_code == 200:
                    repos = res.json().get("items", [])
                    self.log_to_db("SUCCESS", f"{cve_id}: Found {len(repos)} repos.")
                    return repos
                else:
                    self.log_to_db("FAILURE", f"{cve_id} search failed: {res.status_code}")
                    retries += 1
                    time.sleep(self.retry_interval)
            except Exception as e:
                self.log_to_db("FAILURE", f"{cve_id} search exception: {e}")
                retries += 1
                time.sleep(self.retry_interval)
        return []

    def download_repo_zip(self, owner, name, dest_dir):
        if self._stop:
            return []
        headers = {"Authorization": f"token {self.github_token}"}
        repo_info_url = f"https://api.github.com/repos/{owner}/{name}"
        retries = 0

        while retries < self.max_retries:
            if self._stop:
                return []
            try:
                repo_info = requests.get(repo_info_url, headers=headers)
                if self.github_rate_limit_wait(repo_info):
                    continue

                time.sleep(self.request_interval)
                if self._stop:
                    return []

                if repo_info.status_code != 200:
                    self.log_to_db("FAILURE", f"{owner}/{name} repo info failed.")
                    retries += 1
                    time.sleep(self.retry_interval)
                    continue

                default_branch = repo_info.json().get("default_branch", "main")
                zip_url = f"https://github.com/{owner}/{name}/archive/refs/heads/{default_branch}.zip"
                res = requests.get(zip_url)

                if self.github_rate_limit_wait(res):
                    continue

                time.sleep(self.request_interval)
                if self._stop:
                    return []

                if res.status_code != 200:
                    self.log_to_db("FAILURE", f"{owner}/{name} zip download failed.")
                    retries += 1
                    time.sleep(self.retry_interval)
                    continue

                repo_dir = os.path.join(dest_dir, f"{owner}__{name}")
                os.makedirs(repo_dir, exist_ok=True)

                zip_path = os.path.join(repo_dir, f"{name}.zip")
                with open(zip_path, 'wb') as f:
                    f.write(res.content)

                try:
                    with zipfile.ZipFile(BytesIO(res.content)) as zip_ref:
                        zip_ref.extractall(repo_dir)

                    file_paths = []
                    for root, _, files in os.walk(repo_dir):
                        if self._stop:
                            return []
                        for file in files:
                            file_paths.append(os.path.join(root, file))

                    return file_paths
                except Exception as extract_err:
                    self.log_to_db("WARNING", f"{owner}/{name} - zip extraction failed, storing zip only: {extract_err}")
                    return [zip_path]

            except Exception as e:
                self.log_to_db("FAILURE", f"{owner}/{name} download exception: {e}")
                retries += 1
                time.sleep(self.retry_interval)
        return []

    def insert_poc_info(self, cve_id, url, file_paths, sha):
        if self._stop:
            return
        try:
            with self._get_conn() as conn, conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO cve_poc_sources (cve_id, source_identifier, url, downloaded_files, commit_sha)
                    VALUES (%s, %s, %s, %s, %s)
                """, (cve_id, "GitHub", url, json.dumps(file_paths), sha))
                conn.commit()
        except Exception as e:
            self.log_to_db("FAILURE", f"{cve_id} - insert_poc_info failed: {e}")

    def process(self):
        cve_list = self.get_recent_cves()
        total = len(cve_list)
        self.log_to_db("INFO", f"Start processing {total} CVEs.")

        for idx, cve_id in enumerate(cve_list, 1):
            if self._stop:   # ✅ 중간에 정지
                self.log_to_db("INFO", "Process stopped before completion.")
                break

            try:
                percent = round((idx / total) * 100, 5)
                self.log_to_db("INFO", f"[{idx}/{total}] ({percent}%) Processing {cve_id}")

                repos = self.search_github_repos(cve_id)
                if not repos:
                    self.log_to_db("FAILURE", f"{cve_id} - no repos found.")
                    continue

                for repo in repos:
                    if self._stop:   # ✅ repo 단위에서도 체크
                        self.log_to_db("INFO", "Stopping during repo loop.")
                        break

                    owner = repo['owner']['login']
                    name = repo['name']
                    html_url = repo['html_url']

                    latest_sha = self.get_latest_commit_sha(owner, name)
                    if not latest_sha:
                        continue
                    
                    if self.is_same_commit_sha(cve_id, html_url, latest_sha):
                        self.log_to_db("INFO", f"{cve_id} - no change for {html_url} (SHA: {latest_sha})")
                        continue

                    repo_dir = os.path.join(self.download_dir, cve_id.replace("/", "_"))
                    file_paths = self.download_repo_zip(owner, name, repo_dir)

                    if self._stop:
                        break

                    if file_paths:
                        self.insert_poc_info(cve_id, html_url, file_paths, latest_sha)
                        self.log_to_db("SUCCESS", f"{cve_id} - new/updated PoC for {name}")
                    else:
                        self.log_to_db("FAILURE", f"{cve_id} - no files from {name}")

                    time.sleep(self.download_interval)

            except Exception as e:
                self.log_to_db("FAILURE", f"{cve_id} - general error: {e}")
