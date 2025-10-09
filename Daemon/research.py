import os, time, json, zipfile, requests, pymysql, re, hashlib
from io import BytesIO
from datetime import datetime
from pymysql.cursors import DictCursor

class GitHubPoCCollector:
    def __init__(self, github_token, db_config, start_year=1999, start_month=1, base_dir="./poc_sources",
                 request_interval=1, download_interval=2, retry_interval=10, max_retries=3,
                 max_download_size_bytes=500 * 1024 * 1024):
        self.github_token = github_token
        self.db_config = db_config
        self.start_year = start_year
        self.start_month = start_month
        self.base_dir = base_dir
        self.start_time = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.download_dir = os.path.join(base_dir, self.start_time)
        os.makedirs(self.download_dir, exist_ok=True)
        self.request_interval = request_interval
        self.download_interval = download_interval
        self.retry_interval = retry_interval
        self.max_retries = max_retries
        self.max_download_size_bytes = max_download_size_bytes

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
    # CVE 목록 불러오기
    # =========================
    def get_recent_cves(self):
        try:
            with pymysql.connect(**self.db_config) as conn, conn.cursor(DictCursor) as cur:
                cur.execute(f"""
                    SELECT DISTINCT cve_id 
                    FROM cve_vulnerabilities 
                    WHERE published >= '{self.start_year}-{self.start_month:02d}-01';
                """)
                rows = [r["cve_id"] for r in cur.fetchall()]
            self.log("SUCCESS", f"Fetched {len(rows)} CVEs from DB")
            return rows
        except Exception as e:
            self.log("FAILURE", f"Fetch CVEs failed: {e}")
            return []

    # =========================
    # Rate Limit 관리
    # =========================
    def github_rate_limit_wait(self, res):
        if res is None:
            return False
        if res.status_code == 403 and "X-RateLimit-Reset" in res.headers:
            wait_time = max(int(res.headers["X-RateLimit-Reset"]) - int(time.time()), 0)
            self.log("INFO", f"Rate limit hit, sleeping {wait_time}s")
            time.sleep(wait_time + 5)
            return True
        return False

    # =========================
    # Repo 최신 커밋 SHA 가져오기
    # =========================
    def get_latest_commit_sha(self, owner, repo):
        headers = {"Authorization": f"token {self.github_token}"}
        url = f"https://api.github.com/repos/{owner}/{repo}/commits?per_page=1"
        try:
            res = requests.get(url, headers=headers, timeout=15)
            if self.github_rate_limit_wait(res):
                return self.get_latest_commit_sha(owner, repo)
            return res.json()[0]['sha'] if res.status_code == 200 else None
        except Exception:
            return None

    # =========================
    # DB 중복 확인
    # =========================
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

    # =========================
    # ZIP 다운로드
    # =========================
    def download_repo_zip(self, owner, name, dest_dir):
        headers = {"Authorization": f"token {self.github_token}"}
        repo_info_url = f"https://api.github.com/repos/{owner}/{name}"

        for attempt in range(1, self.max_retries + 1):
            try:
                info = requests.get(repo_info_url, headers=headers, timeout=15)
            except Exception as e:
                self.log("WARNING", f"{owner}/{name}: repo info request exception (attempt {attempt}): {e}")
                time.sleep(self.retry_interval)
                continue

            if self.github_rate_limit_wait(info):
                continue

            if info.status_code != 200:
                self.log("WARNING", f"{owner}/{name}: repo info fetch failed (status {info.status_code})")
                time.sleep(self.retry_interval)
                continue

            branch = info.json().get("default_branch", "main")
            zip_url = f"https://github.com/{owner}/{name}/archive/refs/heads/{branch}.zip"

            try:
                with requests.get(zip_url, headers=headers, stream=True, timeout=60) as res:
                    if self.github_rate_limit_wait(res):
                        continue

                    if res.status_code != 200:
                        self.log("WARNING", f"{owner}/{name}: zip download failed ({res.status_code})")
                        time.sleep(self.retry_interval)
                        continue

                    # 용량 제한 확인
                    content_length = res.headers.get("Content-Length")
                    if content_length:
                        try:
                            content_length = int(content_length)
                            if content_length > self.max_download_size_bytes:
                                self.log("WARNING", f"{owner}/{name}: zip too large ({content_length} bytes), skipping")
                                return []
                        except ValueError:
                            pass

                    safe_owner = self._sanitize_name(owner)
                    safe_name = self._sanitize_name(name)
                    repo_dir = os.path.join(dest_dir, f"{safe_owner}__{safe_name}")
                    os.makedirs(repo_dir, exist_ok=True)
                    zip_path = os.path.join(repo_dir, f"{safe_name}.zip")

                    total_written = 0
                    with open(zip_path, "wb") as f:
                        for chunk in res.iter_content(chunk_size=8192):
                            if not chunk:
                                continue
                            total_written += len(chunk)
                            if total_written > self.max_download_size_bytes:
                                f.close()
                                os.remove(zip_path)
                                self.log("WARNING", f"{owner}/{name}: download exceeded max size, aborted")
                                return []
                            f.write(chunk)

                    self.log("INFO", f"{owner}/{name}: zip downloaded ({total_written} bytes)")
                    return [zip_path]
            except Exception as e:
                self.log("FAILURE", f"{owner}/{name}: download exception (attempt {attempt}): {e}")
                time.sleep(self.retry_interval)
                continue

        return []

    # =========================
    # 파일 해시 계산
    # =========================
    def _compute_file_sha256(self, path: str) -> str:
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ""

    # =========================
    # 안전한 이름 처리
    # =========================
    def _sanitize_name(self, name: str) -> str:
        return re.sub(r'[^A-Za-z0-9._\-]', '_', name)

    # =========================
    # DB에 PoC 정보 삽입
    # =========================
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

    # =========================
    # GitHub 검색 API (RateLimit-safe)
    # =========================
    def search_github_repos(self, cve_id):
        headers = {"Authorization": f"token {self.github_token}"}
        url = f"https://api.github.com/search/repositories?q='{cve_id}'"

        for attempt in range(1, self.max_retries + 1):
            try:
                res = requests.get(url, headers=headers, timeout=15)
            except Exception as e:
                self.log("WARNING", f"{cve_id}: search request exception (attempt {attempt}): {e}")
                time.sleep(self.retry_interval)
                continue

            if self.github_rate_limit_wait(res):
                self.log("INFO", f"{cve_id}: Retrying after rate limit (attempt {attempt})")
                time.sleep(self.retry_interval)
                continue

            if res.status_code == 200:
                try:
                    items = res.json().get("items", [])
                except Exception as e:
                    self.log("WARNING", f"{cve_id}: JSON decode failed: {e}")
                    time.sleep(self.retry_interval)
                    continue

                self.log("SUCCESS", f"{cve_id}: Found {len(items)} repos")
                return items

            elif res.status_code == 403 and "rate limit" in res.text.lower():
                self.github_rate_limit_wait(res)
                self.log("INFO", f"{cve_id}: Retrying after rate limit (attempt {attempt})")
                continue

            else:
                self.log("WARNING", f"{cve_id}: search failed ({res.status_code})")
                time.sleep(self.retry_interval)
                continue

        self.log("FAILURE", f"{cve_id}: search failed after {self.max_retries} retries")
        return []

    # =========================
    # 메인 처리
    # =========================
    def process(self):
        cves = self.get_recent_cves()
        self.log("INFO", f"Start processing {len(cves)} CVEs")
        for idx, cve in enumerate(cves, 1):
            self.log("INFO", f"[{idx}/{len(cves)}] Processing {cve}")

            repos = self.search_github_repos(cve)
            if not repos:
                continue

            for repo in repos:
                try:
                    owner = repo['owner']['login']
                    name = repo['name']
                    url = repo['html_url']
                    sha = self.get_latest_commit_sha(owner, name)
                    if not sha:
                        self.log("WARNING", f"{cve}: Cannot fetch commit sha for {owner}/{name}, skipping")
                        continue

                    if self.is_same_commit_sha(cve, url, sha):
                        self.log("INFO", f"{cve}: {owner}/{name} already recorded (same commit), skipping")
                        continue

                    safe_owner = self._sanitize_name(owner)
                    safe_name = self._sanitize_name(name)
                    repo_dir = os.path.join(self.download_dir, cve.replace("/", "_"), f"{safe_owner}__{safe_name}")
                    zip_path = os.path.join(repo_dir, f"{safe_name}.zip")

                    if os.path.exists(zip_path):
                        self.log("INFO", f"{cve}: Local ZIP already exists ({zip_path}), re-downloading to update")
                        try:
                            os.remove(zip_path)
                        except Exception as e:
                            self.log("WARNING", f"{cve}: Failed to remove old ZIP: {e}")

                    files_paths = self.download_repo_zip(owner, name, os.path.join(self.download_dir, cve.replace("/", "_")))
                    if not files_paths:
                        self.log("WARNING", f"{cve}: No ZIP downloaded for {owner}/{name}")
                        continue

                    files_meta = []
                    for p in files_paths:
                        try:
                            size = os.path.getsize(p)
                            sha256 = self._compute_file_sha256(p)
                            files_meta.append({"path": p, "sha256": sha256, "size": size})
                        except Exception as e:
                            self.log("WARNING", f"{cve}: Could not hash/stat file {p}: {e}")
                            files_meta.append({"path": p, "sha256": "", "size": None})

                    self.insert_poc_info(cve, url, files_meta, sha)
                    self.log("SUCCESS", f"{cve}: stored PoC {owner}/{name}")
                    time.sleep(self.download_interval)

                except Exception as e:
                    self.log("ERROR", f"{cve}: Error processing repo {repo.get('html_url', 'unknown')}: {e}")
                    continue
