import os, time, json, zipfile, requests, pymysql
from io import BytesIO
from datetime import datetime
from pymysql.cursors import DictCursor
import re

class GitHubPoCCollector:
    def __init__(self, github_token, db_config, base_dir="./poc_sources",
                 request_interval=1, download_interval=2, retry_interval=10, max_retries=3,
                 max_download_size_bytes=500 * 1024 * 1024):  # 기본 500MB 제한 (필요시 조정)
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
        if res is None:
            return False
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
            res = requests.get(url, headers=headers, timeout=15)
            if self.github_rate_limit_wait(res):
                return self.get_latest_commit_sha(owner, repo)
            return res.json()[0]['sha'] if res.status_code == 200 else None
        except Exception:
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
            try:
                res = requests.get(url, headers=headers, timeout=15)
            except Exception as e:
                self.log("WARNING", f"{cve_id}: search request exception: {e}")
                time.sleep(self.retry_interval)
                continue
            if self.github_rate_limit_wait(res):
                continue
            if res.status_code == 200:
                items = res.json().get("items", [])
                self.log("SUCCESS", f"{cve_id}: Found {len(items)} repos")
                return items
            self.log("WARNING", f"{cve_id}: search failed ({res.status_code})")
            time.sleep(self.retry_interval)
        return []

    # 안전한 파일/디렉터리 이름 생성
    def _sanitize_name(self, name: str) -> str:
        return re.sub(r'[^A-Za-z0-9._\-]', '_', name)

    # =========================
    # ZIP 전용 다운로드 (압축 해제하지 않음)
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

            # 스트리밍으로 zip만 다운로드
            try:
                with requests.get(zip_url, headers=headers, stream=True, timeout=60) as res:
                    if self.github_rate_limit_wait(res):
                        # rate-limit 발생하면 재시도 루프로
                        continue

                    # 컨텐트 타입 혹은 URL 기반으로 zip 여부 확인
                    content_type = res.headers.get("Content-Type", "").lower()
                    if "zip" not in content_type and not zip_url.lower().endswith(".zip"):
                        self.log("WARNING", f"{owner}/{name}: content-type not zip ({content_type}), skipping")
                        return []

                    if res.status_code != 200:
                        self.log("WARNING", f"{owner}/{name}: zip download failed ({res.status_code})")
                        time.sleep(self.retry_interval)
                        continue

                    # 용량 제한 확인 (Content-Length 헤더가 있을 경우)
                    content_length = res.headers.get("Content-Length")
                    if content_length:
                        try:
                            content_length = int(content_length)
                            if content_length > self.max_download_size_bytes:
                                self.log("WARNING", f"{owner}/{name}: zip too large ({content_length} bytes), skipping")
                                return []
                        except ValueError:
                            pass  # 파싱 실패 시 무시

                    safe_owner = self._sanitize_name(owner)
                    safe_name = self._sanitize_name(name)
                    repo_dir = os.path.join(dest_dir, f"{safe_owner}__{safe_name}")
                    os.makedirs(repo_dir, exist_ok=True)
                    zip_path = os.path.join(repo_dir, f"{safe_name}.zip")

                    total_written = 0
                    chunk_size = 8192
                    with open(zip_path, "wb") as f:
                        for chunk in res.iter_content(chunk_size=chunk_size):
                            if not chunk:
                                continue
                            total_written += len(chunk)
                            if total_written > self.max_download_size_bytes:
                                f.close()
                                try:
                                    os.remove(zip_path)
                                except:
                                    pass
                                self.log("WARNING", f"{owner}/{name}: download exceeded max size, aborted")
                                return []
                            f.write(chunk)

                    self.log("INFO", f"{owner}/{name}: zip downloaded to {zip_path} ({total_written} bytes)")
                    # 압축 해제 하지 않음 — zip 파일만 저장하여 반환
                    return [zip_path]
            except Exception as e:
                self.log("FAILURE", f"{owner}/{name}: download exception (attempt {attempt}): {e}")
                time.sleep(self.retry_interval)
                continue

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
