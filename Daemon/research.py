import os, time, json, re, hashlib, requests, pymysql, threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from pymysql.cursors import DictCursor


class GitHubPoCCollector:
    def __init__(self, github_token, db_config, start_year=1999, start_month=1, base_dir="./poc_sources",
                 request_interval=1, download_interval=2, retry_interval=10, max_retries=3,
                 max_download_size_bytes=500 * 1024 * 1024, max_threads=5,
                 research_wait_minutes=5, rate_limit_threshold=500, progress_callback=None):
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
        self.graphql_url = "https://api.github.com/graphql"
        self.headers = {"Authorization": f"bearer {self.github_token}"}
        self.max_threads = max_threads
        self.research_wait_minutes = research_wait_minutes
        self.rate_limit_threshold = rate_limit_threshold

        # ??Rate limit 愿由ъ슜 怨듭쑀 蹂??
        self.rate_limit_lock = threading.Lock()
        self.remaining = 5000
        self.limit = 5000
        self.reset_at = None
        self.min_confidence_score = 90
        self.max_repo_candidates = 300
        self.readme_cache = {}
        self.poc_keywords = (
            "poc",
            "proof of concept",
            "proof-of-concept",
            "exploit",
            "rce",
            "privilege escalation",
            "cve",
        )
        self.progress_callback = progress_callback

    # =========================
    # Logging
    # =========================
    def log(self, status: str, message: str):
        try:
            conn = pymysql.connect(**self.db_config)
            with conn.cursor() as cursor:
                cursor.execute("INSERT INTO logs (status, message) VALUES (%s, %s)", (status, message))
            conn.commit()
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except:
                pass

    def _emit_progress(self, current_step, total_steps, detail):
        if not callable(self.progress_callback):
            return
        try:
            self.progress_callback(int(current_step), int(total_steps), str(detail))
        except Exception:
            pass

    # =========================
    # Rate Limit ?ъ쟾 ?뺤씤
    # =========================
    def check_rate_limit(self):
        with self.rate_limit_lock:
            if self.remaining is not None and self.remaining < self.rate_limit_threshold:
                msg = (f"Rate limit low: remaining={self.remaining}/{self.limit}, resetAt={self.reset_at}. "
                       f"Waiting {self.research_wait_minutes} minutes before continuing...")
                self.log("INFO", msg)
                print(f"?좑툘 {msg}")
                time.sleep(self.research_wait_minutes * 60)

    # =========================
    # GraphQL ?붿껌
    # =========================
    def graphql_request(self, query, variables=None):
        for attempt in range(1, self.max_retries + 1):
            try:
                res = requests.post(self.graphql_url, headers=self.headers,
                                    json={"query": query, "variables": variables or {}}, timeout=30)
                if res.status_code == 200:
                    data = res.json()
                    rate_limit = data.get("data", {}).get("rateLimit", {})
                    with self.rate_limit_lock:
                        self.remaining = rate_limit.get("remaining", self.remaining)
                        self.limit = rate_limit.get("limit", self.limit)
                        self.reset_at = rate_limit.get("resetAt", self.reset_at)
                    return data
                elif res.status_code == 403 and "rate limit" in res.text.lower():
                    reset_time = int(res.headers.get("X-RateLimit-Reset", time.time() + 60))
                    wait = max(reset_time - int(time.time()), 0)
                    self.log("INFO", f"Rate limit hit, waiting {wait}s before retry")
                    time.sleep(wait + 5)
                    continue
                else:
                    self.log("WARNING", f"GraphQL request failed ({res.status_code}): {res.text[:100]}")
            except Exception as e:
                self.log("ERROR", f"GraphQL request exception: {e}")
                time.sleep(self.retry_interval)
        return None

    # =========================
    # GitHub Repository 寃??(GraphQL)
    # =========================
    def search_github_repos(self, cve_id):
        query = """
        query($q: String!, $cursor: String) {
            search(query: $q, type: REPOSITORY, first: 100, after: $cursor) {
                repositoryCount
                pageInfo {
                    hasNextPage
                    endCursor
                }
                edges {
                    node {
                        ... on Repository {
                            id
                            name
                            nameWithOwner
                            url
                            description
                            updatedAt
                            stargazerCount
                            isArchived
                            isFork
                            primaryLanguage { name }
                            owner { login url }
                            defaultBranchRef {
                                name
                                target { oid }
                            }
                        }
                    }
                }
            }
            rateLimit {
                cost
                remaining
                limit
                resetAt
            }
        }
        """

        repos, cursor = [], None
        while True:
            self.check_rate_limit()
            variables = {"q": f'"{cve_id}" in:name,description,readme archived:false fork:false sort:updated-desc', "cursor": cursor}
            data = self.graphql_request(query, variables)
            if not data or "data" not in data:
                self.log("FAILURE", f"{cve_id}: GraphQL search failed")
                return []

            search_data = data["data"]["search"]
            for edge in search_data.get("edges", []):
                repos.append(edge["node"])
                if len(repos) >= self.max_repo_candidates:
                    break

            if len(repos) >= self.max_repo_candidates:
                break
            if not search_data.get("pageInfo", {}).get("hasNextPage"):
                break
            cursor = search_data["pageInfo"]["endCursor"]
            time.sleep(self.request_interval)

        self.log("SUCCESS", f"{cve_id}: Found {len(repos)} repos")
        return repos

    def _contains_exact_cve(self, text, cve_id):
        if not text:
            return False
        return re.search(rf"\b{re.escape(cve_id)}\b", str(text), flags=re.IGNORECASE) is not None

    def _contains_poc_keyword(self, text):
        if not text:
            return False
        lowered = str(text).lower()
        return any(keyword in lowered for keyword in self.poc_keywords)

    def _fetch_readme_text(self, owner, name):
        cache_key = f"{owner}/{name}".lower()
        if cache_key in self.readme_cache:
            return self.readme_cache[cache_key]

        url = f"https://api.github.com/repos/{owner}/{name}/readme"
        headers = {
            "Authorization": f"token {self.github_token}",
            "Accept": "application/vnd.github.raw",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        text = ""
        for attempt in range(1, self.max_retries + 1):
            try:
                res = requests.get(url, headers=headers, timeout=20)
                if res.status_code == 200:
                    text = res.text or ""
                    break
                if res.status_code in (403, 429):
                    wait = self.retry_interval * attempt
                    time.sleep(wait)
                    continue
                if res.status_code in (404, 451):
                    break
            except Exception:
                time.sleep(self.retry_interval)

        self.readme_cache[cache_key] = text
        return text

    def _score_repo(self, repo, cve_id):
        name = repo.get("name") or ""
        desc = repo.get("description") or ""
        owner = (repo.get("owner") or {}).get("login") or ""

        name_hit = self._contains_exact_cve(name, cve_id)
        desc_hit = self._contains_exact_cve(desc, cve_id)
        meta_keyword_hit = self._contains_poc_keyword(name) or self._contains_poc_keyword(desc)

        readme = ""
        readme_cve_hit = False
        readme_keyword_hit = False

        # README 기반 확인은 정확도 향상을 위해 필요한 경우만 수행
        if (not (name_hit or desc_hit) or not meta_keyword_hit) and owner and name:
            readme = self._fetch_readme_text(owner, name)
            readme_cve_hit = self._contains_exact_cve(readme, cve_id)
            readme_keyword_hit = self._contains_poc_keyword(readme)

        score = 0
        if name_hit:
            score += 70
        if desc_hit:
            score += 35
        if meta_keyword_hit:
            score += 20
        if readme_cve_hit:
            score += 25
        if readme_keyword_hit:
            score += 20

        if repo.get("isFork"):
            score -= 40
        if repo.get("isArchived"):
            score -= 100

        if int(repo.get("stargazerCount") or 0) >= 5:
            score += 5

        has_cve_signal = name_hit or desc_hit or readme_cve_hit
        has_poc_signal = meta_keyword_hit or readme_keyword_hit
        is_high_confidence = (
            score >= self.min_confidence_score
            and has_cve_signal
            and has_poc_signal
            and not repo.get("isFork")
            and not repo.get("isArchived")
        )

        return is_high_confidence, score

    def filter_high_confidence_repos(self, cve_id, repos):
        if not repos:
            return []

        selected = []
        for repo in repos:
            ok, score = self._score_repo(repo, cve_id)
            if not ok:
                continue
            repo["_confidence_score"] = score
            selected.append(repo)

        selected.sort(key=lambda r: r.get("_confidence_score", 0), reverse=True)
        self.log("INFO", f"{cve_id}: {len(selected)}/{len(repos)} repos passed high-confidence filter")
        return selected

    # =========================
    # ZIP ?뚯씪 ?ㅼ슫濡쒕뱶 諛?DB ???
    # =========================
    def download_repo_zip(self, owner, name, branch, dest_dir):
        zip_url = f"https://github.com/{owner}/{name}/archive/refs/heads/{branch}.zip"
        headers = {"Authorization": f"token {self.github_token}"}
        safe_owner = re.sub(r'[^A-Za-z0-9._\-]', '_', owner)
        safe_name = re.sub(r'[^A-Za-z0-9._\-]', '_', name)
        repo_dir = os.path.join(dest_dir, f"{safe_owner}__{safe_name}")
        os.makedirs(repo_dir, exist_ok=True)
        zip_path = os.path.join(repo_dir, f"{safe_name}.zip")

        # ??以묐났 ?뚯씪 寃??(SHA256)
        if os.path.exists(zip_path):
            existing_sha = self._compute_file_sha256(zip_path)
            if self._sha_exists_in_db(existing_sha):
                self.log("INFO", f"Skip existing ZIP (same SHA256): {zip_path}")
                return [zip_path]

        for attempt in range(1, self.max_retries + 1):
            try:
                with requests.get(zip_url, headers=headers, stream=True, timeout=60) as res:
                    if res.status_code != 200:
                        time.sleep(self.retry_interval)
                        continue
                    size = int(res.headers.get("Content-Length", 0))
                    if size > self.max_download_size_bytes:
                        self.log("WARNING", f"{owner}/{name}: ZIP too large ({size})")
                        return []
                    with open(zip_path, "wb") as f:
                        for chunk in res.iter_content(8192):
                            f.write(chunk)
                    return [zip_path]
            except Exception as e:
                self.log("ERROR", f"{owner}/{name}: ZIP download error: {e}")
                time.sleep(self.retry_interval)
        return []

    # =========================
    # 以묐났 寃??愿???좏떥
    # =========================
    def _compute_file_sha256(self, path):
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def _sha_exists_in_db(self, sha256):
        try:
            with pymysql.connect(**self.db_config) as conn, conn.cursor() as cur:
                cur.execute("""
                    SELECT EXISTS (
                        SELECT 1 FROM cve_poc_sources 
                        WHERE JSON_SEARCH(downloaded_files, 'one', %s) IS NOT NULL
                    );
                """, (sha256,))
                return cur.fetchone()[0] == 1
        except Exception as e:
            self.log("ERROR", f"SHA exists check failed: {e}")
            return False

    def already_downloaded(self, cve_id, url, sha):
        for attempt in range(1, self.max_retries + 1):
            conn = None
            try:
                conn = pymysql.connect(**self.db_config)
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT EXISTS(
                            SELECT 1 FROM cve_poc_sources
                            WHERE cve_id=%s AND url=%s AND commit_sha=%s
                        );
                    """, (cve_id, url, sha))
                    result = cur.fetchone()
                    if isinstance(result, (list, tuple)):
                        return result[0] == 1
                    if isinstance(result, dict):
                        return list(result.values())[0] == 1
                    return False
            except Exception as e:
                retryable = isinstance(e, pymysql.err.OperationalError) or "server has gone away" in str(e).lower()
                if retryable and attempt < self.max_retries:
                    time.sleep(self.retry_interval)
                    continue
                self.log("ERROR", f"already_downloaded failed for {cve_id}: {e}")
                break
            finally:
                try:
                    if conn:
                        conn.close()
                except:
                    pass

        self.log("ERROR", f"already_downloaded failed permanently after {self.max_retries} retries for {cve_id}")
        return False

    # =========================
    # DB Insert
    # =========================
    def insert_poc_info(self, cve_id, url, files, sha):
        try:
            with pymysql.connect(**self.db_config) as conn, conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO cve_poc_sources
                    (cve_id, source_identifier, url, downloaded_files, commit_sha)
                    VALUES (%s,%s,%s,%s,%s)
                    ON DUPLICATE KEY UPDATE
                    downloaded_files=VALUES(downloaded_files),
                    commit_sha=VALUES(commit_sha)
                """, (cve_id, "GitHub", url, json.dumps(files), sha))
                conn.commit()
        except Exception as e:
            self.log("FAILURE", f"{cve_id} insert_poc_info failed: {e}")

    # =========================
    # CVE ?⑥씪 泥섎━ (Thread)
    # =========================
    def process_single_cve(self, cve):
        try:
            repos = self.search_github_repos(cve)
            if not repos:
                return
            repos = self.filter_high_confidence_repos(cve, repos)
            if not repos:
                self.log("INFO", f"{cve}: No high-confidence PoC repositories found")
                return

            for repo in repos:
                owner = repo["owner"]["login"]
                name = repo["name"]
                url = repo["url"]
                branch = repo["defaultBranchRef"]["name"] if repo["defaultBranchRef"] else "main"
                sha = repo["defaultBranchRef"]["target"]["oid"] if repo["defaultBranchRef"] else None
                if not sha:
                    continue

                # ??DB???숈씪 PoC媛 議댁옱?섎뒗吏 癒쇱? ?뺤씤
                if self.already_downloaded(cve, url, sha):
                    self.log("INFO", f"{cve}: Already stored {owner}/{name} ({sha[:10]}...) - skipped")
                    continue

                cve_dir = os.path.join(self.download_dir, cve.replace("/", "_"))
                files = self.download_repo_zip(owner, name, branch, cve_dir)
                if not files:
                    continue

                files_meta = []
                for path in files:
                    sha256 = self._compute_file_sha256(path)
                    files_meta.append({
                        "path": path,
                        "sha256": sha256,
                        "size": os.path.getsize(path)
                    })

                self.insert_poc_info(cve, url, files_meta, sha)
                self.log("SUCCESS", f"{cve}: Stored {owner}/{name}")
                time.sleep(self.download_interval)
        except Exception as e:
            self.log("ERROR", f"{cve}: Thread processing error: {e}")

    # =========================
    # 硫붿씤 ?ㅽ뻾 (ThreadPoolExecutor)
    # =========================
    def get_recent_cves(self):
        try:
            with pymysql.connect(**self.db_config) as conn, conn.cursor(DictCursor) as cur:
                cur.execute("""
                    SELECT DISTINCT cve_id 
                    FROM cve_vulnerabilities 
                    WHERE published >= %s;
                """, (f"{self.start_year}-{self.start_month:02d}-01",))
                rows = [r["cve_id"] for r in cur.fetchall()]
            self.log("SUCCESS", f"Fetched {len(rows)} CVEs from DB")
            return rows
        except Exception as e:
            self.log("FAILURE", f"Fetch CVEs failed: {e}")
            return []

    def process(self):
        cves = self.get_recent_cves()
        self.log("INFO", f"Start processing {len(cves)} CVEs using {self.max_threads} threads")
        total = len(cves)
        completed = 0
        self._emit_progress(0, max(1, total), f"Starting PoC research for {total} CVEs")

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self.process_single_cve, cve): cve for cve in cves}
            for future in as_completed(futures):
                cve = futures[future]
                try:
                    future.result()
                except Exception as e:
                    self.log("ERROR", f"{cve}: Future crashed with {e}")
                finally:
                    completed += 1
                    if completed % 10 == 0 or completed == total:
                        self._emit_progress(completed, max(1, total), f"PoC research {completed}/{total}")

        self._emit_progress(max(1, total), max(1, total), "PoC research completed")

