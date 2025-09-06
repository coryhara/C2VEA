import os
import subprocess
from datetime import datetime
import pymysql


class DatabaseBackup:
    def __init__(self, db_config: dict, backup_dir: str = "backups", dump_path: str = "mariadb-dump"):
        self.db_config = db_config
        self.db_host = db_config.get("host")
        self.db_port = db_config.get("port")
        self.db_user = db_config.get("user")
        self.db_password = db_config.get("password")
        self.db_name = db_config.get("database")
        self.backup_dir = backup_dir
        self.dump_path = dump_path

        if not all([self.db_user, self.db_password, self.db_name]):
            raise ValueError("DB_CONFIG must contain 'user', 'password', and 'database'.")

        os.makedirs(self.backup_dir, exist_ok=True)

    # =========================
    # 로깅 (통일된 방식)
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
    # 백업 파일 이름 생성
    # =========================
    def generate_backup_filename(self):
        date = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        return os.path.join(self.backup_dir, f"backup-{date}.sql")

    # =========================
    # 백업 실행
    # =========================
    def run_backup(self):
        backup_file = self.generate_backup_filename()
        command = [
            self.dump_path,
            "-h", self.db_host,
            "-P", str(self.db_port),
            "-u", self.db_user,
            f"-p{self.db_password}",
            self.db_name
        ]

        try:
            with open(backup_file, "w", encoding="utf-8") as f:
                subprocess.run(command, stdout=f, stderr=subprocess.PIPE, check=True)
            self.log("SUCCESS", f"Backup completed: {backup_file}")
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.decode("utf-8").strip()
            error_file = os.path.join(self.backup_dir, "last_error.log")
            with open(error_file, "w", encoding="utf-8") as ef:
                ef.write(error_msg)
            self.log("FAILURE", f"Backup failed. See {error_file} for details.")
        except Exception as e:
            self.log("ERROR", f"Unexpected error occurred: {str(e)}")
