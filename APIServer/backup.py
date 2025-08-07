import os
import subprocess
from datetime import datetime
import pymysql


class DatabaseBackup:
    def __init__(self, db_config: dict, backup_dir: str = "backups", dump_path: str = "mariadb-dump"):
        self.db_host = db_config.get("host", "127.0.0.1")
        self.db_port = db_config.get("port", 3306)
        self.db_user = db_config.get("user")
        self.db_password = db_config.get("password")
        self.db_name = db_config.get("database")
        self.backup_dir = backup_dir
        self.dump_path = dump_path

        if not all([self.db_user, self.db_password, self.db_name]):
            raise ValueError("❌ DB_CONFIG must contain 'user', 'password', and 'database'.")

        os.makedirs(self.backup_dir, exist_ok=True)

    def log(self, status: str, message: str):
        """Insert a log entry into the logs table."""
        try:
            conn = pymysql.connect(
                host=self.db_host,
                port=self.db_port,
                user=self.db_user,
                password=self.db_password,
                database=self.db_name,
                charset="utf8mb4"
            )
            with conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO logs (status, message) VALUES (%s, %s)",
                    (status, message)
                )
            conn.commit()
        except Exception as e:
            print(f"❌ Failed to log to database: {e}")
        finally:
            conn.close()

    def generate_backup_filename(self):
        date = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        return os.path.join(self.backup_dir, f"backup-{date}.sql")

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
            msg = f"✅ Backup completed successfully: {backup_file}"
            print(msg)
            self.log("SUCCESS", msg)
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.decode("utf-8").strip()
            full_msg = f"❌ Backup failed: {error_msg}"
            print(full_msg)
            self.log("FAILURE", full_msg)
        except Exception as e:
            full_msg = f"⚠️ Unexpected error occurred: {str(e)}"
            print(full_msg)
            self.log("ERROR", full_msg)
