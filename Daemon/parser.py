import pymysql
import json
import os
from datetime import datetime

class CVEParser:
    def __init__(self, db_config, json_base_dir_path, start_year):
        self.conn = pymysql.connect(**db_config)
        self.cursor = self.conn.cursor()
        self.json_base_dir_path = json_base_dir_path
        self.start_year = start_year
        self.db_config = db_config

    # =========================
    # 로깅 기능
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
    # 데이터 초기화
    # =========================
    def delete_all_data(self):
        tables = [
            'cve_vulnerabilities', 'cve_descriptions', 'cve_tags',
            'cvss_metrics', 'cve_weaknesses', 'cve_configurations', 'cve_references'
        ]
        self.cursor.execute('SET FOREIGN_KEY_CHECKS = 0')
        for table in tables:
            self.cursor.execute(f'TRUNCATE TABLE {table}')
        self.cursor.execute('SET FOREIGN_KEY_CHECKS = 1')
        self.log("INFO", "All CVE-related tables truncated.")

    # =========================
    # JSON 로드
    # =========================
    def load_json_data_from_year_dirs(self):
        data = []
        current_year = datetime.now().year
        for year in range(self.start_year, current_year + 1):
            year_dir_path = os.path.join(self.json_base_dir_path, str(year))
            if os.path.isdir(year_dir_path):
                for filename in os.listdir(year_dir_path):
                    if filename.endswith('.json'):
                        file_path = os.path.join(year_dir_path, filename)
                        with open(file_path, 'r', encoding='utf-8') as f:
                            file_data = json.load(f)
                            data.append(file_data)
        return data

    # =========================
    # 데이터 삽입 메서드들
    # =========================
    def insert_cve_vulnerabilities(self, cve):
        self.cursor.execute('''
            INSERT IGNORE INTO cve_vulnerabilities 
            (cve_id, source_identifier, published, last_modified, vuln_status)
            VALUES (%s, %s, %s, %s, %s)
        ''', (
            cve['id'],
            cve.get('sourceIdentifier', ''),
            cve.get('published'),
            cve.get('lastModified'),
            cve.get('vulnStatus', '')
        ))

    def insert_cve_descriptions(self, cve):
        for desc in cve.get('descriptions', []):
            self.cursor.execute('''
                INSERT INTO cve_descriptions (cve_id, description_lang, description_value)
                VALUES (%s, %s, %s)
            ''', (cve['id'], desc.get('lang', ''), desc.get('value', '')))

    def insert_cve_tags(self, cve):
        for tag_entry in cve.get('cveTags', []):
            for tag in tag_entry.get('tags', []):
                self.cursor.execute('''
                    INSERT INTO cve_tags (cve_id, source_identifier, tag)
                    VALUES (%s, %s, %s)
                ''', (cve['id'], tag_entry.get('sourceIdentifier', ''), tag))

    def insert_cvss_metrics(self, cve):
        if 'metrics' in cve:
            for metrics in cve['metrics'].values():
                for metric in metrics:
                    cvss = metric.get('cvssData', {})
                    self.cursor.execute('''
                        INSERT INTO cvss_metrics (
                            cve_id, version, vector_string, base_score, base_severity,
                            attack_vector, attack_complexity, privileges_required, 
                            user_interaction, scope, confidentiality_impact, 
                            integrity_impact, availability_impact
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ''', (
                        cve['id'],
                        cvss.get('version', ''),
                        cvss.get('vectorString', ''),
                        cvss.get('baseScore', 0),
                        cvss.get('baseSeverity', ''),
                        cvss.get('attackVector', ''),
                        cvss.get('attackComplexity', ''),
                        cvss.get('privilegesRequired', ''),
                        cvss.get('userInteraction', ''),
                        cvss.get('scope', ''),
                        cvss.get('confidentialityImpact', ''),
                        cvss.get('integrityImpact', ''),
                        cvss.get('availabilityImpact', '')
                    ))

    def insert_cve_weaknesses(self, cve):
        for weakness in cve.get('weaknesses', []):
            for desc in weakness.get('description', []):
                self.cursor.execute('''
                    INSERT INTO cve_weaknesses (cve_id, source, type, description_lang, description_value)
                    VALUES (%s, %s, %s, %s, %s)
                ''', (
                    cve['id'],
                    weakness.get('source', ''),
                    weakness.get('type', ''),
                    desc.get('lang', ''),
                    desc.get('value', '')
                ))

    def insert_cve_configurations(self, cve):
        for config in cve.get('configurations', []):
            operator = config.get('operator', 'OR') == 'OR'
            for node in config.get('nodes', []):
                cpe_match = node.get('cpeMatch', [])
                self.cursor.execute('''
                    INSERT INTO cve_configurations (cve_id, operator, cpe_match)
                    VALUES (%s, %s, %s)
                ''', (cve['id'], operator, json.dumps(cpe_match)))

    def insert_cve_references(self, cve):
        for ref in cve.get('references', []):
            self.cursor.execute('''
                INSERT INTO cve_references (cve_id, url, source, tags)
                VALUES (%s, %s, %s, %s)
            ''', (
                cve['id'],
                ref.get('url', ''),
                ref.get('source', ''),
                json.dumps(ref.get('tags', []))
            ))

    # =========================
    # 데이터 처리
    # =========================
    def process_data(self):
        try:
            self.delete_all_data()
            data = self.load_json_data_from_year_dirs()
            for file_data in data:
                for item in file_data:
                    cve = item['cve']
                    self.insert_cve_vulnerabilities(cve)
                    self.insert_cve_descriptions(cve)
                    self.insert_cve_tags(cve)
                    self.insert_cvss_metrics(cve)
                    self.insert_cve_weaknesses(cve)
                    self.insert_cve_configurations(cve)
                    self.insert_cve_references(cve)
            self.log("SUCCESS", "CVE data processed successfully.")
        except Exception as e:
            self.log("FAILURE", f"CVE data processing failed: {str(e)}")

    # =========================
    # 커밋 및 종료
    # =========================
    def commit_and_close(self):
        try:
            self.conn.commit()
            self.log("INFO", "Database commit complete.")
        except Exception as e:
            self.log("ERROR", f"Commit failed: {str(e)}")
        finally:
            try:
                self.cursor.close()
                self.conn.close()
                self.log("INFO", "Database connection closed.")
            except Exception:
                pass
