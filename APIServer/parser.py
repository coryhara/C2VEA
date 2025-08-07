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

    def delete_all_data(self):
        tables = [
            'cve_vulnerabilities', 'cve_descriptions', 'cve_tags',
            'cvss_metrics', 'cve_weaknesses', 'cve_configurations', 'cve_references'
        ]
        self.cursor.execute('SET FOREIGN_KEY_CHECKS = 0')
        for table in tables:
            self.cursor.execute(f'TRUNCATE TABLE {table}')
            print(f"⚠️ Truncated table '{table}'")
        self.cursor.execute('SET FOREIGN_KEY_CHECKS = 1')
        print("✅ All tables cleared.")

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

    def insert_cve_vulnerabilities(self, cve):
        cve_id = cve['id']
        source_identifier = cve.get('sourceIdentifier', '')
        published = cve.get('published')
        last_modified = cve.get('lastModified')
        vuln_status = cve.get('vulnStatus', '')
        self.cursor.execute('''
            INSERT IGNORE INTO cve_vulnerabilities (cve_id, source_identifier, published, last_modified, vuln_status)
            VALUES (%s, %s, %s, %s, %s)
        ''', (cve_id, source_identifier, published, last_modified, vuln_status))

    def insert_cve_descriptions(self, cve):
        cve_id = cve['id']
        for desc in cve.get('descriptions', []):
            lang = desc.get('lang', '')
            value = desc.get('value', '')
            self.cursor.execute('''
                INSERT INTO cve_descriptions (cve_id, description_lang, description_value)
                VALUES (%s, %s, %s)
            ''', (cve_id, lang, value))

    def insert_cve_tags(self, cve):
        cve_id = cve['id']
        for tag_entry in cve.get('cveTags', []):
            source_identifier = tag_entry.get('sourceIdentifier', '')
            for tag in tag_entry.get('tags', []):
                self.cursor.execute('''
                    INSERT INTO cve_tags (cve_id, source_identifier, tag)
                    VALUES (%s, %s, %s)
                ''', (cve_id, source_identifier, tag))

    def insert_cvss_metrics(self, cve):
        cve_id = cve['id']
        if 'metrics' in cve:
            for key, metrics in cve['metrics'].items():
                for metric in metrics:
                    cvss_data = metric.get('cvssData', {})
                    self.cursor.execute('''
                        INSERT INTO cvss_metrics (
                            cve_id, version, vector_string, base_score, base_severity,
                            attack_vector, attack_complexity, privileges_required, user_interaction, scope,
                            confidentiality_impact, integrity_impact, availability_impact
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ''', (
                        cve_id,
                        cvss_data.get('version', ''),
                        cvss_data.get('vectorString', ''),
                        cvss_data.get('baseScore', 0),
                        cvss_data.get('baseSeverity', ''),
                        cvss_data.get('attackVector', ''),
                        cvss_data.get('attackComplexity', ''),
                        cvss_data.get('privilegesRequired', ''),
                        cvss_data.get('userInteraction', ''),
                        cvss_data.get('scope', ''),
                        cvss_data.get('confidentialityImpact', ''),
                        cvss_data.get('integrityImpact', ''),
                        cvss_data.get('availabilityImpact', '')
                    ))

    def insert_cve_weaknesses(self, cve):
        cve_id = cve['id']
        for weakness in cve.get('weaknesses', []):
            source = weakness.get('source', '')
            w_type = weakness.get('type', '')
            for desc in weakness.get('description', []):
                lang = desc.get('lang', '')
                value = desc.get('value', '')
                self.cursor.execute('''
                    INSERT INTO cve_weaknesses (cve_id, source, type, description_lang, description_value)
                    VALUES (%s, %s, %s, %s, %s)
                ''', (cve_id, source, w_type, lang, value))

    def insert_cve_configurations(self, cve):
        cve_id = cve['id']
        for config in cve.get('configurations', []):
            operator = config.get('operator', 'OR') == 'OR'
            for node in config.get('nodes', []):
                cpe_match = node.get('cpeMatch', [])
                self.cursor.execute('''
                    INSERT INTO cve_configurations (cve_id, operator, cpe_match)
                    VALUES (%s, %s, %s)
                ''', (cve_id, operator, json.dumps(cpe_match)))

    def insert_cve_references(self, cve):
        cve_id = cve['id']
        for ref in cve.get('references', []):
            url = ref.get('url', '')
            source = ref.get('source', '')
            tags = ref.get('tags', [])
            self.cursor.execute('''
                INSERT INTO cve_references (cve_id, url, source, tags)
                VALUES (%s, %s, %s, %s)
            ''', (cve_id, url, source, json.dumps(tags)))

    def process_data(self):
        print("🔒 Starting data deletion and reload process...")
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
        print("✅ Data processing complete.")

    def commit_and_close(self):
        self.conn.commit()
        self.cursor.close()
        self.conn.close()
        print("💾 Database commit and connection closed.")
