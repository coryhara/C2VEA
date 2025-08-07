CREATE TABLE IF NOT EXISTS  cve_vulnerabilities (
    cve_id VARCHAR(50) PRIMARY KEY,
    source_identifier VARCHAR(100),
    published TIMESTAMP,
    last_modified TIMESTAMP,
    vuln_status VARCHAR(50)
);

CREATE TABLE IF NOT EXISTS  cve_descriptions (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(50),
    description_lang VARCHAR(20),
    description_value TEXT,
    FOREIGN KEY (cve_id) REFERENCES cve_vulnerabilities(cve_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS  cve_tags (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(50), 
    source_identifier VARCHAR(100),
    tag VARCHAR(100),
    FOREIGN KEY (cve_id) REFERENCES cve_vulnerabilities(cve_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS  cvss_metrics (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(50),
    version VARCHAR(10),
    vector_string VARCHAR(500),
    base_score FLOAT,
    base_severity VARCHAR(20),
    attack_vector VARCHAR(20),
    attack_complexity VARCHAR(20),
    privileges_required VARCHAR(20),
    user_interaction VARCHAR(20),
    scope VARCHAR(20),
    confidentiality_impact VARCHAR(20),
    integrity_impact VARCHAR(20),                           
    availability_impact VARCHAR(20),
    FOREIGN KEY (cve_id) REFERENCES cve_vulnerabilities(cve_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS  cve_weaknesses (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(50),
    source TEXT,
    type VARCHAR(100),
    description_lang VARCHAR(20),
    description_value TEXT,
    FOREIGN KEY (cve_id) REFERENCES cve_vulnerabilities(cve_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS  cve_configurations (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(50),
    operator BOOLEAN,
    cpe_match JSON,
    FOREIGN KEY (cve_id) REFERENCES cve_vulnerabilities(cve_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS  cve_references (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(50),
    url TEXT,
    source TEXT,
    tags JSON,
    FOREIGN KEY (cve_id) REFERENCES cve_vulnerabilities(cve_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cve_poc_sources (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(50),
    source_identifier VARCHAR(100),
    url TEXT,
    downloaded_files JSON,
    commit_sha VARCHAR(64) DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (cve_id) REFERENCES cve_vulnerabilities(cve_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS logs (
    id SERIAL PRIMARY KEY,
    status TEXT,
    message TEXT,
    log_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);