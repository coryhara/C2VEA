CREATE TABLE IF NOT EXISTS cve_vulnerabilities (
    cve_id VARCHAR(50) PRIMARY KEY,
    source_identifier VARCHAR(100),
    published TIMESTAMP NULL,
    last_modified TIMESTAMP NULL,
    vuln_status VARCHAR(50)
);

CREATE TABLE IF NOT EXISTS cve_descriptions (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(50) NOT NULL,
    description_lang VARCHAR(20) NOT NULL,
    description_value TEXT,
    UNIQUE KEY (cve_id, description_lang),
    FOREIGN KEY (cve_id) REFERENCES cve_vulnerabilities (cve_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cve_tags (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(50) NOT NULL,
    source_identifier VARCHAR(100),
    tag VARCHAR(100) NOT NULL,
    UNIQUE KEY (cve_id, tag),
    FOREIGN KEY (cve_id) REFERENCES cve_vulnerabilities (cve_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cvss_metrics (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(50) NOT NULL,
    version VARCHAR(10) NOT NULL,
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
    UNIQUE KEY (cve_id, version),
    FOREIGN KEY (cve_id) REFERENCES cve_vulnerabilities (cve_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cve_weaknesses (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(50) NOT NULL,
    source TEXT,
    type VARCHAR(100) NOT NULL,
    description_lang VARCHAR(20) NOT NULL,
    description_value TEXT,
    UNIQUE KEY (cve_id, type, description_lang),
    FOREIGN KEY (cve_id) REFERENCES cve_vulnerabilities (cve_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cve_configurations (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(50) NOT NULL,
    operator VARCHAR(10) NOT NULL,
    cpe_match JSON,
    UNIQUE KEY (cve_id, operator),
    FOREIGN KEY (cve_id) REFERENCES cve_vulnerabilities (cve_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cve_references (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(50) NOT NULL,
    url TEXT NOT NULL,
    source TEXT,
    tags JSON,
    UNIQUE KEY (cve_id, url(255)),
    FOREIGN KEY (cve_id) REFERENCES cve_vulnerabilities (cve_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cve_poc_sources (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(50) NOT NULL,
    source_identifier VARCHAR(100),
    url TEXT,
    downloaded_files JSON,
    commit_sha VARCHAR(64) DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY (cve_id, url(255)),
    FOREIGN KEY (cve_id) REFERENCES cve_vulnerabilities (cve_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS logs (
    id SERIAL PRIMARY KEY,
    status TEXT,
    message TEXT,
    log_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS app_config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    config_key VARCHAR(100) UNIQUE NOT NULL,
    config_value VARCHAR(255) NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS coharas (
    id VARCHAR(20) PRIMARY KEY,
    password VARCHAR(255) NOT NULL,
    name VARCHAR(1000) NOT NULL,
    nickname VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(320) UNIQUE NOT NULL,
    phone VARCHAR(15) UNIQUE NOT NULL,
    github_token VARCHAR(255) NOT NULL,
    github_token_hash CHAR(64) UNIQUE NOT NULL,
    email_token VARCHAR(255) UNIQUE NULL,
    admin_permission BOOLEAN DEFAULT 0,
    phone_verified BOOLEAN DEFAULT 0,
    email_verified BOOLEAN DEFAULT 0,
    github_verified BOOLEAN DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_cve_vuln_published_cve
    ON cve_vulnerabilities (published, cve_id);
CREATE INDEX IF NOT EXISTS idx_cvss_metrics_severity_cve
    ON cvss_metrics (base_severity, cve_id);
CREATE INDEX IF NOT EXISTS idx_cvss_metrics_score_cve
    ON cvss_metrics (base_score, cve_id);
CREATE INDEX IF NOT EXISTS idx_cvss_metrics_vector_cve
    ON cvss_metrics (attack_vector, cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_desc_cve_lang
    ON cve_descriptions (cve_id, description_lang);
CREATE INDEX IF NOT EXISTS idx_cve_tags_cve_tag
    ON cve_tags (cve_id, tag);
CREATE INDEX IF NOT EXISTS idx_cve_poc_created_id
    ON cve_poc_sources (created_at, id);
CREATE INDEX IF NOT EXISTS idx_cve_poc_source_id
    ON cve_poc_sources (source_identifier, id);
CREATE INDEX IF NOT EXISTS idx_cve_poc_cve_id
    ON cve_poc_sources (cve_id);

-- ============================================
-- 초기 구성 데이터 (환경 설정)
-- ============================================
INSERT INTO app_config (config_key, config_value)
VALUES
    ('CVE_START_YEAR', '1999'),
    ('CVE_START_MONTH', '1'),
    ('CVE_INTERVAL_HOURS', '1'),
    ('CVE_MINUTE', '30'),
    ('CVE_INTERVAL', '10.0'),
    ('RESEARCH_GITHUB_TOKEN', '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'),
    ('RESEARCH_START_YEAR', '1999'),
    ('RESEARCH_START_MONTH', '1'),
    ('RESEARCH_SCHEDULE_TIME', '09:00'),
    ('RESEARCH_MAX_THREADS', '5'),
    ('RESEARCH_WAIT_MINUTES', '10'),
    ('RESEARCH_RATE_LIMIT_THRESHOLD', '500'),
    ('RESEARCH_DOWNLOAD_INTERVAL', '2.0'),
    ('RESEARCH_RETRY_INTERVAL', '1.0'),
    ('RESEARCH_REQUEST_INTERVAL', '1.7'),
    ('RESEARCH_MAX_RETRIES', '3')
ON DUPLICATE KEY UPDATE
    config_value = VALUES(config_value);

-- ============================================
-- Default admin account (created only once)
-- id/password: admin / admin
-- ============================================
INSERT INTO coharas (
    id,
    password,
    name,
    nickname,
    email,
    phone,
    github_token,
    github_token_hash,
    admin_permission,
    phone_verified,
    email_verified,
    github_verified,
    email_token
)
SELECT
    'admin',
    SHA2('admin', 512),
    'Administrator',
    'admin',
    'admin@coharas.local',
    '10000000000',
    'admin-default-token',
    SHA2('admin-default-token', 256),
    1,
    1,
    1,
    1,
    NULL
WHERE NOT EXISTS (
    SELECT 1 FROM coharas WHERE id = 'admin'
);
