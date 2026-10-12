-- ============================================================================
-- PhishGuard — Phishing URL & QR Code Threat Detection Platform
-- Database Schema Definition (MySQL 8.0+)
-- ============================================================================

CREATE DATABASE IF NOT EXISTS phishguard CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE phishguard;

-- Table: users
CREATE TABLE IF NOT EXISTS users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'ROLE_ANALYST',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_users_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: scans
CREATE TABLE IF NOT EXISTS scans (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NULL,
    scan_type VARCHAR(20) NOT NULL, -- 'URL' or 'QR'
    submitted_content VARCHAR(2048) NOT NULL,
    destination_hostname VARCHAR(255) NULL,
    detected_content_type VARCHAR(50) NOT NULL DEFAULT 'URL', -- 'URL', 'EMAIL', 'PHONE', 'WIFI', 'CONTACT', 'PLAIN_TEXT'
    risk_level VARCHAR(30) NOT NULL DEFAULT 'UNKNOWN', -- 'LOW', 'MEDIUM', 'HIGH', 'UNKNOWN'
    risk_score INT NOT NULL DEFAULT 0, -- 0 to 100
    threat_provider_status VARCHAR(150) NULL,
    scanned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_scans_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_scans_user_id (user_id),
    INDEX idx_scans_type (scan_type),
    INDEX idx_scans_risk (risk_level),
    INDEX idx_scans_timestamp (scanned_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: scan_findings
CREATE TABLE IF NOT EXISTS scan_findings (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    scan_id BIGINT NOT NULL,
    indicator_code VARCHAR(80) NOT NULL,
    title VARCHAR(150) NOT NULL,
    description VARCHAR(1000) NOT NULL,
    severity VARCHAR(30) NOT NULL, -- 'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    score_impact INT NOT NULL DEFAULT 0,
    CONSTRAINT fk_findings_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    INDEX idx_findings_scan_id (scan_id),
    INDEX idx_findings_code (indicator_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: quiz_results
CREATE TABLE IF NOT EXISTS quiz_results (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NULL,
    quiz_id BIGINT NOT NULL DEFAULT 1,
    score INT NOT NULL,
    total_questions INT NOT NULL,
    completed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_quiz_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_quiz_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
