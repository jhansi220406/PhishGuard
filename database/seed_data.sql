-- ============================================================================
-- PhishGuard — Phishing URL & QR Code Threat Detection Platform
-- Seed Data Script (MySQL 8.0+)
-- Default Password for seeded analyst: 'PhishGuard@2026'
-- ============================================================================

USE phishguard;

-- Seed Analyst User
INSERT INTO users (id, name, email, password_hash, role, created_at)
VALUES (
    1,
    'Security Analyst',
    'analyst@phishguard.security',
    '$2a$10$tQ1zIe8PqE4vjN/V0XmC9.GqJg8Bf3yXl1GkE.gWp9mQZ4bA0J/Xe', -- BCrypt hash of 'PhishGuard@2026'
    'ROLE_ANALYST',
    NOW()
) ON DUPLICATE KEY UPDATE name=VALUES(name);

-- Seed Sample Scans
INSERT INTO scans (id, user_id, scan_type, submitted_content, destination_hostname, detected_content_type, risk_level, risk_score, threat_provider_status, scanned_at)
VALUES 
(
    1,
    1,
    'URL',
    'http://paypa1-security.account-update.tk/verify?r=token',
    'paypa1-security.account-update.tk',
    'URL',
    'HIGH',
    85,
    'Reputation service unconfigured (Fallback mode)',
    DATE_SUB(NOW(), INTERVAL 2 HOUR)
),
(
    2,
    1,
    'URL',
    'http://192.168.0.12/webscr/login.php',
    '192.168.0.12',
    'URL',
    'HIGH',
    75,
    'Reputation service unconfigured (Fallback mode)',
    DATE_SUB(NOW(), INTERVAL 5 HOUR)
),
(
    3,
    1,
    'URL',
    'https://portal.myuniversity.edu/login',
    'portal.myuniversity.edu',
    'URL',
    'LOW',
    10,
    'Clean',
    DATE_SUB(NOW(), INTERVAL 1 DAY)
),
(
    4,
    1,
    'QR',
    'http://city-meter-pay.quick-check.xyz/charge',
    'city-meter-pay.quick-check.xyz',
    'URL',
    'HIGH',
    70,
    'Reputation service unconfigured (Fallback mode)',
    DATE_SUB(NOW(), INTERVAL 2 DAY)
),
(
    5,
    1,
    'QR',
    'BEGIN:VCARD\nVERSION:3.0\nFN:Alex Vance\nEMAIL:alex@security.edu\nEND:VCARD',
    'vcard-contact',
    'CONTACT',
    'LOW',
    5,
    'Non-URL Payload',
    DATE_SUB(NOW(), INTERVAL 3 DAY)
) ON DUPLICATE KEY UPDATE submitted_content=VALUES(submitted_content);

-- Seed Sample Scan Findings
INSERT INTO scan_findings (scan_id, indicator_code, title, description, severity, score_impact)
VALUES
(1, 'LOOKALIKE_DOMAIN', 'Brand Impersonation Target (PAYPAL)', 'Deceptive domain mimicking PayPal brand.', 'HIGH', 40),
(1, 'SUSPICIOUS_TLD', 'High-Risk Top-Level Domain (.tk)', 'Disposable TLD associated with phishing campaigns.', 'MEDIUM', 25),
(1, 'INSECURE_HTTP', 'Cleartext HTTP Transmission', 'No SSL/TLS transport encryption active.', 'LOW', 15),
(2, 'IP_HOSTNAME', 'Raw IP Hostname Detected', 'Direct IP used instead of registered domain.', 'CRITICAL', 45),
(2, 'CREDENTIAL_TARGETING_KEYWORD', 'Sensitive Authentication Keywords', 'Path contains sensitive login keyword.', 'MEDIUM', 20),
(4, 'SUSPICIOUS_TLD', 'High-Risk Top-Level Domain (.xyz)', 'Low cost disposable TLD.', 'MEDIUM', 25),
(4, 'INSECURE_HTTP', 'Cleartext HTTP Transmission', 'Missing transport layer security.', 'LOW', 15),
(5, 'QR_VCARD_CONTACT', 'Contact Card (vCard) Payload', 'Standard business card payload.', 'INFO', 5);

-- Seed Sample Quiz Results
INSERT INTO quiz_results (user_id, quiz_id, score, total_questions, completed_at)
VALUES
(1, 1, 4, 4, DATE_SUB(NOW(), INTERVAL 1 DAY));
