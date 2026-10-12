# PhishGuard — Phishing URL & QR Code Threat Detection Platform

> **"Scan Smart. Stay Secure."**  
> An enterprise-grade cybersecurity SaaS web application for analyzing suspicious links, inspecting QR-code (Quishing) destinations, and delivering explainable threat assessments before you click.

[![Spring Boot](https://img.shields.io/badge/Spring_Boot-3.3.5-brightgreen.svg)](https://spring.io/projects/spring-boot)
[![Java](https://img.shields.io/badge/Java-21%20%7C%2023-orange.svg)](https://www.oracle.com/java/)
[![MySQL](https://img.shields.io/badge/MySQL-8.0-blue.svg)](https://www.mysql.com/)
[![HTML5/CSS3/JS](https://img.shields.io/badge/Frontend-HTML5%20%2F%20CSS3%20%2F%20JavaScript-yellow.svg)](https://developer.mozilla.org/)
[![License](https://img.shields.io/badge/License-Apache_2.0-lightgrey.svg)](LICENSE)

---

## 1. Project Objectives & Problem Statement

Phishing remains the primary initial compromise vector in 90%+ of cybersecurity incidents. Modern attackers increasingly deploy:
- **Quishing (QR Code Phishing)**: Counterfeit QR stickers on parking meters, menus, and physical signs that bypass email scanners.
- **Lexical Obfuscation**: Typosquatting, homoglyph character swaps (Cyrillic homoglyphs), raw IP hosting, `@` credential deception, and disposable high-risk TLDs.
- **The HTTPS Fallacy**: Over 80% of phishing kits obtain free TLS certificates (e.g. Let's Encrypt), misleading victims who rely blindly on browser padlocks.

**PhishGuard provides an explainable, deterministic detection platform that evaluates threats safely without executing or visiting untrusted destinations.**

---

## 2. Architecture & Design Principles

### High-Level Architecture
```
  [ Web Browser Client ]
  • Vanilla HTML5 / CSS3 / ES6
  • html5-qrcode (Camera & Upload)
  • Chart.js (Telemetry & Distribution)
  • Lucide Security Icons
           │
           │ REST APIs (JWT Bearer Auth / CORS)
           ▼
  [ Spring Boot 3.3.5 Core Backend ]
  • Spring Security 6 (Stateless JWT Filter & BCrypt)
  • Deterministic Heuristic Engine (Zero-SSRF Guarantee)
  • Brand Impersonation & Homoglyph Matcher
  • QR Payload Classifier (URL, WiFi, Email, vCard, Text)
  • Spring Data JPA & Validation
           │
           ├──► [ MySQL 8.0+ Database ] (Production)
           └──► [ H2 In-Memory DB ] (Resilient Fallback Mode)
```

### Core Security Guarantees:
1. **Zero-SSRF Execution**: PhishGuard never visits, crawls, or opens submitted links on the server.
2. **Never Auto-Opens QR Codes**: Decoded links are neutralized and displayed for review; no automatic redirects.
3. **Data Minimization & Redaction**: Sensitive URL query parameters (e.g., `?token=...`, `?password=...`) are automatically redacted before persistence.
4. **Ownership Enforcement**: Users can only access and delete their own scan history records.

---

## 3. Technology Stack & Verified Versions

| Layer | Technology | Version | Purpose |
|---|---|---|---|
| **Backend Framework** | Spring Boot | 3.3.5 | Core application framework & REST APIs |
| **Language** | Java | 21 / 23 | Modern LTS Java runtime |
| **Security** | Spring Security 6 | 6.3.4 | Stateless security, BCrypt hashing |
| **Tokens** | JJWT | 0.12.6 | HMAC-SHA256 JWT generation and validation |
| **ORM / Data** | Spring Data JPA / Hibernate | 6.5.3 | Relational entity mapping and repository layer |
| **Database** | MySQL | 8.0+ | Relational persistence with fallback H2 mode |
| **API Docs** | SpringDoc OpenAPI | 2.6.0 | Swagger UI interactive documentation |
| **Frontend** | HTML5, CSS3, JavaScript | Modern ES6 | Vanilla responsive SaaS UI |
| **QR Engine** | html5-qrcode | 2.3.8 | Client-side camera and file image decoding |
| **Visualization** | Chart.js | 4.4.1 | Risk donut charts and 7-day timeline graphs |
| **Build Tool** | Apache Maven | 3.9+ | Build lifecycle and dependency management |

---

## 4. Key Modules & Capabilities

1. **Public Landing Page (`/`)**:
   - Modern cybersecurity aesthetic with dark navy palette (`#0B1020`), purple (`#8B5CF6`), and electric cyan (`#22D3EE`).
   - Instant quick-scan widget directly on the hero section.
   - Comprehensive limitation disclaimer explaining findings are risk indicators.

2. **URL Threat Analyzer (`/url-scanner.html`)**:
   - Analyzes raw IP addresses, brand typosquatting, user-info `@` tricks, suspicious TLDs, length anomalies, and TLS contexts.
   - Outputs explainable risk score (0–100) and severity ratings (LOW, MEDIUM, HIGH, UNKNOWN).

3. **QR Code Threat Scanner (`/qr-scanner.html`)**:
   - **Tab A (Camera)**: Live camera feed with active cyber targeting reticle and permission controls.
   - **Tab B (Upload)**: Drag-and-drop image upload supporting PNG, JPG, and WEBP.
   - **Payload Categorization**: Identifies URLs, emails, phone numbers, WiFi configs, and vCards.

4. **Security Analytics Dashboard (`/dashboard.html`)**:
   - Aggregated metrics: Total Scans, URLs Analyzed, QR Codes Scanned, Potential Threats.
   - Interactive Chart.js charts: 7-day scan timeline and risk distribution donut.
   - Real-time recent scans table with detailed findings modal.

5. **Scan History (`/history.html`)**:
   - User-isolated scan log with filtering (Type, Risk Level), search bar, sorting, and pagination.

6. **Security Insights (`/insights.html`)**:
   - Telemetry on the most frequently triggered indicators (e.g. `LOOKALIKE_DOMAIN`, `INSECURE_HTTP`).

7. **Awareness Center & Quizzes (`/awareness.html`)**:
   - Educational articles on QRishing, Homoglyphs, and the HTTPS Fallacy.
   - Interactive scenario quiz with automatic grading and in-depth answer rationales.

---

## 5. Database Schema

The database model is defined in `database/schema.sql`:

- **`users`**: `id`, `name`, `email`, `password_hash`, `role`, `created_at`
- **`scans`**: `id`, `user_id`, `scan_type`, `submitted_content`, `destination_hostname`, `detected_content_type`, `risk_level`, `risk_score`, `threat_provider_status`, `scanned_at`
- **`scan_findings`**: `id`, `scan_id`, `indicator_code`, `title`, `description`, `severity`, `score_impact`
- **`quiz_results`**: `id`, `user_id`, `quiz_id`, `score`, `total_questions`, `completed_at`

---

## 6. Installation & Running Locally

### Prerequisites
- Java JDK 21 or 23 installed
- Apache Maven 3.9+ installed
- (Optional) MySQL 8.0 running locally

### Option A: Instant Run (Zero Setup with Smart Fallback)
PhishGuard is configured with an intelligent embedded database mode that starts immediately with preloaded demo data and zero external dependencies:

```bash
# Navigate to the backend directory
cd backend

# Run via Maven Spring Boot plugin
mvn spring-boot:run
```
Open your browser to: **`http://localhost:8080/`**

### Option B: Running with Native MySQL

1. **Set up the Database**:
```sql
mysql -u root -p < database/schema.sql
mysql -u root -p < database/seed_data.sql
```

2. **Configure Environment Variables or `.env`**:
```bash
export SPRING_PROFILES_ACTIVE=mysql
export DB_HOST=localhost
export DB_PORT=3306
export DB_NAME=phishguard
export DB_USER=root
export DB_PASS=your_password
```

3. **Start the Backend**:
```bash
cd backend
mvn spring-boot:run
```

### Preloaded Credentials for Evaluators:
- **Email**: `analyst@phishguard.security`
- **Password**: `PhishGuard@2026`
*(A "Use Demo Analyst Account" button is also provided directly on the login page for one-click access)*

---

## 7. API Documentation

Interactive Swagger UI documentation is available at:  
👉 **`http://localhost:8080/swagger-ui.html`**

OpenAPI JSON schema:  
👉 **`http://localhost:8080/v3/api-docs`**

---

## 8. Running Automated Tests

To execute the test suite (19 unit & integration tests):

```bash
cd backend
mvn test
```

Tests verify:
- Heuristic rule triggers (IP hostname, brand lookalike, suspicious TLD, `@` trick)
- QR code payload identification (URL, text, email, WiFi, contact)
- Privacy-conscious token redaction
- User registration, login, and JWT validation
- MockMvc HTTP endpoint contracts and validation error handling

---

## 9. College Presentation & Demo Workflow

Follow the step-by-step presentation script in [`docs/PRESENTATION_GUIDE.md`](docs/PRESENTATION_GUIDE.md):
1. **Landing Page**: Introduce the core problem and test the Hero quick-analyzer.
2. **URL Scanner**: Test `http://paypa1-security.account-update.tk/verify?token=123`.
3. **QR Scanner**: Demonstrate the live camera reticle or upload a QR image.
4. **Dashboard**: Log in to inspect real-time Chart.js charts and history filters.
5. **Awareness Center**: Complete the scenario quiz to demonstrate educational feedback.

---

## 10. Security Limitations & Future Enhancements

- **Machine Learning Classifier**: Future iterations can integrate an ONNX runtime to combine heuristic scores with a Random Forest or BERT lexical model.
- **External Threat Registries**: Optional VirusTotal or Google Safe Browsing API keys can be activated via environment variables (`VIRUSTOTAL_API_KEY`, `SAFEBROWSING_API_KEY`).
- **Browser Extension**: A companion manifest v3 extension to inspect links directly inside web clients.

---

## License
Licensed under the Apache License, Version 2.0. Built for academic demonstration, portfolios, and cybersecurity education.
