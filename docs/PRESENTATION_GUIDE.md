# PhishGuard — College Presentation & Live Demonstration Guide

This guide is designed for presenting PhishGuard in a college Full Stack Development (FSD) project defense, portfolio review, or internship interview.

---

## 1. 5-Minute Demonstration Script

| Time | Stage | Action / Talking Points |
|:---:|---|---|
| **0:00 - 1:00** | **Problem Statement** | Open `http://localhost:8080/`. Explain the surge of QRishing (QR phishing) and lookalike domains. Point out that traditional users rely on the "green padlock" (HTTPS) which only proves encryption, not identity. |
| **1:00 - 2:00** | **URL Threat Engine** | Click **URL Scanner**. Paste test link: `http://paypa1-security.account-update.tk/verify?token=123`. Click **Analyze URL**. Point out how PhishGuard decomposes the host: identifies brand spoofing of PayPal, flags `.tk` TLD, detects cleartext HTTP, redacts sensitive query tokens, and renders a 85/100 HIGH Risk report. |
| **2:00 - 3:15** | **QR Scanner (Camera & Upload)** | Click **QR Scanner**. Switch to **Upload QR Image**. Drop a sample QR code or use the **Start Scanner** webcam feed with the pulsing targeting reticle. Emphasize the Zero-Execution policy: PhishGuard never blindly executes or navigates to QR destinations. Show how non-URL payloads (WiFi, vCard, Plain Text) are accurately identified without falsely claiming safe web status. |
| **3:15 - 4:15** | **Security Dashboard & Auth** | Log in with the preloaded analyst credentials (`analyst@phishguard.security` / `PhishGuard@2026`). Navigate to `/dashboard.html`. Showcase the Chart.js visual telemetry: 7-day scan timeline, risk distribution donut chart, and real-time stored scan log. Open `/history.html` and filter by High Risk. |
| **4:15 - 5:00** | **Awareness & Architecture** | Navigate to `/awareness.html`. Complete a scenario in the **Interactive Scenario Quiz**. Highlight the instant grading and technical explanations. Show Swagger docs at `/swagger-ui.html`. |

---

## 2. Recommended Test Scenarios for Evaluators

### Scenario A: Legitimate Portal (LOW Risk)
- **Input URL**: `https://portal.myuniversity.edu/login`
- **Expected Result**: Score 0–15, **LOW RISK**, green badge, TLS confirmed, zero brand spoofing triggers.

### Scenario B: Brand Lookalike / Typosquatting (HIGH Risk)
- **Input URL**: `http://paypal-verification-account.tk/login`
- **Expected Result**: Score 80–90, **HIGH RISK**, red badge.
- **Triggers**: `LOOKALIKE_DOMAIN` (PayPal target), `SUSPICIOUS_TLD` (.tk), `INSECURE_HTTP`.

### Scenario C: Raw IP Address Hostname (HIGH Risk)
- **Input URL**: `http://192.168.0.12/webscr/login.php`
- **Expected Result**: Score 70–80, **HIGH RISK**.
- **Triggers**: `IP_HOSTNAME` (Raw IPv4 target), `CREDENTIAL_TARGETING_KEYWORD` (`login`).

### Scenario D: User-Info Prefix Credential Trap (HIGH Risk)
- **Input URL**: `http://google.com@phishing-trap.com/verify`
- **Expected Result**: Triggers `AT_SYMBOL_TRICK` explaining that the browser connects to `phishing-trap.com`, not Google.

### Scenario E: QR Code Non-Web Payload (Neutral / Low Risk)
- **Input Text**: `BEGIN:VCARD\nVERSION:3.0\nFN:Alex Vance\nEMAIL:alex@security.edu\nEND:VCARD`
- **Expected Result**: Identified as `CONTACT` (vCard), non-URL alert, does not trigger false web warnings.

---

## 3. Anticipated Viva / Interview Questions & Answers

**Q1: How does PhishGuard protect against Server-Side Request Forgery (SSRF)?**  
*Answer*: PhishGuard does not use server-side HTTP fetchers or headless crawlers to load candidate pages. Instead, it inspects URL lexical structure, RFC 3986 syntax rules, Punycode representations, and deterministic brand dictionaries. This eliminates outbound SSRF vectors completely.

**Q2: Why not just check if a website uses HTTPS?**  
*Answer*: Over 80% of modern phishing sites obtain free, automated SSL/TLS certificates (e.g. Let's Encrypt). HTTPS only protects data in transit; it provides no guarantee that the domain operator is honest. PhishGuard treats HTTPS as an encryption indicator, not an authentication proof.

**Q3: How are user records protected in multi-tenant environments?**  
*Answer*: Every scan and history record is tied to a foreign key `user_id`. In `ScanService`, all query and deletion operations enforce record ownership against the authenticated JWT `UserPrincipal`. Users cannot access or delete another user's scan history.
