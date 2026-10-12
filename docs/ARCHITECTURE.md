# PhishGuard — Architecture & Threat Model

## 1. System Architecture Overview

PhishGuard is structured as an enterprise-grade full-stack threat detection platform designed to protect users against deceptive URLs and malicious QR code (Quishing) vectors.

```
                           ┌──────────────────────────────┐
                           │      Web Browser Client      │
                           │  Vanilla HTML5 / CSS3 / JS   │
                           │ html5-qrcode | Chart.js | UI │
                           └──────────────┬───────────────┘
                                          │  HTTPS / REST / JWT
                                          ▼
                      ┌────────────────────────────────────────┐
                      │    Spring Boot 3.3.5 Backend Core      │
                      │ ┌────────────────────────────────────┐ │
                      │ │   Spring Security 6 (JWT / CORS)   │ │
                      │ └──────────────────┬─────────────────┘ │
                      │                    ▼                   │
                      │ ┌────────────────────────────────────┐ │
                      │ │    REST Controllers (Auth/Scans)   │ │
                      │ └──────────────────┬─────────────────┘ │
                      │                    ▼                   │
                      │ ┌────────────────────────────────────┐ │
                      │ │ Deterministic Heuristic Engine     │ │
                      │ │  • Zero-SSRF Rule Evaluator        │ │
                      │ │  • Lookalike Domain Matcher        │ │
                      │ │  • Brand Impersonation Scorer      │ │
                      │ │  • QR Payload Classifier           │ │
                      │ └──────────────────┬─────────────────┘ │
                      │                    ▼                   │
                      │ ┌────────────────────────────────────┐ │
                      │ │ Spring Data JPA / Hibernate        │ │
                      │ └──────────────────┬─────────────────┘ │
                      └────────────────────┼───────────────────┘
                                           │
                        ┌──────────────────┴──────────────────┐
                        │                                     │
                        ▼                                     ▼
             ┌─────────────────────┐               ┌─────────────────────┐
             │ MySQL Database (8+) │               │  H2 In-Memory DB    │
             │   Production Mode   │               │ Development Fallback│
             └─────────────────────┘               └─────────────────────┘
```

---

## 2. Zero-SSRF Execution Policy

A critical vulnerability in many insecure URL inspection tools is Server-Side Request Forgery (SSRF) and malicious code execution caused by fetching or crawling untrusted endpoints.

**PhishGuard adheres to a strict Zero-SSRF architectural guarantee:**
1. **No Inbound Crawling**: The server never issues outbound HTTP GET/POST requests or downloads HTML/JS/executables from submitted targets.
2. **Deterministic Syntactic Analysis**: Risk evaluation is performed strictly on URL structure, domain grammar, punycode representations, user-info prefixes (`@`), and heuristic tokens.
3. **Safe Storage**: Before writing to persistent tables, sensitive query parameters (e.g. `token`, `password`, `key`) are automatically redacted.

---

## 3. Heuristic Indicator Taxonomy

The scoring engine evaluates candidate URLs against 12+ deterministic rules:

| Indicator Code | Description | Severity | Score Weight |
|---|---|---|:---:|
| `IP_HOSTNAME` | Host is specified via raw IPv4 or encoded IP | CRITICAL | +45 |
| `LOOKALIKE_DOMAIN` | Known brand (e.g. PayPal, Apple) in foreign host | HIGH | +40 |
| `AT_SYMBOL_TRICK` | RFC 3986 user-info deception (`user@target.com`) | HIGH | +35 |
| `SUSPICIOUS_ENCODING`| Punycode (`xn--`) or multi-stage percent encoding | HIGH | +35 |
| `SUSPICIOUS_TLD` | Disposable or high-abuse TLD (`.tk`, `.xyz`, etc.) | MEDIUM | +25 |
| `EXCESSIVE_SUBDOMAINS`| Host contains > 4 nested subdomains | MEDIUM | +25 |
| `REDIRECT_PARAMETER` | Open redirect trapping (`?redirect=`, `?url=`) | MEDIUM | +20 |
| `CREDENTIAL_TARGETING_KEYWORD` | Path contains `login`, `verify`, or `account` | MEDIUM | +20 |
| `EXCESSIVE_LENGTH` | URL length > 120 characters | LOW | +15 |
| `INSECURE_HTTP` | Cleartext HTTP transmission without TLS | LOW | +15 |

### Risk Score Formula
$$\text{Score} = \min\left(100, \sum \text{ScoreImpact}\right)$$
- **LOW Risk**: $0 \le \text{Score} < 30$
- **MEDIUM Risk**: $30 \le \text{Score} < 70$
- **HIGH Risk**: $70 \le \text{Score} \le 100$

---

## 4. Quishing & QR Pipeline

1. **Client-Side Decoding**: Utilizing `html5-qrcode`, video stream buffers and uploaded image matrices are decoded completely inside the user's browser runtime.
2. **Payload Typing**: The backend analyzes the decoded string and classifies it as:
   - `URL` (dispatched to the URL Heuristic Engine)
   - `EMAIL` (`mailto:` protocol)
   - `PHONE` (`tel:` dialer action)
   - `WIFI` (`WIFI:S:...` network configuration)
   - `CONTACT` (`BEGIN:VCARD` format)
   - `PLAIN_TEXT` (neutral message)
3. **Non-Execution Invariant**: Decoded links are never opened automatically. The user is presented with a breakdown of destination hostnames and indicators before any navigation decision is made.
