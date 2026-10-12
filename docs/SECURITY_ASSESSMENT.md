# PhishGuard — Security Assessment & Risk Engine Specification

## 1. Threat Landscape & Problem Definition

Phishing attacks remain the #1 initial access vector in cybersecurity breaches. Modern threat actors leverage two distinct evasion vectors:
1. **Quishing (QR Code Phishing)**: Bypasses standard secure email gateways (SEG) because legacy text filters cannot read binary 2D barcodes embedded in image attachments or printed flyers.
2. **Lexical Domain Obfuscation**: Attackers exploit Internationalized Domain Names (IDN homoglyphs), typosquatting, user-info prefixes, open redirects, and raw IP hosting.

---

## 2. Threat Indicator Rules Matrix

| Code | Indicator | Category | Default Weight | Condition |
|---|---|---|:---:|---|
| `IP_HOSTNAME` | Raw IP Hostname | Infrastructure | 45 | Target host matches IPv4 / Hex / Octal pattern |
| `LOOKALIKE_DOMAIN` | Lookalike / Brand Spoofing | Identity | 40 | Host contains target brand (e.g. `paypal`) without being the official domain |
| `AT_SYMBOL_TRICK` | RFC 3986 User-Info Deception | Lexical | 35 | URL contains `@` character before destination host |
| `SUSPICIOUS_ENCODING` | Punycode / Multi-hex | Lexical | 35 | Host begins with `xn--` or contains nested `%` encoding |
| `SUSPICIOUS_TLD` | High-Risk TLD | Infrastructure | 25 | Suffix matches `.tk`, `.ml`, `.xyz`, `.top`, `.work`, etc. |
| `EXCESSIVE_SUBDOMAINS` | Subdomain Nesting Depth | Lexical | 25 | Host segment split count > 4 |
| `REDIRECT_PARAMETER` | Open Redirect Trapping | Semantic | 20 | Query contains `?redirect=`, `?url=`, `?next=`, etc. |
| `CREDENTIAL_TARGETING_KEYWORD` | Credential Target Path | Semantic | 20 | Path/query contains `login`, `verify`, `account` on non-official host |
| `EXCESSIVE_LENGTH` | Excessive Length | Obfuscation | 15 | Total URL length > 120 characters |
| `INSECURE_HTTP` | Cleartext Protocol | Cryptographic | 15 | Protocol is `http://` instead of `https://` |

---

## 3. Quishing Classification Model

When a QR code is submitted, the payload is categorized before any action:

```
                  ┌──────────────────────────────┐
                  │      Decoded QR Payload      │
                  └──────────────┬───────────────┘
                                 │
           ┌─────────────────────┼─────────────────────┐
           ▼                     ▼                     ▼
     [Starts with          [Starts with          [Starts with
     http:// / https://]   mailto: / email]      WIFI: / wifi]
           │                     │                     │
           ▼                     ▼                     ▼
       Type: URL            Type: EMAIL           Type: WIFI
   (Dispatch to URL      (Email action warning (Wi-Fi MITM alert
   Heuristic Engine)        score: 10)            score: 30)
```

---

## 4. Privacy & Data Minimization

1. **Authentication Token Stripping**: When URLs are submitted that contain tokens or session IDs (e.g. `?token=...`, `?password=...`), they are automatically redacted prior to database storage (`[REDACTED]`).
2. **Stateless QR Processing**: QR image uploads are processed directly in memory or client-side; image files are never permanently saved to disk.
