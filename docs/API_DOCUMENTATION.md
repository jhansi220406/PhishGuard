# PhishGuard — REST API Specification

Base URL: `/api`  
Swagger UI Interactive Documentation: `http://localhost:8080/swagger-ui.html`  
OpenAPI JSON Schema: `http://localhost:8080/v3/api-docs`

---

## 1. Authentication Endpoints

### 1.1 Register Analyst Account
- **Method**: `POST`
- **Path**: `/api/auth/register`
- **Public**: Yes
- **Request Body**:
```json
{
  "name": "Alex Vance",
  "email": "alex@security-lab.edu",
  "password": "SecurePassword123!"
}
```
- **Response `201 Created`**:
```json
{
  "token": "eyJhbGciOiJIUzI1NiJ9...",
  "type": "Bearer",
  "user": {
    "id": 2,
    "name": "Alex Vance",
    "email": "alex@security-lab.edu",
    "role": "ROLE_ANALYST",
    "createdAt": "2026-10-12T14:30:00"
  }
}
```

### 1.2 Sign In (Authenticate)
- **Method**: `POST`
- **Path**: `/api/auth/login`
- **Public**: Yes
- **Request Body**:
```json
{
  "email": "analyst@phishguard.security",
  "password": "PhishGuard@2026"
}
```
- **Response `200 OK`**:
```json
{
  "token": "eyJhbGciOiJIUzI1NiJ9...",
  "type": "Bearer",
  "user": {
    "id": 1,
    "name": "Security Analyst",
    "email": "analyst@phishguard.security",
    "role": "ROLE_ANALYST",
    "createdAt": "2026-10-12T10:00:00"
  }
}
```

### 1.3 Get Current User Profile
- **Method**: `GET`
- **Path**: `/api/auth/me`
- **Headers**: `Authorization: Bearer <token>`
- **Response `200 OK`**: Returns current user object.

---

## 2. Threat Analysis Endpoints

### 2.1 Heuristic URL Analysis
- **Method**: `POST`
- **Path**: `/api/scans/url`
- **Public**: Yes (Anonymous scans permitted; attached to account if Authorization header present)
- **Request Body**:
```json
{
  "url": "http://paypa1-security.account-update.tk/verify?token=secret123"
}
```
- **Response `200 OK`**:
```json
{
  "id": 6,
  "scanType": "URL",
  "submittedContent": "http://paypa1-security.account-update.tk/verify?token=[REDACTED]",
  "destinationHostname": "paypa1-security.account-update.tk",
  "detectedContentType": "URL",
  "riskLevel": "HIGH",
  "riskScore": 85,
  "threatProviderStatus": "Reputation service unconfigured (Fallback mode)",
  "scannedAt": "2026-10-12T14:35:10",
  "findings": [
    {
      "indicatorCode": "LOOKALIKE_DOMAIN",
      "title": "Brand Impersonation Target (PAYPAL)",
      "description": "The host contains references to 'paypal' but does not belong to the official registered domain.",
      "severity": "HIGH",
      "scoreImpact": 40
    },
    {
      "indicatorCode": "SUSPICIOUS_TLD",
      "title": "High-Risk Top-Level Domain (.tk)",
      "description": "The TLD '.tk' is statistically correlated with disposable, free, or low-cost phishing campaigns.",
      "severity": "MEDIUM",
      "scoreImpact": 25
    },
    {
      "indicatorCode": "INSECURE_HTTP",
      "title": "Cleartext HTTP Transmission",
      "description": "Destination does not enforce TLS encryption.",
      "severity": "LOW",
      "scoreImpact": 15
    }
  ],
  "recommendations": [
    "Navigate to paypal using your browser bookmarks or official mobile application.",
    "Never submit credentials or sensitive payment details over unencrypted HTTP."
  ]
}
```

### 2.2 QR Code Payload Analysis
- **Method**: `POST`
- **Path**: `/api/scans/qr`
- **Request Body**:
```json
{
  "content": "http://city-meter-pay.quick-check.xyz/charge",
  "scanType": "QR"
}
```
- **Response `200 OK`**: Returns typed verdict and routed URL or non-URL findings.

---

## 3. History Endpoints

### 3.1 List Scan History
- **Method**: `GET`
- **Path**: `/api/scans?page=0&size=10&scanType=URL&riskLevel=HIGH&search=paypal`
- **Headers**: `Authorization: Bearer <token>`
- **Response `200 OK`**: Returns Paginated `Page<ScanResponse>` strictly isolated to current user.

### 3.2 Get Scan Details
- **Method**: `GET`
- **Path**: `/api/scans/{id}`
- **Response `200 OK`**: Returns single scan with all itemized findings.

### 3.3 Delete Scan Record
- **Method**: `DELETE`
- **Path**: `/api/scans/{id}`
- **Response `200 OK`**: `{"message": "Scan record deleted successfully."}`

---

## 4. Dashboard & Analytics Endpoints

### 4.1 Summary Metrics
- **Method**: `GET`
- **Path**: `/api/dashboard/summary`
- **Response `200 OK`**:
```json
{
  "totalScans": 32,
  "urlScans": 21,
  "qrScans": 11,
  "threatsDetected": 9,
  "isDemo": false
}
```

### 4.2 Chart Activity & Indicator Distribution
- **Method**: `GET`
- **Path**: `/api/dashboard/activity`
- **Response `200 OK`**: Returns 7-day timeline points, risk breakdown, and top triggered threat indicators.

---

## 5. Phishing Awareness & Training Endpoints

### 5.1 Educational Articles
- **Method**: `GET`
- **Path**: `/api/awareness/articles`

### 5.2 Scenario Quiz Questions
- **Method**: `GET`
- **Path**: `/api/awareness/quizzes`

### 5.3 Submit Quiz Answers
- **Method**: `POST`
- **Path**: `/api/awareness/quiz-results`
- **Request Body**:
```json
{
  "quizId": 1,
  "answers": [
    { "questionId": 1, "chosenIndex": 1 },
    { "questionId": 2, "chosenIndex": 2 },
    { "questionId": 3, "chosenIndex": 1 },
    { "questionId": 4, "chosenIndex": 1 }
  ]
}
```
- **Response `200 OK`**: Returns score percentage, accuracy level, and in-depth rationales for every question.
