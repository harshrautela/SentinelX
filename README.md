# SentinelX — Automated API VAPT & Vulnerability Intelligence Platform

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-009688?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18.2+-61DAFB?style=flat&logo=react&logoColor=black)](https://react.dev/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat&logo=docker&logoColor=white)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> **SentinelX** is an authorized, local API Vulnerability Assessment and Penetration Testing (VAPT) platform designed to automatically discover REST APIs, execute controlled security probes, verify vulnerabilities with reproducible evidence, assign transparent CVSS-style risk ratings, generate professional assessment reports, and perform live retesting after developer remediation.

---

## Table of Contents

1. [Executive Summary & Problem Statement](#1-executive-summary--problem-statement)
2. [VAPT Methodology & Workflow](#2-vapt-methodology--workflow)
3. [Architecture Overview](#3-architecture-overview)
4. [Technology Stack](#4-technology-stack)
5. [VulnBank API — Target Architecture](#5-vulnbank-api--target-architecture)
6. [Vulnerability Test Modules](#6-vulnerability-test-modules)
7. [Evidence & Comparison Engine](#7-evidence--comparison-engine)
8. [Risk & Severity Engine](#8-risk--severity-engine)
9. [Remediation & Retesting Workflow](#9-remediation--retesting-workflow)
10. [Defensive Security & Containment](#10-defensive-security--containment)
11. [Quickstart & Running Locally](#11-quickstart--running-locally)
12. [Interview Guide: Answering Technical Questions](#12-interview-guide-answering-technical-questions)
13. [Limitations & Roadmap](#13-limitations--roadmap)

---

## 1. Executive Summary & Problem Statement

### The Problem
Modern web architectures rely heavily on REST APIs, microservices, and mobile backends. However, traditional vulnerability scanners (such as generic DAST tools built for static HTML pages) fail to effectively assess modern APIs because:
- They do not understand OpenAPI / Swagger contract schemas.
- They lack deep contextual understanding of authentication tokens (JWT) and multi-tenant resource boundaries.
- They rely blindly on HTTP response status codes, generating excessive false positives.
- They report that an endpoint "might" be vulnerable without capturing reproducible proof.

### The Solution: SentinelX
SentinelX was architected to bridge this gap:
- **Contract-Driven Discovery**: Automatically ingests OpenAPI 3.x specifications to discover paths, methods, parameters, and authentication requirements.
- **Evidence-Based Verification**: Probes are verified using multidimensional differential analysis (comparing baseline responses against test responses). A finding is only registered when tangible technical evidence confirms the vulnerability.
- **Defensive Containment**: Bounded by design to local/private authorized environments with strict SSRF protection, request limits, and sensitive data masking.
- **Full Retesting Lifecycle**: Bridges the gap between AppSec engineers and developers: **Discover → Prove with Evidence → Remediate → Retest → Verify Fixed**.

---

## 2. VAPT Methodology & Workflow

```
   Target API (VulnBank)
            │
            ▼
┌───────────────────────┐
│  1. API Discovery     │  Parses OpenAPI / Swagger 3.x specs & maps endpoints
└───────────┬───────────┘
            │
            ▼
┌───────────────────────┐
│  2. Parameter Analysis│  Extracts path, query, body schemas & auth requirements
└───────────┬───────────┘
            │
            ▼
┌───────────────────────┐
│  3. Security Engine   │  Plugin-style checks (BOLA, SQLi, Auth, JWT, Headers, Data)
└───────────┬───────────┘
            │
            ▼
┌───────────────────────┐
│  4. Evidence Collector│  Captures sanitized baseline & attack request/response pairs
└───────────┬───────────┘
            │
            ▼
┌───────────────────────┐
│  5. Severity Scoring  │  Transparent CVSS-style score (Exploitability × Impact × Confidence)
└───────────┬───────────┘
            │
            ▼
┌───────────────────────┐
│  6. Security Report   │  Generates deliverables (Executive Summary, Markdown, JSON)
└───────────┬───────────┘
            │
            ▼
┌───────────────────────┐
│  7. Developer Fix     │  Application owner patches target code
└───────────┬───────────┘
            │
            ▼
┌───────────────────────┐
│  8. Automated Retest  │  SentinelX reruns specific probe to verify fix (OPEN -> FIXED)
└───────────────────────┘
```

---

## 3. Architecture Overview

SentinelX operates as three decoupled services within an isolated Docker bridge network (`sentinelx-net`):

```
                        Docker Bridge Network (sentinelx-net)
 ┌──────────────────────┐         HTTP          ┌──────────────────────┐
 │  SentinelX Frontend  │ ────────────────────> │  SentinelX Backend   │
 │  React + Vite        │   REST API (:8000)    │  FastAPI + SQLAlchemy│
 │  Port 5173           │                       │  Port 8000           │
 └──────────────────────┘                       └──────────┬───────────┘
                                                           │
                                                           │ Controlled HTTP Probes
                                                           │ (:8001)
                                                           ▼
                                                ┌──────────────────────┐
                                                │   VulnBank API       │
                                                │   (Vulnerable Target)│
                                                │   Port 8001          │
                                                └──────────────────────┘
```

**Key Architectural Decisions:**
1. **Zero Code Coupling**: SentinelX and VulnBank share no code or database. SentinelX treats VulnBank purely as an external HTTP target.
2. **Plugin Test Engine**: All vulnerability checks inherit from `BaseVulnerabilityTest`. New security modules can be added in seconds without modifying engine internals.
3. **Audit Trail**: Every outbound HTTP request is logged in SQLite (`RequestLog`) for security accountability.

---

## 4. Technology Stack

- **Backend**: Python 3.11+, FastAPI, Pydantic v2, SQLAlchemy 2.0, SQLite (WAL mode)
- **Scanning & Security**: `httpx` (async HTTP client), `PyJWT` (token inspection), Standard Library `ipaddress`, `socket`, `re`
- **Frontend**: React 18, Vite, Lucide Icons, Pure Vanilla CSS Design System
- **Testing**: `pytest`, `pytest-asyncio`
- **Containerization**: Docker, Docker Compose

---

## 5. VulnBank API — Target Architecture

VulnBank simulates a modern retail and commercial banking REST API. It is **intentionally vulnerable** to enable safe, authorized VAPT demonstrations.

| Endpoint | Method | Intentional Flaw | CWE | Vulnerable Behavior |
|---|---|---|---|---|
| `/api/v1/auth/login` | POST | Insecure JWT | CWE-287 | Issues tokens with no expiration (`exp`) and sensitive user data in claims. |
| `/api/v1/users/{id}` | GET | BOLA / IDOR | CWE-639 | Any authenticated user can read any other customer's profile by altering `{id}`. |
| `/api/v1/accounts/{id}` | GET | BOLA / IDOR | CWE-639 | Customer A can view Customer B's bank account balance and account numbers. |
| `/api/v1/accounts/{id}/transactions` | GET | BOLA / IDOR | CWE-639 | Customer A can read Customer B's private transaction ledger. |
| `/api/v1/admin/users` | GET | Missing Auth | CWE-306 | Entire customer directory accessible anonymously without credentials. |
| `/api/v1/profile` | GET | Data Leakage | CWE-200 | Returns `password_hash` (MD5) and internal `api_key` in JSON response. |
| `/api/v1/search?q=` | GET | SQL Injection | CWE-89 | Raw SQL query concatenation; reveals database errors on syntax probes. |
| `/api/v1/change-password` | POST | No Rate Limit | CWE-770 | Allows unlimited password change attempts without throttling or lockout. |
| All Endpoints | * | Missing Headers| CWE-693 | Omits CSP, HSTS, X-Frame-Options, and X-Content-Type-Options. |

### Remediation Mode
Setting environment variable `VULNBANK_SECURE_MODE=true` instantly patches all intentional vulnerabilities, allowing you to demonstrate the retest workflow (`OPEN` → `FIXED`).

---

## 6. Vulnerability Test Modules

### 1. BOLA / IDOR (`bola.py`)
- **Methodology**: Authenticates as User A. Sends baseline request to `/accounts/101`. Then alters the path parameter to `/accounts/102` using the *same* token.
- **Verification**: Uses `ResponseComparator` to check if a foreign account's data (`user_id`, `account_number`) is returned with HTTP 200 instead of HTTP 403 Forbidden.

### 2. Missing Authentication (`authentication.py`)
- **Methodology**: Identifies endpoints marked with authentication requirements or administrative paths (`/admin`, `/manage`).
- **Verification**: Sends unauthenticated requests (omitting Authorization header). Flags vulnerability if protected data is returned with HTTP 200.

### 3. Controlled SQL Injection (`injection.py`)
- **Methodology**: Sends safe, non-destructive payloads:
  - Syntax probe: `'`
  - Boolean tautology probe: `' OR '1'='1`
- **Verification**: Scans responses against multi-engine database error regexes (SQLite, Postgres, MySQL) and checks for boolean tautology result set expansion.

### 4. Sensitive Data Exposure (`sensitive_data.py`)
- **Methodology**: Inspects JSON response keys on data-returning endpoints.
- **Verification**: Recursively checks for leaked credentials (`password_hash`, `api_key`, `secret`). Automatically masks sensitive values before persisting evidence.

### 5. JWT Security Analysis (`jwt_analysis.py`)
- **Methodology**: Decodes unverified tokens issued during login.
- **Verification**: Detects missing `exp` claims, weak `alg: none` settings, and exposed credentials inside unencrypted JWT claims.

### 6. Missing Security Headers (`security_headers.py`)
- **Methodology**: Checks HTTP response headers against defense-in-depth standards:
  - `Content-Security-Policy`
  - `Strict-Transport-Security` (HSTS)
  - `X-Frame-Options`
  - `X-Content-Type-Options`
- **Severity**: Proportionate scoring (Medium/Low) rather than arbitrarily marking everything Critical.

### 7. Controlled Rate Limiting (`rate_limit.py`)
- **Methodology**: Sends a small, safe burst of probe requests (max 10 requests) to sensitive endpoints (`/change-password`).
- **Verification**: Verifies whether HTTP 429 Too Many Requests or `Retry-After` headers are enforced.

---

## 7. Evidence & Comparison Engine

Every confirmed vulnerability contains immutable technical evidence:
```json
{
  "finding_id": "9d1b-...",
  "evidence_type": "REQUEST_RESPONSE",
  "original_request": {
    "method": "GET",
    "url": "http://vulnerable-api:8000/api/v1/accounts/101",
    "headers": { "Authorization": "Bearer eyJ[REDACTED_JWT]" }
  },
  "original_status": 200,
  "original_response_excerpt": "{\"id\": 101, \"user_id\": 1, \"account_number\": \"ACC-001-ALICE\"}",
  "test_request": {
    "method": "GET",
    "url": "http://vulnerable-api:8000/api/v1/accounts/102",
    "headers": { "Authorization": "Bearer eyJ[REDACTED_JWT]" }
  },
  "test_status": 200,
  "test_response_excerpt": "{\"id\": 102, \"user_id\": 2, \"account_number\": \"ACC-002-BOB\"}",
  "observation": "Authenticated request to id=101 succeeded with HTTP 200. Requesting foreign resource id=102 with the same credentials also succeeded with HTTP 200. Response indicates access to a different user/resource identity.",
  "confidence": "HIGH"
}
```

### Sensitive Data Masking Rule
Tokens and passwords are masked before storage:
`Bearer eyJhbGci...` → `Bearer [REDACTED_JWT]`
`api_key: ak_alice_secret_123` → `api_key: ak_al1********`

---

## 8. Risk & Severity Engine

SentinelX calculates transparent risk ratings using a formula inspired by CVSS v3.1:

$$\text{Risk Score} = \min(10.0, (\text{Exploitability Weight} + \text{Impact Weight}) \times \text{Confidence Multiplier})$$

| Metric | Level | Weight / Multiplier |
|---|---|---|
| **Exploitability** | EASY | 3.5 |
| | MODERATE | 2.2 |
| | DIFFICULT | 1.0 |
| **Impact** | CRITICAL | 5.5 |
| | HIGH | 4.5 |
| | MEDIUM | 3.0 |
| | LOW | 1.5 |
| **Confidence** | HIGH | 1.0 |
| | MEDIUM | 0.85 |
| | LOW | 0.65 |

**Severity Mapping:**
- **CRITICAL** (9.0 – 10.0)
- **HIGH** (7.0 – 8.9)
- **MEDIUM** (4.0 – 6.9)
- **LOW** (2.0 – 3.9)
- **INFO** (0.0 – 1.9)

---

## 9. Remediation & Retesting Workflow

Retesting proves whether a patch successfully eliminated a vulnerability:
1. Developer remediates code in target API.
2. Security engineer navigates to the finding in SentinelX and clicks **Retest Finding**.
3. SentinelX re-executes the exact probe:
   - If server now returns `HTTP 403 Forbidden` on foreign resource request → Status updates: `OPEN` → `FIXED`.
   - If server still returns `HTTP 200 OK` → Status remains: `OPEN`.

---

## 10. Defensive Security & Containment

SentinelX is designed as a defense-oriented security tool:
- **SSRF Protection**: Target URLs must resolve to private IP addresses or explicit allowlist entries (`ALLOWED_TARGETS`). Scanner refuses to target arbitrary public IPs.
- **DoS Prevention**: Hard caps on request volumes (`max_requests_per_scan: 1000`, rate limit probe capped at 10 requests).
- **ORM Integrity**: SentinelX uses parameterized SQLAlchemy ORM exclusively for its own database, preventing self-injection flaws.

---

## 11. Quickstart & Running Locally

### Option A: Running with Docker Compose (Recommended)

```bash
# Clone the repository
git clone https://github.com/your-username/sentinelx.git
cd sentinelx

# Copy environment configuration
cp .env.example .env

# Build and start all 3 services
docker compose up --build
```

Access the services:
- **SentinelX Dashboard**: [http://localhost:5173](http://localhost:5173)
- **SentinelX Backend API**: [http://localhost:8000](http://localhost:8000) (Swagger at `/docs`)
- **VulnBank Target API**: [http://localhost:8001](http://localhost:8001) (Swagger at `/docs`)

---

### Option B: Running Locally (Development Mode)

#### 1. Start VulnBank API (Target)
```bash
cd vulnerable-api
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8001 --reload
```

#### 2. Start SentinelX Backend
```bash
cd backend
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

#### 3. Start React Dashboard
```bash
cd frontend
npm install
npm run dev
```

#### 4. Run Automated Tests
```bash
# Run VulnBank unit tests (verifies vulnerabilities exist)
python -m pytest vulnerable-api/tests -v

# Run SentinelX unit tests
python -m pytest backend/tests/unit -v

# Run full End-to-End VAPT Integration Scan
python -m pytest backend/tests/integration -v -s
```

---

## 12. Interview Guide: Answering Technical Questions

This section provides authoritative, code-backed answers to help you defend SentinelX during technical security interviews:

### Q1: What problem does SentinelX solve and why did you build it?
> *"Traditional DAST web scanners are designed for HTML web pages and struggle with APIs because they don't understand OpenAPI contracts, authentication flows, or object-level authorization. I built SentinelX to automate contract-driven API VAPT: it parses OpenAPI schemas, extracts parameters, performs differential behavioral testing for BOLA and SQLi, collects reproducible evidence, and supports instant retesting after remediation."*

### Q2: How does your BOLA / IDOR detection work under the hood?
> *"BOLA cannot be detected by status codes alone because both authorized and unauthorized requests might return HTTP 200. SentinelX logs in as User A and sends a baseline request to `/accounts/101`. Then it sends a test request to `/accounts/102` using the same bearer token. The `ResponseComparator` compares the responses. If the test response returns HTTP 200 and the JSON payload contains Bob's user ID or account number, SentinelX proves that object ownership wasn't checked on the server."*

### Q3: How do you distinguish a vulnerability from a false positive?
> *"We avoid single-indicator alerts. For SQL injection, we require database error signatures (e.g. SQLite syntax errors) or boolean tautology result set expansion compared to a benign baseline. For BOLA, we verify semantic ownership divergence. For authentication bypass, we require sensitive data to be returned anonymously. Every finding requires reproducible request/response evidence."*

### Q4: How does your severity scoring work?
> *"We use a transparent formula inspired by CVSS v3.1: Exploitability (weight 1.0 to 3.5) + Impact (weight 1.5 to 5.5), scaled by a Confidence factor (0.65 to 1.0). For example, BOLA is Easy to exploit (3.5) and has High impact (4.5) with High confidence (1.0), yielding a score of 8.0 (HIGH). We never arbitrarily mark everything Critical."*

### Q5: How do you prevent your scanner from causing Denial of Service (DoS)?
> *"We enforce strict client-side constraints. Rate limit tests are capped at 10 requests maximum with micro-delays between probes. Total requests per scan are capped at 1,000, and HTTP client timeouts are set to 10 seconds. The tool is designed for precision verification, not brute-force flooding."*

### Q6: How do you protect sensitive evidence?
> *"VAPT reports must not leak credentials. The `EvidenceCollector` passes headers and response bodies through sanitization filters before persisting them in SQLite. Bearer JWTs are redacted, and sensitive JSON fields (passwords, API keys) are masked (e.g. `ak_al1********`). Response bodies are truncated to 2KB to prevent memory exhaustion."*

### Q7: How does the retesting engine work?
> *"Each vulnerability module implements a `retest()` method. When the user remediates their code (for example, setting `VULNBANK_SECURE_MODE=true`), clicking Retest reruns that specific probe. If the foreign resource request now returns HTTP 403 Forbidden, the finding state transitions from `OPEN` to `FIXED`."*

---

## 13. Limitations & Roadmap

### Current Version Limitations
- Targets REST APIs with OpenAPI/Swagger 3.x specifications or common paths.
- Initial release uses SQLite (suitable for local/single-operator testing).
- GraphQL and gRPC testing are not currently supported.

### Version 2.0 Roadmap
- [ ] GraphQL schema introspection and query depth vulnerability checks.
- [ ] Automated CI/CD pipeline integration (GitHub Actions / GitLab CI scanner).
- [ ] Multi-tenant PostgreSQL database migration.
- [ ] Automated export to SARIF (Static Analysis Results Interchange Format) for GitHub Code Scanning integration.

---

## License

This project is licensed under the MIT License. Developed for educational, research, and authorized security testing purposes only.
