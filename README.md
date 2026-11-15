# CYBERSHIELD — Web Vulnerability Scanner as a Service (v4.0)

CyberShield is a full-stack, enterprise-grade web vulnerability scanner and threat intelligence platform built with **Next.js 16 (Turbopack) + React 19 + Tailwind CSS**.

Engineered with a **"Safe by Design"** philosophy, CyberShield focuses on abuse prevention, anti-SSRF perimeter isolation, authorization attestations for active scans, and human-in-the-loop workflows with confidence ratings.

---

## 🛡️ Architecture & Threat Model

### 1. Two-Tier Scan Model (Intrusiveness Separation)

| Scan Tier | Scope & Intrusiveness | Target Prerequisites | Checks Performed |
|---|---|---|---|
| **Basic Tier** | **Passive & Non-Intrusive**<br>(Equivalent to standard browser inspection) | Any non-denylisted target | • **Security Headers:** HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy<br>• **TLS/SSL Handshake:** TLS 1.3/1.2 validation, cipher suites, certificate authority chain, expiry countdown, SHA-256 fingerprint<br>• **Cookie Isolation:** `Secure`, `HttpOnly`, `SameSite`<br>• **Supply Chain & Scripts:** Subresource Integrity (SRI) on 3rd-party scripts, mixed content audit, known-vulnerable JS libraries (jQuery, Bootstrap, AngularJS, Lodash)<br>• **DNS & Email Posture:** SPF, DMARC, and MX records<br>• **Information Leakage:** Server banners, `robots.txt`, and RFC 9116 `security.txt`<br>• **OWASP Top 10 (2021)** compliance matrix |
| **Deep Tier** | **Active Probing & Exploit Indicators**<br>(Safe non-destructive canary payloads) | **Signed Legal Scope Attestation** | • **Reflected XSS:** Non-executable canary tokens injected into query parameters<br>• **Open Redirects:** Destination validation against external probes<br>• **SQL Injection:** Safe single-quote syntax anomaly detection (non-destructive)<br>• **Sensitive File Exposure:** `.env`, `.git/HEAD`, `phpinfo.php`, and administrative panels<br>• **Active CORS:** Origin reflection and credential theft probes<br>• **Authentication Hygiene:** Rate-limiting detection on login endpoints |

---

### 2. Abuse Prevention & Target Authorization

- **High-Profile Denylist:** Scanning high-profile domains (e.g., `google.com`, `apple.com`, `gov.in`, critical infrastructure) is automatically blocked.
- **Legal Attestation & Scope Agreement:** Deep scans require an explicit checkbox confirming authorization and scope before active tests can run.
- **Abuse Controls:** Target rate-limiting, concurrency caps, and kill-switch capabilities.

---

### 3. Platform Self-Defense (Anti-SSRF & Sandboxing)

- **Pre-Resolution SSRF Shield:** Resolves DNS before dispatching HTTP requests and verifies that the destination IP does not belong to loopback (`127.0.0.1`), RFC 1918 private subnets (`10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`), link-local, or cloud metadata endpoints (`169.254.169.254`), neutralizing DNS rebinding attacks.
- **Hostile Response Sanitization:** All untrusted target responses, error snippets, and banners are escaped before DOM insertion to neutralize stored XSS attacks targeting SecOps analysts.
- **Non-Destructive Payloads:** Detection probes exclusively inspect reflection and syntax errors; strictly zero `DROP`, `UPDATE`, `exec()`, or data modifications.

---

### 4. Human-in-the-Loop & Standing Out

- **Confidence Levels:** Eliminates false positive fatigue by tagging every finding with:
  - `Confirmed`: Cryptographically or mathematically proven flaw.
  - `Likely`: Strong heuristic indicators detected.
  - `Needs Human Verification`: Complex state requiring manual inspection.
- **Guided Manual Tester Checklist:** Context-aware prompts for manual testers covering business logic flaws, 2-account IDOR validation, race conditions with safe bursts, and session fixation.
- **Actionable Remediation:** Code snippets for Nginx, Apache, Cloudflare, Next.js, and Caddy.
- **Dual Audiences:** Instant toggle between **Executive Summary** (plain English for leadership) and **Technical Detail** (for engineers).
- **DevSecOps Integration:** Export reports in standard JSON, Executive Markdown, and **SARIF 2.1.0** (Static Analysis Results Interchange Format) for direct integration into GitHub Security and CI/CD pipelines.

---

## 💻 Running Locally

### 1. Install Dependencies
```bash
npm install
```

### 2. Start the Development Server
```bash
npm run dev
```

Visit [http://localhost:3000](http://localhost:3000) in your web browser.

### 3. Run the Automated Test Suite
```bash
npm test
```

This runs the existing security and verification tests plus exactly five Basic ZAP checks and five Deep ZAP checks. The ten ZAP unit tests verify alert grouping and test configuration; they do not send scan traffic to a target. The live scanner runs only when you start a scan from the website.
