# Security Policy

## Supported Versions

Security updates and patches are actively applied to the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.4.x   | :white_check_mark: |
| < 0.4.0 | :x:                |

---

## Reporting a Vulnerability

We take the security of ShadowVault and the applications relying on it seriously. If you discover a security vulnerability, please do **NOT** open a public issue.

### Reporting Procedure

1. **Email:** Report findings privately to `dhirajparihar.dev@gmail.com` (or create a Private Vulnerability Report via GitHub Security Advisories).
2. **Subject Line:** `[Vulnerability Report] ShadowVault: <Brief Description>`
3. **Details to Include:**
   - Detailed description of the vulnerability.
   - Proof-of-concept (PoC) code or reproducible steps.
   - Affected versions, OS, and Python versions.
   - Potential impact (e.g. data leak, bypass of fail-closed policy, denial-of-service).

### Response SLA

- **Acknowledgment:** Within 24 hours.
- **Initial Assessment & Reproduction:** Within 48 hours.
- **Fix & Advisory Release:** Within 7 business days depending on complexity.

We will acknowledge your contribution in the security release notes (unless you prefer to remain anonymous).

---

## Security Architecture & Threat Model

For full details on ShadowVault's cryptographic design, trust boundaries, and threat mitigation matrix, consult [THREAT_MODEL.md](file:///c:/Users/HP/Desktop/projectios/shadow-vault/THREAT_MODEL.md).
