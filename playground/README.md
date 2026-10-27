# 🛡️ ShadowVault Interactive Web Playground

A standalone, zero-dependency client-side web application demonstrating format-preserving, bi-directional PII masking and re-hydration for AI agents, LangChain/LangGraph, and Model Context Protocol (MCP) tools.

Hosted live on GitHub Pages: [https://dhirajparihar.github.io/shadow-vault/](https://dhirajparihar.github.io/shadow-vault/)

---

## Architecture & Features

- **Zero Server Trust**: Executes entirely in the user's browser runtime. Zero external API calls, zero server telemetry, and 100% uptime on GitHub CDN.
- **Panel 1 (User & Local Tool Boundary)**: Highlights detected raw PII locally in red and verifies `@vault_guard` restoring real values before local tools execute.
- **Panel 2 (What Cloud LLMs See)**: Highlights format-preserving synthetic `@shadow.vault` tokens in green, verifies mathematical checksums (Luhn Mod 10, Verhoeff D5, PAN, Email), and animates token streaming re-hydration.
- **Panel 3 (Live Ephemeral SQLite Vault)**: Inspects the live session reverse mapping table, authenticated AES-256-GCM cipher hashes, and sub-millisecond execution latency counters.

---

## 3 Pre-Loaded Scenarios

1. **Fintech UPI/PAN Refund Agent**: Credit card chargebacks, Indian PAN numbers (`ABCDE1234F`), and UPI handles (`@okaxis`).
2. **Healthcare Patient Booking Agent**: HIPAA patient booking with SSNs (`123-45-6789`) and Indian Aadhaar UIDs (`3675 9834 6015`) passing Verhoeff validation.
3. **DevOps API Key Log Analyzer**: Autonomous SRE triage with engineer email/phone contacts and live API tokens (`sk-proj-...`).

---

## Local Development

Simply open `playground/index.html` in any modern web browser or serve it with Python's built-in HTTP server:

```bash
python -m http.server 8000 --directory playground
```

Then visit `http://localhost:8000` in your browser.
