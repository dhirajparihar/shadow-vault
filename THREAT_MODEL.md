# ShadowVault Threat Model & Security Architecture

**Document Version:** 1.0.0  
**Target Release:** v0.4.0+  
**Status:** Published Security Reference  

---

## 1. Executive Summary & Security Objectives

ShadowVault is an open-source privacy proxy and de-identification engine designed specifically for **AI agent tool-calling workflows** and the **Model Context Protocol (MCP)**. 

Traditional PII masking tools were built for one-way static document redaction (e.g. substituting `[REDACTED]`). When applied to autonomous AI agents, static redaction crashes downstream tool validators (Stripe APIs, PostgreSQL queries, CRM lookups) because tools require schema-valid, reversible parameters.

ShadowVault's primary security objective is to **ensure that raw sensitive PII never reaches untrusted model context or third-party cloud LLMs**, while **guaranteeing that authorized local tools receive 100% valid, decrypted data** at trusted execution boundaries.

---

## 2. System Architecture & Trust Zones

```
+-------------------------------------------------------------------------------+
|                             TRUST ZONE 0: CLIENT                              |
|   End-User Prompt / Raw Input: "Refund $450 to alice@fintech.io on 4532..."   |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+===============================================================================+
|                   TRUST ZONE 1: SHADOWVAULT LOCAL BOUNDARY                    |
|                                                                               |
|  [ Inbound Prompt Scanner ]                                                   |
|   • Zero-ML Regex & Checksums (Luhn mod 10, Verhoeff D5)                     |
|   • Optional Presidio / spaCy NER for Named Entities                          |
|                                                                               |
|  [ Vault Storage & Cryptography ]                                             |
|   • AES-256-GCM Authenticated Encryption at Rest (128-bit MAC tag)           |
|   • HMAC-SHA256 Session-Scoped Blind Indexing                                 |
|   • Auto-pruning TTL eviction                                                 |
|                                                                               |
|  [ Tool Policy Manager & Fail-Closed Gatekeeper ]                              |
|   • ToolPolicy whitelist / blacklist enforcement                              |
|   • PIILeakBlockedError prevention on tool returns                            |
+===============================================================================+
          |                                                   ^
          | (Outbound: Dehydrated Wire Payload)               | (Local Stdio JSON-RPC)
          | "Refund $450 to u_c09@shadow.vault..."            |
          v                                                   v
+-----------------------------------------+   +---------------------------------+
|     TRUST ZONE 2: UNTRUSTED CLOUD      |   |   TRUST ZONE 1: LOCAL TOOL      |
|  Cloud LLM (OpenAI, Anthropic, etc.)    |   |  Local MCP Server / Tool Guard  |
|  Prompt loggers (LangSmith, Helicone)   |   |  • Restored real card/email     |
|  Synthetic tokens ONLY                  |   |  • Executes refund securely     |
+-----------------------------------------+   +---------------------------------+
```

### Trust Boundary Definitions

| Zone | Component | Trust Level | Description |
|:---|:---|:---:|:---|
| **Zone 0** | Client / End-User | **Trusted** | Origin of sensitive prompt or data. |
| **Zone 1** | ShadowVault Engine & Local Tools | **Guarded / Trusted** | Local Python runtime or MCP stdio process. Has access to encryption keys and local database. |
| **Zone 2** | Cloud LLM / Upstream Network | **Untrusted** | Third-party cloud providers, model training pipelines, intermediate proxies, and cloud observability platforms. |

---

## 3. Attacker Persona & Threat Matrix

| Threat ID | Threat Vector | Attacker Objective | ShadowVault Countermeasure | Mitigation Level |
|:---|:---|:---|:---|:---:|
| **T-01** | **Cloud Model Context Harvesting** | Provider retains prompts for training; logs leaked in cloud observability. | Prompt is sanitized with format-preserving synthetic tokens (`u_c09@shadow.vault`). | **Prevented** |
| **T-02** | **Prompt Injection / Jailbreak** | Attacker prompts the model to output reverse mapping keys or extract original PII. | Model never receives real PII or vault keys; synthetic tokens are decoupled from secret keys. | **Prevented** |
| **T-03** | **Database Dumper (Cold Storage Leak)** | Malicious insider dumps SQLite database file (`.db`). | All `real_val` entries are encrypted with AES-256-GCM; blind index uses keyed HMAC-SHA256. | **Prevented** |
| **T-04** | **Ciphertext Bit-Flipping / Tampering** | Attacker tampers with stored ciphertext in database. | AES-256-GCM 128-bit authentication tag rejects altered bits with immediate `ValueError`. | **Prevented** |
| **T-05** | **Cross-Tenant / Cross-Session Hijack** | Tenant A passes a synthetic token attempting to hydrate Tenant B's data. | Session-scoped namespaces; tokens can only hydrate within the matching `session_id`. | **Prevented** |
| **T-06** | **Rogue Tool Data Exfiltration** | An untrusted agent tool (e.g. `post_to_slack`) attempts to leak raw credit cards. | `ToolPolicy` allows fine-grained entity whitelisting or blocks hydration entirely (`allow_hydration=False`). | **Prevented** |
| **T-07** | **Tool Return PII Leakage** | A compromised tool returns unmasked raw PII in its response JSON. | In fail-closed mode, `PIILeakBlockedError` blocks outbound leak, or engine re-dehydrates result. | **Prevented** |
| **T-08** | **SSE Stream Token Tearing** | Cloud model streams tokens across chunk boundaries, leaking split characters. | `StreamHydrator` lookahead buffer delays output until synthetic tokens are fully reassembled. | **Prevented** |
| **T-09** | **Frequency Analysis / Entropy Probe** | Attacker correlates synthetic token frequencies across multiple sessions. | Nonces and BLAKE2b/HMAC session salts generate distinct tokens for identical inputs across sessions. | **Prevented** |
| **T-10** | **Host Memory Dump** | Attacker with local root/OS access dumps Python RAM. | Out of scope for application-level library. Requires OS-level full-disk encryption and enclave isolation. | **Out of Scope** |
| **T-11** | **Application Log Pollution / Trace Leaks** | Developer or tool accidentally executes `logger.info(real_card)` post-hydration. | `VaultLogFilter` intercepts log records and scrubs real PII to synthetic tokens before hitting disk or sinks. | **Prevented** |
| **T-12** | **Lingering Stale PII in Abandoned Sessions** | Unpurged mapping entries persist indefinitely in SQLite memory. | Enforced 3,600s default TTL (`DEFAULT_TTL_SECONDS`) and `with vault.session(..., auto_purge=True)` context lifecycle. | **Prevented** |

---

## 4. Cryptographic Guarantees & Implementation

### 4.1 Authenticated Encryption (AEAD)
- **Primary Cipher:** AES-256-GCM (`cryptography.hazmat.primitives.ciphers.aead.AESGCM`).
- **Key Derivation:** HKDF-SHA256 with 256-bit derived key or direct 256-bit key material.
- **Nonce/IV:** 96-bit cryptographically secure pseudorandom nonce generated per encryption (`os.urandom(12)`). Nonces are prepended to the ciphertext and never reused with the same key.
- **Authentication Tag:** 128-bit MAC tag verified prior to any plaintext release. Any modified byte aborts execution with a strict `ValueError`.
- **Pure-Python Fallback:** When `cryptography` is omitted, ShadowVault uses BLAKE2b in counter mode with HMAC-SHA256 authenticated envelope encryption.

### 4.2 Cryptographic Blind Indexing
To permit $O(1)$ equality lookups without storing plaintext lookup keys, ShadowVault implements **HMAC-SHA256 blind indexing**:
$$\text{Index} = \text{HMAC-SHA256}(K_{\text{enc}}, \text{session\_id} \parallel \text{":\!"} \parallel \text{real\_val})$$
- Anyone inspecting the database sees only a 64-character hexadecimal digest.
- Without knowledge of $K_{\text{enc}}$, the blind index cannot be inverted or correlated across sessions.

### 4.3 Fail-Closed Governance
When `fail_closed=True` is enabled:
1. Encountering an unmapped, expired, or tampered synthetic token at a tool boundary immediately triggers `FailClosedAction.RAISE` (`UnmappedTokenError`) or `FailClosedAction.REDACT`.
2. Outbound payloads returning from tools are re-scanned. If raw unmasked PII is detected, `PIILeakBlockedError` halts transmission.

---

## 5. Explicit Limitations & Boundaries

To ensure radical transparency, the following constraints are documented:

1. **Unstructured Named Entities (Person Names):**
   The zero-dependency core engine focuses on deterministic, checksum-validated identifiers (Cards, PAN, Aadhaar, SSN, UPI, Email, Phone, API Keys). Unstructured Person names require the optional Presidio/spaCy NER adapter (`pip install "shadow-vault[presidio]"`).
2. **Length & Type Preservation:**
   Format-preserving tokens intentionally maintain length and structural validity (e.g. 16-digit credit cards). While the value is synthetic, an observer can deduce that the field represents a payment card.
3. **In-Process Key Residency:**
   Encryption keys reside in Python process memory while the application is running. Defense against malicious memory dumpers requires OS-level process isolation (e.g., containerization, non-root users, or Confidential Computing enclaves).
4. **Persistent Vault Key Requirement:**
   When using a persistent SQLite file (`db_path != ":memory:"`), setting an encryption key via `encryption_key` or `SHADOW_VAULT_KEY` is strongly recommended. ShadowVault emits a prominent `UserWarning` if a persistent file database is initialized without encryption.

---

## 6. Security Audit & Verification

ShadowVault includes an automated, self-verifying test suite that executes across Python 3.10, 3.11, 3.12, and 3.13.

To run the complete adversarial security evaluation:
```bash
python -m pytest tests/test_adversarial_security.py -v
```

To run the full reproducible verification suite:
```bash
python -m shadow_vault.verify
```
