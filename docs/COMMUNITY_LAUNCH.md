# 🚀 ShadowVault Community Launch & Distribution Pack

This document contains ready-to-use launch drafts, ecosystem PR submissions, and community announcements to drive adoption, GitHub stars, and independent validation for **ShadowVault**.

---

## 1. Hacker News — "Show HN" Submission

### Title:
> **Show HN: ShadowVault – Zero-leak reversible PII protection for AI agents (zero-deps core)**

### URL:
> `https://github.com/dhirajparihar/shadow-vault`

### Text / First Comment:
```markdown
Hi HN! I built ShadowVault (https://github.com/dhirajparihar/shadow-vault) because existing PII tools break AI agent workflows.

When you use traditional anonymizers (like Presidio or redactors):
1. They redact data irreversibly (e.g., `<EMAIL>` or `[REDACTED]`), so downstream tools (like Stripe or database queries) cannot execute.
2. They generate generic placeholders that fail downstream validator checks (e.g. invalid Luhn credit cards or invalid checksum IDs).
3. When streaming over Server-Sent Events (SSE), synthetic tokens get split across chunk boundaries, causing torn artifacts or token leaks.

ShadowVault is a bi-directional, format-preserving reversible PII layer built specifically for AI agents, LangChain/LangGraph, and Model Context Protocol (MCP) servers:

- **Format-Preserving Tokens**: Synthetic cards pass Luhn Mod-10, Indian Aadhaar numbers pass Verhoeff D5, emails match RFC 5322. Downstream LLM schema validators never fail.
- **Zero Tool Code Changes**: Add `@vault_guard` to any Python function or MCP tool. The LLM sees only synthetic tokens; your local tool executes with genuine PII.
- **Torn Stream Reassembly**: An atomic lookahead sliding holdback buffer buffers partial token candidates across streaming SSE micro-chunks without leaking.
- **AEAD Vault at Rest**: Token-to-PII mappings are encrypted with AES-256-GCM and indexed with deterministic HMAC blind indexes.
- **Zero-Dependency Core**: Pure standard library (`sqlite3`, `hmac`, `hashlib`, `re`). Hardware-accelerated `cryptography` is optional.
- **Independent Self-Audit**: Run `shadow-vault verify` or `python -m shadow_vault.verify` to verify 6 cryptographic and privacy checks in real-time.

You can try it directly in Google Colab without installing anything:
https://colab.research.google.com/github/dhirajparihar/shadow-vault/blob/main/notebooks/shadow_vault_quickstart.ipynb

GitHub repo: https://github.com/dhirajparihar/shadow-vault
Threat Model & Security Policy: https://github.com/dhirajparihar/shadow-vault/blob/main/THREAT_MODEL.md

Would love to hear your thoughts, feedback on our threat model, and edge cases we should test!
```

---

## 2. Awesome Lists Pull Request Submissions

### A. Submission to `punkpeye/awesome-mcp-servers`
- **File**: `README.md`
- **Category**: `Security & Privacy` or `Gateways / Proxies`
- **Entry**:
```markdown
- [ShadowVault](https://github.com/dhirajparihar/shadow-vault) - Transparent bi-directional PII masking proxy for MCP stdio and HTTP tool servers with authenticated AES-256-GCM encryption and format-preserving tokens.
```

### B. Submission to `kyrolabs/awesome-langchain`
- **File**: `README.md`
- **Category**: `Tools & Utilities` / `Privacy & Security`
- **Entry**:
```markdown
- [ShadowVault](https://github.com/dhirajparihar/shadow-vault) - Bi-directional format-preserving reversible PII protection for LangChain chat models, agents, and LangGraph checkpoint states.
```

### C. Submission to `tensorchord/Awesome-LLMOps`
- **Category**: `Privacy & Guardrails`
- **Entry**:
```markdown
- [ShadowVault](https://github.com/dhirajparihar/shadow-vault) - Zero-leak reversible privacy layer for AI agent tool calls with format-preserving checksums and SSE streaming reassembly.
```

---

## 3. Reddit Post: `r/LocalLLaMA` & `r/LangChain`

### Title:
> **I built an open-source zero-leak reversible PII proxy for AI agents and MCP tools (82 passing tests, format-preserving tokens, Colab demo)**

### Body:
```markdown
Hey everyone!

One of the biggest blockers to deploying AI agents in production (especially healthcare, fintech, and enterprise support) is sending raw customer PII to cloud LLMs.

Traditional anonymization tools don't work well for agents because:
1. Irreversible redaction (`[REDACTED]`) breaks tool execution. If an agent needs to refund an order, it doesn't have the real card or email.
2. In-memory maps break when agents stream tokens or run multi-turn graphs.
3. Random UUIDs fail downstream schema validators that expect valid credit cards or formatted IDs.

To solve this, I built **ShadowVault** (MIT License, pure Python core):
👉 GitHub: https://github.com/dhirajparihar/shadow-vault
👉 1-Click Colab: https://colab.research.google.com/github/dhirajparihar/shadow-vault/blob/main/notebooks/shadow_vault_quickstart.ipynb

### Key Features:
- **Format-Preserving Checksums**: Synthetic cards pass Luhn Mod-10, Aadhaar numbers pass Verhoeff D5, emails match RFC 5322. The LLM reasons over realistic data without schema errors.
- **Bi-Directional Tool Restoration**: Wrap local tools in `@vault_guard`. The agent passes synthetic tokens over the wire, but your tool receives the real decrypted PII locally.
- **Streaming SSE Holdback Buffer**: Eliminates torn-token leaks across OpenAI/Anthropic streaming chunks.
- **MCP Stdio Gateway**: Transparently wraps any downstream Model Context Protocol server (`shadow-vault mcp-proxy -- uvx mcp-server-sqlite`).
- **Cryptographic Security**: AES-256-GCM authenticated encryption + blind HMAC indexes.
- **Built-in Verification**: Comes with `shadow-vault verify` for independent reproducible self-auditing.

Check it out, star the repo if you find it helpful, and let me know what other entity types or integrations you'd like to see!
```

---

## 4. X (Twitter) Launch Thread

**Tweet 1 (Hook):**
> Introducing ShadowVault ⚡: A bi-directional, format-preserving reversible PII layer for AI agents, LangChain, and MCP tools.
> 
> Keep 100% of sensitive PII out of cloud LLMs while allowing local tools to execute with genuine values.
> 
> 🧵👇 (Open Source & 1-Click Colab below)
> https://github.com/dhirajparihar/shadow-vault

**Tweet 2 (The Problem):**
> Why do standard anonymizers fail with AI agents?
> 
> 1. Redaction `<REDACTED>` breaks downstream tool calls (Stripe can't charge `[CARD]`).
> 2. Fake tokens fail regex & checksum validators.
> 3. SSE streaming tears tokens across micro-chunks, leaking sensitive bytes.

**Tweet 3 (The Solution):**
> ShadowVault solves all three:
> 
> 💳 Format-preserving: Synthetic cards pass Luhn, Aadhaar passes Verhoeff.
> 🛡️ `@vault_guard`: Intercepts tool calls and restores genuine PII inside your local perimeter.
> 🌊 StreamHydrator: Lookahead holdback buffer reassembles torn tokens across SSE streams.

**Tweet 4 (Zero-Dependency & Security):**
> Best of all:
> 📦 Pure Python standard library core (no heavy ML bloat required)
> 🔐 AES-256-GCM authenticated vault encryption + HMAC blind indexes
> 🧪 82 adversarial test cases + reproducible self-audit CLI (`shadow-vault verify`)

**Tweet 5 (Try it):**
> Try the 1-click interactive demo right in your browser:
> https://colab.research.google.com/github/dhirajparihar/shadow-vault/blob/main/notebooks/shadow_vault_quickstart.ipynb
> 
> Star on GitHub: https://github.com/dhirajparihar/shadow-vault ⭐
```
