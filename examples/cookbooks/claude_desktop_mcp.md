# Cookbook: Securing Claude Desktop & Cursor with ShadowVault MCP Gateway

This cookbook demonstrates how to wrap **any** Model Context Protocol (MCP) server with ShadowVault so that Anthropic's Claude Desktop or Cursor never sees raw customer credentials, while your local tools and databases execute with real data.

---

## The Problem

When using Claude Desktop or Cursor with MCP servers (such as SQLite, PostgreSQL, Stripe, or GitHub), raw sensitive data (credit cards, API keys, customer emails, SSNs) is passed directly into Claude's prompt context over the wire. This can violate **SOC2**, **HIPAA**, and **PCI-DSS** compliance.

Traditional redaction (e.g. replacing cards with `[REDACTED]`) breaks MCP tools because SQL queries and API endpoints fail strict schema validations.

---

## The Solution: ShadowVault Transparent Stdio Gateway

ShadowVault operates as a transparent Stdio JSON-RPC proxy sitting between Claude Desktop and downstream MCP servers:

```
+--------------------+                     +--------------------+                     +--------------------+
|   Claude Desktop   |  --- Stdio (JSON) -> |    ShadowVault     |  --- Stdio (JSON) -> |   Target Server    |
|   (Model Context)  |  <- Synthetic PII -- |     mcp-proxy      |  <- Real Restored -- |   (mcp-server-db)  |
+--------------------+                     +--------------------+                     +--------------------+
```

1. **Inbound to Tool:** When Claude dispatches `tools/call` with synthetic tokens (e.g. `card: "4000009995970590"`), ShadowVault intercepts the JSON-RPC call and restores real data (`"4532 0151 1283 0366"`).
2. **Outbound to Claude:** When the tool returns data (e.g. query results containing emails or phones), ShadowVault re-dehydrates them into format-preserving synthetic tokens before returning to Claude.

---

## 60-Second Setup Guide

### 1. Install ShadowVault

Install `shadow-vault` into your global or local environment:

```bash
pip install shadow-vault
```

Ensure the CLI is in your PATH:
```bash
shadow-vault --help
```

---

### 2. Configure Claude Desktop

Open your Claude Desktop configuration file:
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux:** `~/.config/Claude/claude_desktop_config.json`

Add ShadowVault as the gateway command before your target MCP server:

```json
{
  "mcpServers": {
    "secure-customer-db": {
      "command": "shadow-vault",
      "args": [
        "mcp-proxy",
        "--session-id", "claude_desktop_main",
        "--fail-closed",
        "--",
        "uvx", "mcp-server-sqlite", "--db", "/path/to/customers.db"
      ],
      "env": {
        "SHADOW_VAULT_KEY": "your-master-aes256-encryption-key"
      }
    }
  }
}
```

#### What each flag does:
- `mcp-proxy`: Launches the high-performance Stdio JSON-RPC interceptor.
- `--session-id <id>`: Scopes reverse-mapping tables to the current Claude session.
- `--fail-closed`: Rejects unmapped or expired synthetic tokens, preventing data corruption.
- `--`: Separates ShadowVault arguments from the downstream MCP server command.
- `SHADOW_VAULT_KEY`: Enables authenticated AES-256-GCM encryption for all session mappings at rest.

---

### 3. Example Execution Trace

#### Step 1: User asks Claude Desktop
> *"Search our database for customer alice@fintech.io and charge their card 4532 0151 1283 0366 for invoice #104."*

#### Step 2: What Claude Desktop sees in context
```json
{
  "method": "tools/call",
  "params": {
    "name": "lookup_and_charge",
    "arguments": {
      "customer_email": "u_c09753@shadow.vault",
      "card_number": "4000009995970590",
      "invoice_id": "104"
    }
  }
}
```
*Claude's model context contains only valid, format-preserving synthetic tokens passing Luhn Modulo 10 checks.*

#### Step 3: What the local SQLite MCP Server executes
```sql
SELECT * FROM customers WHERE email = 'alice@fintech.io';
-- Process payment with real card: 4532 0151 1283 0366
```

#### Step 4: What is returned to Claude Desktop
```json
{
  "status": "SUCCESS",
  "receipt": "Invoice #104 charged to 4000009995970590. Receipt emailed to u_c09753@shadow.vault."
}
```

---

## Cursor IDE Setup

For Cursor, open `.cursor/mcp.json` in your project root:

```json
{
  "mcpServers": {
    "secure-fetch": {
      "command": "shadow-vault",
      "args": [
        "mcp-proxy",
        "--session-id", "cursor_dev",
        "--",
        "uvx", "mcp-server-fetch"
      ]
    }
  }
}
```

Now Cursor can fetch external documentation or web APIs without leaking confidential customer identifiers stored in your workspace.
