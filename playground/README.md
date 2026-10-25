# 🛡️ ShadowVault Interactive Web Playground

A real-time interactive Streamlit web application demonstrating format-preserving, bi-directional PII masking and re-hydration for AI agents, LangChain/LangGraph, and Model Context Protocol (MCP) tools.

---

## Live 3-Panel Architecture

When you click **"⚡ Run Agent Turn"**, the playground displays:

- **Panel 1 (User & Local MCP Tool)**: Shows the raw input with real PII highlighted in red, and demonstrates `@vault_guard` hydrating real values right before invoking the local private Stripe, SQL, or EHR tool.
- **Panel 2 (What Cloud LLMs See)**: Highlights every format-preserving synthetic token (`@shadow.vault`, `SHDWV...`, `4000...`, `sk-sv-...`) in green, proving zero sensitive data leaves the perimeter while preserving full schema validation.
- **Panel 3 (Live Ephemeral SQLite Vault)**: Shows the active session mapping table with deterministic BLAKE2b hashes, TTL countdowns, and sub-millisecond latency counters.

---

## 3 Pre-Loaded Scenarios

1. **Fintech UPI/PAN Refund Agent**: Credit card chargebacks, Indian PAN numbers (`ABCDE1234F`), and UPI handles (`@okaxis`).
2. **Healthcare Patient Booking Agent**: HIPAA patient booking with SSNs (`123-45-6789`) and Indian Aadhaar UIDs (`3675 9834 6015`) passing Verhoeff validation.
3. **DevOps API Key Log Analyzer**: Autonomous SRE triage with engineer email/phone contacts and live API tokens (`sk-proj-...`).

---

## How to Run Locally

```bash
# 1. Install dependencies
pip install -r playground/requirements.txt
pip install -e .

# 2. Launch Streamlit playground
streamlit run playground/app.py
```

---

## Deploy to Hugging Face Spaces (Free)

1. Create a new Space on [Hugging Face](https://huggingface.co/new-space).
2. Set **Space SDK** to `Streamlit`.
3. Set **License** to `MIT`.
4. Upload `playground/app.py` as `app.py` and `playground/requirements.txt` as `requirements.txt`.
5. Hugging Face Spaces will automatically build and host the live interactive demo at `https://huggingface.co/spaces/<your-username>/shadow-vault`.

---

## Deploy to Render (Free Web Service)

1. Create a new Web Service on [Render](https://dashboard.render.com/).
2. Connect your GitHub repository: `https://github.com/dhirajparihar/shadow-vault`.
3. Configure settings:
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r playground/requirements.txt && pip install -e .`
   - **Start Command**: `streamlit run playground/app.py --server.port $PORT --server.address 0.0.0.0 --server.headless true`
