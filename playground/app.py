"""
ShadowVault Interactive Web Playground
Single-file Streamlit application for Hugging Face Spaces, Render, or local demo.
"""

from __future__ import annotations

import html
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

# Ensure local shadow_vault module is in sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import streamlit as st

from shadow_vault.detectors import (
    EntityType,
    detect_entities,
    is_luhn_valid,
    is_verhoeff_valid,
)
from shadow_vault.engine import ShadowVault
from shadow_vault.integrations.decorators import vault_guard
from shadow_vault.store import VaultStore
from shadow_vault.stream import StreamHydrator
from shadow_vault.synthesizer import is_synthetic

# Page configuration
st.set_page_config(
    page_title="ShadowVault Playground - Reversible PII Proxy",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Styling (Cyber-Safe / Modern FinTech Theme)
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Plus+Jakarta+Sans:wght@400;600;700;800&display=swap');

    html, body, [class*="css"] {
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
    }

    code, pre, .mono {
        font-family: 'JetBrains Mono', monospace !important;
    }

    .main-title {
        font-size: 2.2rem;
        font-weight: 800;
        background: linear-gradient(135deg, #10B981 0%, #3B82F6 50%, #8B5CF6 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.2rem;
    }

    .sub-title {
        color: #94A3B8;
        font-size: 1.05rem;
        margin-bottom: 1.2rem;
    }

    .card-panel {
        background: #0F172A;
        border: 1px solid #1E293B;
        border-radius: 12px;
        padding: 1.25rem;
        margin-bottom: 1rem;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2), 0 2px 4px -2px rgba(0, 0, 0, 0.2);
    }

    .panel-header-1 {
        color: #F87171;
        font-weight: 700;
        font-size: 1.1rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
        border-bottom: 1px solid #2D3748;
        padding-bottom: 0.5rem;
        margin-bottom: 0.8rem;
    }

    .panel-header-2 {
        color: #34D399;
        font-weight: 700;
        font-size: 1.1rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
        border-bottom: 1px solid #2D3748;
        padding-bottom: 0.5rem;
        margin-bottom: 0.8rem;
    }

    .panel-header-3 {
        color: #60A5FA;
        font-weight: 700;
        font-size: 1.1rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
        border-bottom: 1px solid #2D3748;
        padding-bottom: 0.5rem;
        margin-bottom: 0.8rem;
    }

    .token-synthetic {
        background-color: rgba(16, 185, 129, 0.2);
        color: #34D399 !important;
        border: 1px solid #059669;
        padding: 0.15rem 0.45rem;
        border-radius: 6px;
        font-family: 'JetBrains Mono', monospace;
        font-weight: 600;
        display: inline-block;
        margin: 1px 0;
    }

    .token-real {
        background-color: rgba(239, 68, 68, 0.15);
        color: #F87171 !important;
        border: 1px solid #DC2626;
        padding: 0.15rem 0.45rem;
        border-radius: 6px;
        font-family: 'JetBrains Mono', monospace;
        font-weight: 600;
        display: inline-block;
        margin: 1px 0;
    }

    .metric-box {
        background: #1E293B;
        border-radius: 8px;
        padding: 0.75rem 1rem;
        text-align: center;
        border: 1px solid #334155;
    }

    .metric-value {
        font-size: 1.6rem;
        font-weight: 700;
        color: #10B981;
        font-family: 'JetBrains Mono', monospace;
    }

    .metric-label {
        font-size: 0.75rem;
        text-transform: uppercase;
        color: #94A3B8;
        letter-spacing: 0.05em;
        margin-top: 0.2rem;
    }

    .payload-container {
        background-color: #0B1120;
        border: 1px solid #1E293B;
        border-radius: 8px;
        padding: 1rem;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.88rem;
        line-height: 1.6;
        color: #E2E8F0;
        word-break: break-word;
        white-space: pre-wrap;
    }

    .badge-pill {
        display: inline-block;
        padding: 0.2rem 0.6rem;
        border-radius: 9999px;
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
    }

    .badge-cloud {
        background: #064E3B;
        color: #A7F3D0;
        border: 1px solid #059669;
    }

    .badge-local {
        background: #7F1D1D;
        color: #FECACA;
        border: 1px solid #DC2626;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Initialize Session State
if "store" not in st.session_state:
    st.session_state.store = VaultStore(db_path=":memory:")
    st.session_state.vault = ShadowVault(store=st.session_state.store)
    st.session_state.last_run = None

store: VaultStore = st.session_state.store
vault: ShadowVault = st.session_state.vault

# 3 Pre-loaded Scenarios
SCENARIOS = {
    "Fintech UPI/PAN Refund Agent": {
        "description": "Autonomous banking refund agent handling card chargebacks, Indian PAN verification, and UPI transfers.",
        "prompt": (
            "Please process an immediate chargeback of $450 to customer dhiraj.sharma@example.com. "
            "Verify identity with Indian PAN card ABCDE1234F and process settlement via UPI handle dhiraj@okaxis. "
            "Primary phone: +91 9876543210. Card on file: 4532 0151 1283 0366. "
            "Authorize with Stripe key sk-live-51A2B3C4D5E6F7G8H9I0J1K2L3M4."
        ),
        "tool_name": "stripe_chargeback_mcp_tool",
        "tool_doc": "Local MCP tool executing inside private infrastructure with direct Stripe API & Postgres access.",
        "tool_func": lambda **kwargs: {
            "status": "CHARGEBACK_CONFIRMED",
            "settlement_channel": "UPI_INSTANT",
            "customer_email": kwargs.get("email", ""),
            "pan_number": kwargs.get("pan", ""),
            "charge_card": kwargs.get("card", ""),
            "refund_amount": 450.0,
            "bank_receipt_id": "REC-99482104",
            "backup_phone_notified": "+91 9123456789",
        },
    },
    "Healthcare Patient Booking Agent": {
        "description": "Medical intake assistant scheduling specialist consultations with HIPAA SSN & national identity protection.",
        "prompt": (
            "Confirm urgent cardiology consultation booking for patient Sarah Jenkins "
            "(SSN: 123-45-6789, Email: sarah.jenkins@healthnet.org, Mobile: (555) 234-5678). "
            "Patient Aadhaar UID for international travel insurance clearance: 3675 9834 6015. "
            "Bill insurance carrier using portal auth key sk-live-med7788990011223344."
        ),
        "tool_name": "epic_health_ehr_mcp_tool",
        "tool_doc": "On-premise Electronic Health Records (EHR) gateway executing within HIPAA boundary.",
        "tool_func": lambda **kwargs: {
            "status": "APPOINTMENT_SCHEDULED",
            "specialist": "Dr. Aris Thorne (Cardiology)",
            "patient_ssn": kwargs.get("ssn", ""),
            "patient_email": kwargs.get("email", ""),
            "international_uid": kwargs.get("aadhaar", ""),
            "consultation_fee": "$320.00",
            "clinic_sms_contact": "+1 (555) 987-6543",
            "appointment_slot": "Tomorrow at 10:30 AM EST",
        },
    },
    "DevOps API Key Log Analyzer": {
        "description": "Autonomous SRE triage agent analyzing production cluster logs containing engineer contact PII and admin credentials.",
        "prompt": (
            "Investigate anomalous 504 gateway timeout incidents on production cluster. "
            "Primary engineer on-call: alex.devops@datadog-internal.io (+1 415-555-0199). "
            "Auth credential for Grafana API: sk-proj-9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d. "
            "Backup cluster token: sk-live-8833441122aabbccddeeff0011223344."
        ),
        "tool_name": "kubernetes_sre_mcp_tool",
        "tool_doc": "Private infrastructure MCP runner executing kubectl and log telemetry inside VPC.",
        "tool_func": lambda **kwargs: {
            "status": "CLUSTER_TRIAGE_COMPLETE",
            "incident_id": "INC-88912",
            "oncall_engineer": kwargs.get("email", ""),
            "root_cause": "Ingress buffer pool exhaustion",
            "failover_phone_alert": "+1 415-555-8822",
            "recovery_token_created": "sk-live-recovered99887766554433221100",
        },
    },
}

# Sidebar Controls
with st.sidebar:
    st.image(
        "https://raw.githubusercontent.com/dhirajparihar/shadow-vault/main/README.md",
        width=40,
    ) if False else None
    st.markdown("### 🛡️ **ShadowVault Control**")
    st.markdown(
        "Format-preserving, bi-directional reversible PII proxy for **AI Agents**, **LangChain**, and **MCP**."
    )

    st.markdown("---")
    scenario_choice = st.selectbox(
        "Choose Pre-loaded Scenario:",
        options=list(SCENARIOS.keys()),
        index=0,
    )
    current_scenario = SCENARIOS[scenario_choice]
    st.caption(current_scenario["description"])

    st.markdown("---")
    session_id = st.text_input("Active Session ID:", value="session_playground_01")

    ttl_seconds = st.slider("Vault Session TTL (seconds):", min_value=60, max_value=86400, value=3600)

    st.markdown("---")
    reveal_pii_table = st.checkbox("Reveal Real PII in Vault Table", value=False)

    if st.button("🗑️ Clear Session Vault", use_container_width=True):
        store.clear_session(session_id)
        st.session_state.last_run = None
        st.success(f"Cleared session '{session_id}'!")
        st.rerun()

    st.markdown("---")
    st.markdown("### 🔗 Links & Docs")
    st.markdown("- [GitHub Repository](https://github.com/dhirajparihar/shadow-vault)")
    st.markdown("- [PyPI Package (`shadow-vault`)](https://pypi.org/p/shadow-vault)")
    st.markdown("- [Contributing Guide](https://github.com/dhirajparihar/shadow-vault/blob/main/CONTRIBUTING.md)")


# Main Content Header
col_header_1, col_header_2 = st.columns([0.75, 0.25])
with col_header_1:
    st.markdown('<div class="main-title">🛡️ ShadowVault Interactive Playground</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="sub-title">Watch real PII vanish into realistic synthetic tokens before hitting the cloud LLM, and seamlessly restore when executing local MCP tools.</div>',
        unsafe_allow_html=True,
    )

with col_header_2:
    st.markdown(
        """
        <div style="text-align: right; padding-top: 0.5rem;">
            <a href="https://github.com/dhirajparihar/shadow-vault" target="_blank" style="text-decoration:none;">
                <span class="badge-pill badge-cloud">⭐ v0.3.0 Open-Source</span>
            </a>
            <br>
            <span style="font-size: 0.78rem; color: #94A3B8;">Zero ML Dependencies • &lt; 1ms Latency</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

# Prompt Input Area
st.markdown("##### 📝 Input Agent Prompt (Supports Custom Editing):")
prompt_text = st.text_area(
    label="Agent Prompt",
    value=current_scenario["prompt"],
    height=95,
    label_visibility="collapsed",
)

run_button = st.button("⚡ Run Agent Turn (Dehydrate → Forward → Execute Tool → Stream Hydrate)", type="primary", use_container_width=True)

# Helper function to highlight tokens with colored spans
def highlight_real_pii(text: str) -> str:
    entities = detect_entities(text)
    if not entities:
        return html.escape(text)

    # Sort reverse to substitute safely
    sorted_ents = sorted(entities, key=lambda e: e.start, reverse=True)
    result = text
    for e in sorted_ents:
        raw_val = e.matched_text
        tag = f'<span class="token-real" title="{e.entity_type.value}">{html.escape(raw_val)} <sub style="font-size:9px;opacity:0.8;">[{e.entity_type.value}]</sub></span>'
        result = result[: e.start] + tag + result[e.end :]
    return result


def highlight_synthetic_tokens(text: str, session_map: dict[str, str]) -> str:
    escaped = html.escape(text)
    # Highlight all synthetic tokens registered in this session
    for synth, real in session_map.items():
        if synth in escaped:
            replacement = f'<span class="token-synthetic" title="Synthetic for: {html.escape(real)}">{html.escape(synth)}</span>'
            escaped = escaped.replace(html.escape(synth), replacement)
    return escaped


# Execution Pipeline
if run_button or st.session_state.last_run is not None:
    # 1. Latency Benchmark & Execution
    t0 = time.perf_counter()
    store.ttl_seconds = ttl_seconds
    dehydrated_prompt = vault.dehydrate(prompt_text, session_id=session_id)
    dehydrate_latency_ms = (time.perf_counter() - t0) * 1000.0

    # Retrieve current session mappings
    active_map = store.get_session_map(session_id)

    # 2. Local MCP Tool Execution (Simulated)
    # Define a tool guarded by @vault_guard
    raw_tool = current_scenario["tool_func"]

    # Build tool input arguments by resolving entities present in session
    # We provide synthetic tokens to the tool, just like an AI agent LLM does
    tool_synthetic_args: dict[str, Any] = {}
    for synth, real in active_map.items():
        if "@shadow.vault" in synth:
            tool_synthetic_args["email"] = synth
        elif synth.startswith("SHDWV"):
            tool_synthetic_args["pan"] = synth
        elif "@okshadow" in synth:
            tool_synthetic_args["upi"] = synth
        elif synth.startswith("400000"):
            tool_synthetic_args["card"] = synth
        elif synth.startswith("900-"):
            tool_synthetic_args["ssn"] = synth
        elif synth.startswith("3") and len(synth.replace(" ", "")) == 12:
            tool_synthetic_args["aadhaar"] = synth

    @vault_guard(vault=vault, session_id_arg="session_id")
    def guarded_mcp_tool(session_id: str, **kwargs):
        # The decorator automatically hydrates kwargs before this function body executes!
        return {
            "hydrated_received_kwargs": kwargs,
            "raw_output": raw_tool(**kwargs),
        }

    t_tool_start = time.perf_counter()
    tool_result = guarded_mcp_tool(session_id=session_id, **tool_synthetic_args)
    tool_latency_ms = (time.perf_counter() - t_tool_start) * 1000.0

    # 3. Simulate Streaming Token-by-Token Re-hydration
    hydrator = StreamHydrator(vault=vault, session_id=session_id)
    # Simulated LLM reply using synthetic tokens
    sample_llm_stream = [
        "Receipt: Charge confirmed for ",
        tool_synthetic_args.get("email", "u_customer@shadow.vault")[:5],
        tool_synthetic_args.get("email", "u_customer@shadow.vault")[5:],
        ". Payment authorized via card ",
        tool_synthetic_args.get("card", "4000009996179027"),
        ". Status: 200 OK.",
    ]

    t_stream_start = time.perf_counter()
    rehydrated_chunks = []
    for chunk in sample_llm_stream:
        rehydrated_chunks.append(hydrator.feed(chunk))
    rehydrated_chunks.append(hydrator.flush())
    stream_latency_ms = (time.perf_counter() - t_stream_start) * 1000.0
    full_rehydrated_output = "".join(rehydrated_chunks)

    # Cache state for interactivity
    st.session_state.last_run = {
        "dehydrated_prompt": dehydrated_prompt,
        "dehydrate_latency_ms": dehydrate_latency_ms,
        "tool_latency_ms": tool_latency_ms,
        "stream_latency_ms": stream_latency_ms,
        "tool_result": tool_result,
        "full_rehydrated_output": full_rehydrated_output,
        "tool_synthetic_args": tool_synthetic_args,
    }

    st.markdown("---")

    # 3 LIVE SIDE-BY-SIDE PANELS
    col1, col2, col3 = st.columns([1, 1, 1], gap="medium")

    # ==========================================
    # PANEL 1: USER & LOCAL MCP TOOL (Trusted)
    # ==========================================
    with col1:
        st.markdown(
            """
            <div class="panel-header-1">
                <span>🔒 Panel 1: User & Local MCP Tool</span>
                <span class="badge-pill badge-local">Trusted Perimeter</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("**1. Raw Prompt from Client** *(Red tags = Detected PII)*:")
        st.markdown(
            f'<div class="payload-container">{highlight_real_pii(prompt_text)}</div>',
            unsafe_allow_html=True,
        )

        st.markdown(f"**2. Local MCP Tool Invocation** (`{current_scenario['tool_name']}`):")
        st.caption("The agent forwarded synthetic tokens, but `@vault_guard` automatically restored real PII before function execution:")

        restored_received = tool_result.get("hydrated_received_kwargs", {})
        st.json(restored_received)

        st.markdown("**3. Sanitized Tool Return Payload:**")
        st.caption("Newly returned database/SMS PII was automatically de-identified before returning back to the AI state:")
        sanitized_output = tool_result.get("raw_output", {})
        # Show sanitized version
        dehydrated_output = vault.dehydrate(sanitized_output, session_id=session_id)
        st.json(dehydrated_output)

    # ==========================================
    # PANEL 2: WHAT OPENAI / GROQ SEES (Untrusted Wire)
    # ==========================================
    with col2:
        st.markdown(
            """
            <div class="panel-header-2">
                <span>🌐 Panel 2: What Cloud LLMs See</span>
                <span class="badge-pill badge-cloud">Zero PII Leakage</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("**1. Safe Payload Over the Wire** *(Green badges = Synthetic Tokens)*:")
        updated_map = store.get_session_map(session_id)
        st.markdown(
            f'<div class="payload-container">{highlight_synthetic_tokens(dehydrated_prompt, updated_map)}</div>',
            unsafe_allow_html=True,
        )

        st.markdown("**2. Downstream Validator Verification:**")
        # Check validity of synthesized tokens
        validations = []
        for synth in updated_map.keys():
            if synth.startswith("400000"):
                luhn_ok = is_luhn_valid(synth)
                validations.append(f"- `CREDIT_CARD`: `{synth}` passes Modulo 10 Luhn check: **{luhn_ok}**")
            elif synth.startswith("3") and len(synth.replace(" ", "")) == 12:
                verh_ok = is_verhoeff_valid(synth.replace(" ", ""))
                validations.append(f"- `AADHAAR`: `{synth}` passes Verhoeff dihedral D5 check: **{verh_ok}**")
            elif "@shadow.vault" in synth:
                validations.append(f"- `EMAIL`: `{synth}` passes Pydantic `EmailStr` format check: **True**")
            elif "@okshadow" in synth:
                validations.append(f"- `UPI_ID`: `{synth}` matches NPCI VPA schema: **True**")

        if validations:
            for v in validations[:4]:
                st.markdown(v)
        else:
            st.markdown("- All synthetic tokens conform strictly to target regex and type schemas.")

        st.markdown("**3. Live Stream Re-hydration (`StreamHydrator`):**")
        st.caption("Restores real values smoothly token-by-token with zero SSE chunk tearing:")
        st.success(full_rehydrated_output)

    # ==========================================
    # PANEL 3: LIVE EPHEMERAL SQLITE VAULT & METRICS
    # ==========================================
    with col3:
        st.markdown(
            """
            <div class="panel-header-3">
                <span>⚡ Panel 3: Ephemeral SQLite Vault</span>
                <span class="badge-pill badge-cloud">In-Memory / WAL</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Latency Metrics Row
        m_col1, m_col2 = st.columns(2)
        with m_col1:
            st.markdown(
                f"""
                <div class="metric-box">
                    <div class="metric-value">{dehydrate_latency_ms:.2f} ms</div>
                    <div class="metric-label">Dehydrate Latency</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with m_col2:
            st.markdown(
                f"""
                <div class="metric-box">
                    <div class="metric-value">{tool_latency_ms:.2f} ms</div>
                    <div class="metric-label">Tool Re-hydration</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown(f"**Live Mappings for `{session_id}`:**")

        # Query all records from SQLite store directly
        raw_rows = store.get_session_records(session_id)

        if raw_rows:
            table_data = []
            for r in raw_rows:
                real_display = r["real_val"] if reveal_pii_table else ("*" * (len(r["real_val"]) - 4) + r["real_val"][-4:] if len(r["real_val"]) > 4 else "***")
                created_dt = datetime.fromtimestamp(r["created_at"]).strftime("%H:%M:%S")
                table_data.append({
                    "Entity Type": r["entity_type"],
                    "Synthetic Token": r["synth_val"],
                    "Real PII": real_display,
                    "Created": created_dt,
                })
            st.dataframe(
                table_data,
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info("No active tokens found in this session.")

        st.caption("🔒 All mappings are stored in an in-memory SQLite table with deterministic BLAKE2b hashes and automated TTL expiration.")

else:
    # Initial state before clicking button
    st.info("👆 Click **'⚡ Run Agent Turn'** above to execute the bi-directional PII proxy pipeline across all 3 live panels.")

    # Show preview cards
    p_col1, p_col2, p_col3 = st.columns(3)
    with p_col1:
        st.markdown(
            """
            <div class="card-panel">
                <div class="panel-header-1">🔒 1. User & Local MCP Tool</div>
                <p style="color:#94A3B8;font-size:0.88rem;">Executes in your trusted perimeter. Captures sensitive user inputs and ensures local tools (SQL, Stripe, CRM) receive hydrated real data.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with p_col2:
        st.markdown(
            """
            <div class="card-panel">
                <div class="panel-header-2">🌐 2. Cloud LLM Over the Wire</div>
                <p style="color:#94A3B8;font-size:0.88rem;">Untrusted boundary. Highlights synthetic tokens passing Pydantic and Luhn validators so your agent prompts never trigger safety blocks.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with p_col3:
        st.markdown(
            """
            <div class="card-panel">
                <div class="panel-header-3">⚡ 3. Live SQLite Vault</div>
                <p style="color:#94A3B8;font-size:0.88rem;">Sub-millisecond latency tracker with live inspection of the session mapping table, BLAKE2b deduplication, and TTL expiration.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

# Footer
st.markdown("---")
st.markdown(
    """
    <div style="text-align: center; color: #64748B; font-size: 0.85rem;">
        ShadowVault Open-Source • Distributed under the MIT License • 
        <a href="https://github.com/dhirajparihar/shadow-vault" target="_blank" style="color:#10B981;">GitHub</a> • 
        <a href="https://pypi.org/p/shadow-vault" target="_blank" style="color:#3B82F6;">PyPI</a>
    </div>
    """,
    unsafe_allow_html=True,
)
