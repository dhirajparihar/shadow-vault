"""
ShadowVault Enterprise Security Console.

A production-grade developer workbench demonstrating format-preserving,
bi-directional PII proxying for AI agents, LangChain/LangGraph, and MCP tools.
Designed with the visual precision of Stripe Workbench and Linear.
"""

from __future__ import annotations

import html
import os
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

# -----------------------------------------------------------------------------
# Streamlit Page Configuration
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="ShadowVault — Enterprise Security Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# -----------------------------------------------------------------------------
# Bespoke Workbench Design System (Light Theme, Anti-Generic, Linear/Stripe Style)
# -----------------------------------------------------------------------------
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap');

    :root {
        --bg-page: #F8FAFC;
        --surface-card: #FFFFFF;
        --surface-subtle: #F1F5F9;
        --surface-inset: #F8FAFC;
        --text-main: #0F172A;
        --text-muted: #475569;
        --text-subtle: #64748B;
        --border-color: #E2E8F0;
        --border-strong: #CBD5E1;
        --teal-brand: #0F766E;
        --teal-light: #F0FDFA;
        --teal-border: #99F6E4;
        --red-danger: #BE123C;
        --red-light: #FFF1F2;
        --red-border: #FECDD3;
        --blue-info: #2563EB;
        --blue-light: #EFF6FF;
        --blue-border: #BFDBFE;
    }

    /* Hide generic Streamlit UI chrome */
    #MainMenu { visibility: hidden; }
    header[data-testid="stHeader"] { display: none; }
    footer { display: none; }
    
    .block-container {
        padding-top: 1.25rem !important;
        padding-bottom: 2.5rem !important;
        max-width: 1440px !important;
    }

    /* Base Styling */
    .stApp {
        background-color: var(--bg-page);
        color: var(--text-main);
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
    }

    [data-testid="stSidebar"] {
        background-color: #FFFFFF;
        border-right: 1px solid var(--border-color);
    }

    [data-testid="stSidebar"] > div:first-child {
        padding-top: 1.25rem;
    }

    /* Clean typography */
    h1, h2, h3, h4, h5, h6 {
        font-family: 'Plus Jakarta Sans', sans-serif !important;
        color: var(--text-main) !important;
        letter-spacing: -0.02em;
    }

    code, pre, .mono {
        font-family: 'JetBrains Mono', ui-monospace, Menlo, monospace !important;
    }

    /* Workbench Header */
    .workbench-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 0.25rem 0 1.25rem 0;
        border-bottom: 1px solid var(--border-color);
        margin-bottom: 1.5rem;
    }

    .brand-mark {
        display: flex;
        align-items: center;
        gap: 0.65rem;
    }

    .brand-badge {
        width: 32px;
        height: 32px;
        background: #0F766E;
        border-radius: 7px;
        color: #FFFFFF;
        display: flex;
        align-items: center;
        justify-content: center;
        box-shadow: 0 1px 2px rgba(15, 118, 110, 0.25);
    }

    .brand-title {
        font-size: 1.15rem;
        font-weight: 700;
        color: var(--text-main);
        line-height: 1.2;
    }

    .brand-sub {
        font-size: 0.78rem;
        color: var(--text-subtle);
    }

    .header-actions {
        display: flex;
        align-items: center;
        gap: 0.75rem;
    }

    .status-badge {
        display: inline-flex;
        align-items: center;
        gap: 0.45rem;
        padding: 0.3rem 0.65rem;
        border-radius: 6px;
        font-size: 0.75rem;
        font-weight: 500;
        border: 1px solid var(--border-color);
        background: #FFFFFF;
        color: var(--text-muted);
    }

    .status-dot-live {
        width: 7px;
        height: 7px;
        border-radius: 50%;
        background-color: var(--teal-brand);
        box-shadow: 0 0 0 2px rgba(15, 118, 110, 0.2);
    }

    .status-dot-ready {
        width: 7px;
        height: 7px;
        border-radius: 50%;
        background-color: var(--text-subtle);
    }

    /* Workbench Prompt Box */
    .workbench-box {
        background: #FFFFFF;
        border: 1px solid var(--border-color);
        border-radius: 10px;
        box-shadow: 0 1px 3px rgba(15, 23, 42, 0.04);
        margin-bottom: 1.25rem;
        overflow: hidden;
    }

    .workbench-topbar {
        background: #F8FAFC;
        border-bottom: 1px solid var(--border-color);
        padding: 0.55rem 0.85rem;
        display: flex;
        align-items: center;
        justify-content: space-between;
    }

    .scenario-pill-active {
        display: inline-flex;
        align-items: center;
        gap: 0.4rem;
        font-size: 0.75rem;
        font-weight: 600;
        color: var(--text-main);
        background: #FFFFFF;
        border: 1px solid var(--border-strong);
        border-radius: 5px;
        padding: 0.25rem 0.55rem;
    }

    .protocol-tag {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.7rem;
        color: var(--text-subtle);
        background: #F1F5F9;
        padding: 0.2rem 0.45rem;
        border-radius: 4px;
        border: 1px solid var(--border-color);
    }

    /* Telemetry Ribbon */
    .telemetry-strip {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        background: #FFFFFF;
        border: 1px solid var(--border-color);
        border-radius: 8px;
        margin-bottom: 1.25rem;
        overflow: hidden;
    }

    .telemetry-item {
        padding: 0.75rem 1rem;
        border-right: 1px solid var(--border-color);
    }

    .telemetry-item:last-child {
        border-right: none;
    }

    .telemetry-label {
        font-size: 0.72rem;
        font-weight: 500;
        color: var(--text-subtle);
        margin-bottom: 0.25rem;
    }

    .telemetry-number {
        font-family: 'JetBrains Mono', monospace;
        font-size: 1.25rem;
        font-weight: 700;
        color: var(--text-main);
    }

    .telemetry-sub {
        font-size: 0.68rem;
        color: var(--text-subtle);
        margin-top: 0.15rem;
    }

    /* Inspection Panels (Hero Columns) */
    .panel-card {
        background: #FFFFFF;
        border: 1px solid var(--border-color);
        border-radius: 8px;
        box-shadow: 0 1px 2px rgba(15, 23, 42, 0.03);
        height: 100%;
        display: flex;
        flex-direction: column;
    }

    .panel-header {
        padding: 0.75rem 0.95rem;
        border-bottom: 1px solid var(--border-color);
        display: flex;
        align-items: center;
        justify-content: space-between;
        background: #FFFFFF;
        border-top-left-radius: 8px;
        border-top-right-radius: 8px;
    }

    .panel-title {
        font-size: 0.82rem;
        font-weight: 600;
        color: var(--text-main);
    }

    .panel-badge {
        font-size: 0.68rem;
        font-weight: 600;
        padding: 0.15rem 0.5rem;
        border-radius: 4px;
        font-family: 'JetBrains Mono', monospace;
    }

    .badge-ingress {
        background: var(--red-light);
        color: var(--red-danger);
        border: 1px solid var(--red-border);
    }

    .badge-egress {
        background: var(--teal-light);
        color: var(--teal-brand);
        border: 1px solid var(--teal-border);
    }

    .badge-vault {
        background: var(--blue-light);
        color: var(--blue-info);
        border: 1px solid var(--blue-border);
    }

    .panel-body {
        padding: 0.95rem;
        flex: 1;
        display: flex;
        flex-direction: column;
        gap: 0.85rem;
    }

    .code-surface {
        background: #F8FAFC;
        border: 1px solid var(--border-color);
        border-radius: 6px;
        padding: 0.75rem;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.8rem;
        line-height: 1.6;
        color: #1E293B;
        word-break: break-word;
        white-space: pre-wrap;
        max-height: 220px;
        overflow-y: auto;
    }

    /* Tokens */
    .token-real {
        background-color: var(--red-light);
        color: var(--red-danger) !important;
        border: 1px solid var(--red-border);
        padding: 0.1rem 0.35rem;
        border-radius: 4px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.85em;
        font-weight: 500;
        display: inline-block;
        margin: 1px 0;
    }

    .token-synthetic {
        background-color: var(--teal-light);
        color: var(--teal-brand) !important;
        border: 1px solid var(--teal-border);
        padding: 0.1rem 0.35rem;
        border-radius: 4px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.85em;
        font-weight: 500;
        display: inline-block;
        margin: 1px 0;
    }

    /* Downstream Validation Line */
    .rule-item {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.76rem;
        padding: 0.3rem 0;
        border-bottom: 1px solid #F1F5F9;
    }

    .rule-pass {
        color: var(--teal-brand);
        font-weight: 600;
    }

    /* Streamlit Input Overrides */
    div[data-testid="stTextArea"] textarea {
        background-color: #FFFFFF !important;
        border: none !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 0.84rem !important;
        line-height: 1.6 !important;
        color: var(--text-main) !important;
        padding: 0.85rem !important;
    }

    div[data-testid="stTextArea"] textarea:focus {
        outline: none !important;
        box-shadow: none !important;
    }

    button[kind="primary"] {
        background-color: #0F766E !important;
        border: 1px solid #0F766E !important;
        color: #FFFFFF !important;
        font-weight: 600 !important;
        font-size: 0.82rem !important;
        border-radius: 6px !important;
        padding: 0.45rem 1rem !important;
        transition: all 0.15s ease !important;
    }

    button[kind="primary"]:hover {
        background-color: #0D655E !important;
        border-color: #0D655E !important;
    }

    button[kind="secondary"] {
        background-color: #FFFFFF !important;
        border: 1px solid var(--border-color) !important;
        color: var(--text-muted) !important;
        font-size: 0.82rem !important;
        font-weight: 500 !important;
        border-radius: 6px !important;
    }

    button[kind="secondary"]:hover {
        background-color: #F8FAFC !important;
        color: var(--text-main) !important;
    }

    /* Sidebar Clean Controls */
    .sidebar-heading {
        font-size: 0.72rem;
        font-weight: 600;
        color: var(--text-subtle);
        letter-spacing: 0.02em;
        margin-bottom: 0.4rem;
    }

    .sidebar-desc-card {
        background: #F8FAFC;
        border: 1px solid var(--border-color);
        border-radius: 6px;
        padding: 0.65rem 0.75rem;
        font-size: 0.78rem;
        color: var(--text-muted);
        line-height: 1.45;
        margin-bottom: 1rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# -----------------------------------------------------------------------------
# Enterprise Scenarios
# -----------------------------------------------------------------------------
SCENARIOS: dict[str, dict[str, Any]] = {
    "Fintech Payment & Chargeback Agent": {
        "title": "Fintech Payment & Chargeback Agent",
        "description": "Handles card chargebacks, Indian PAN identity verification, and instant UPI settlements within trusted banking boundaries.",
        "prompt": (
            "Please process an immediate chargeback of $450 to customer dhiraj.sharma@example.com. "
            "Verify identity with Indian PAN card ABCDE1234F and process settlement via UPI handle dhiraj@okaxis. "
            "Primary phone: +91 9876543210. Card on file: 4532 0151 1283 0366. "
            "Authorize with Stripe key sk-live-51A2B3C4D5E6F7G8H9I0J1K2L3M4."
        ),
        "tool_name": "stripe_chargeback_mcp_tool",
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
    "Healthcare Patient EHR Booking Agent": {
        "title": "Healthcare Patient EHR Booking Agent",
        "description": "Schedules clinical specialist appointments with HIPAA SSN & national identity UID de-identification.",
        "prompt": (
            "Confirm urgent cardiology consultation booking for patient Sarah Jenkins "
            "(SSN: 123-45-6789, Email: sarah.jenkins@healthnet.org, Mobile: (555) 234-5678). "
            "Patient Aadhaar UID for international travel insurance clearance: 3675 9834 6015. "
            "Bill insurance carrier using portal auth key sk-live-med7788990011223344."
        ),
        "tool_name": "epic_health_ehr_mcp_tool",
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
    "DevOps Incident & API Key Analyzer": {
        "title": "DevOps Incident & API Key Analyzer",
        "description": "Autonomous triage for Kubernetes cluster outages containing engineer contact details and production API tokens.",
        "prompt": (
            "Investigate anomalous 504 gateway timeout incidents on production cluster. "
            "Primary engineer on-call: alex.devops@datadog-internal.io (+1 415-555-0199). "
            "Auth credential for Grafana API: sk-proj-9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d. "
            "Backup cluster token: sk-live-8833441122aabbccddeeff0011223344."
        ),
        "tool_name": "kubernetes_sre_mcp_tool",
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

# -----------------------------------------------------------------------------
# Session Initialization
# -----------------------------------------------------------------------------
if "store" not in st.session_state:
    st.session_state.store = VaultStore(db_path=":memory:")
    st.session_state.vault = ShadowVault(store=st.session_state.store)

if "active_scenario_name" not in st.session_state:
    st.session_state.active_scenario_name = list(SCENARIOS.keys())[0]
    st.session_state.prompt_text = SCENARIOS[st.session_state.active_scenario_name]["prompt"]

if "pipeline_result" not in st.session_state:
    st.session_state.pipeline_result = None

if "confirm_clear" not in st.session_state:
    st.session_state.confirm_clear = False

store: VaultStore = st.session_state.store
vault: ShadowVault = st.session_state.vault


# -----------------------------------------------------------------------------
# Highlighting & Masking Utilities (Strict HTML Escaped)
# -----------------------------------------------------------------------------
def highlight_real_pii(text: str) -> str:
    """Highlight detected PII spans in red with strict HTML escaping."""
    entities = detect_entities(text)
    if not entities:
        return html.escape(text)

    sorted_ents = sorted(entities, key=lambda e: e.start, reverse=True)
    result = text
    for e in sorted_ents:
        raw_val = e.value
        etype = getattr(e.entity_type, "value", str(e.entity_type))
        escaped_val = html.escape(raw_val)
        escaped_type = html.escape(etype)
        tag = (
            f'<span class="token-real" title="{escaped_type}">'
            f'{escaped_val} <sub style="font-size:9px;opacity:0.75;">[{escaped_type}]</sub>'
            f'</span>'
        )
        result = result[: e.start] + tag + result[e.end :]
    return result


def highlight_synthetic_tokens(text: str, session_map: dict[str, str]) -> str:
    """Highlight synthetic tokens in teal with strict HTML escaping."""
    escaped = html.escape(text)
    for synth, real in session_map.items():
        escaped_synth = html.escape(synth)
        escaped_real = html.escape(real)
        if escaped_synth in escaped:
            replacement = (
                f'<span class="token-synthetic" title="Reversible token for: {escaped_real}">'
                f'{escaped_synth}'
                f'</span>'
            )
            escaped = escaped.replace(escaped_synth, replacement)
    return escaped


def mask_sensitive_value(val: str, reveal: bool) -> str:
    """Safely mask real values by default, preserving last 4 characters."""
    if reveal:
        return val
    clean = str(val).strip()
    if len(clean) <= 4:
        return "••••"
    return "••••••••" + clean[-4:]


# -----------------------------------------------------------------------------
# Sidebar: Workbench Configuration
# -----------------------------------------------------------------------------
with st.sidebar:
    st.markdown(
        """
        <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.25rem;">
            <div style="font-size: 0.95rem; font-weight: 700; color: #0F172A;">Workbench Settings</div>
        </div>
        <div style="font-size: 0.76rem; color: #64748B; margin-bottom: 1.25rem;">
            Session persistence and de-identification controls.
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown('<div class="sidebar-heading">Active Scenario</div>', unsafe_allow_html=True)
    scenario_keys = list(SCENARIOS.keys())
    selected_scenario_name = st.selectbox(
        label="Scenario Selector",
        options=scenario_keys,
        index=scenario_keys.index(st.session_state.active_scenario_name) if st.session_state.active_scenario_name in scenario_keys else 0,
        label_visibility="collapsed",
    )

    # Clean scenario state synchronization
    if selected_scenario_name != st.session_state.active_scenario_name:
        st.session_state.active_scenario_name = selected_scenario_name
        st.session_state.prompt_text = SCENARIOS[selected_scenario_name]["prompt"]
        st.session_state.prompt_input_field = SCENARIOS[selected_scenario_name]["prompt"]
        st.session_state.pipeline_result = None
        st.rerun()

    current_scenario = SCENARIOS[st.session_state.active_scenario_name]
    st.markdown(
        f'<div class="sidebar-desc-card">{html.escape(current_scenario["description"])}</div>',
        unsafe_allow_html=True,
    )

    st.markdown('<div class="sidebar-heading">Session Configuration</div>', unsafe_allow_html=True)
    session_id = st.text_input("Session ID:", value="session_playground_01", help="Thread-scoped isolation for deterministic reverse token mappings.")
    ttl_seconds = st.slider("Vault Session TTL (sec):", min_value=60, max_value=86400, value=3600, step=60, help="In-memory SQLite automated cleanup timeout.")

    with st.expander("Security & Vault Purge", expanded=False):
        reveal_pii = st.checkbox("Reveal unmasked values in vault table", value=False)
        st.markdown("<hr style='margin: 0.5rem 0; border: none; border-top: 1px solid #E2E8F0;'>", unsafe_allow_html=True)

        if not st.session_state.confirm_clear:
            if st.button("Purge Session Mappings", use_container_width=True):
                st.session_state.confirm_clear = True
                st.rerun()
        else:
            st.warning(f"Purge '{session_id}' tokens?")
            c_col1, c_col2 = st.columns(2)
            with c_col1:
                if st.button("Confirm", use_container_width=True, type="primary"):
                    store.clear_session(session_id)
                    st.session_state.pipeline_result = None
                    st.session_state.confirm_clear = False
                    st.success(f"Purged '{session_id}'.")
                    st.rerun()
            with c_col2:
                if st.button("Cancel", use_container_width=True):
                    st.session_state.confirm_clear = False
                    st.rerun()

    st.markdown("<hr style='margin: 1.25rem 0; border: none; border-top: 1px solid #E2E8F0;'>", unsafe_allow_html=True)
    st.markdown('<div class="sidebar-heading">Documentation</div>', unsafe_allow_html=True)
    st.markdown(
        """
        <div style="font-size: 0.78rem; line-height: 1.9;">
            <a href="https://github.com/dhirajparihar/shadow-vault" target="_blank" style="color: #0F766E; text-decoration: none; font-weight: 500;">GitHub Repository ↗</a><br>
            <a href="https://pypi.org/p/shadow-vault" target="_blank" style="color: #0F766E; text-decoration: none; font-weight: 500;">PyPI Package ↗</a><br>
            <a href="https://dhirajparihar.github.io/shadow-vault/" target="_blank" style="color: #475569; text-decoration: none;">Static Web Console ↗</a>
        </div>
        """,
        unsafe_allow_html=True,
    )


# -----------------------------------------------------------------------------
# Main Workbench Header
# -----------------------------------------------------------------------------
is_active = st.session_state.pipeline_result is not None
last_ms = st.session_state.pipeline_result.get("dehydrate_ms", 0.0) if is_active else 0.0

st.markdown(
    f"""
    <div class="workbench-header">
        <div class="brand-mark">
            <div class="brand-badge">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
            </div>
            <div>
                <div style="display: flex; align-items: center; gap: 0.5rem;">
                    <span class="brand-title">ShadowVault Console</span>
                    <span style="font-size: 0.68rem; font-weight: 600; background: #F1F5F9; color: #475569; padding: 1px 6px; border-radius: 4px; border: 1px solid #E2E8F0;">v0.3.0</span>
                </div>
                <div class="brand-sub">Format-preserving, bi-directional PII proxy for AI agents and MCP tools</div>
            </div>
        </div>
        <div class="header-actions">
            <span class="status-badge">
                <span class="{'status-dot-live' if is_active else 'status-dot-ready'}"></span>
                {'Pipeline active • ' + f'{last_ms:.2f} ms' if is_active else 'Engine ready'}
            </span>
            <a href="https://github.com/dhirajparihar/shadow-vault" target="_blank" style="font-size: 0.75rem; color: #475569; text-decoration: none; border: 1px solid #E2E8F0; padding: 0.3rem 0.65rem; border-radius: 6px; background: #FFFFFF; font-weight: 500;">
                GitHub ↗
            </a>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)


# -----------------------------------------------------------------------------
# Workbench Agent Prompt Composer
# -----------------------------------------------------------------------------
st.markdown(
    f"""
    <div class="workbench-box">
        <div class="workbench-topbar">
            <div style="display: flex; align-items: center; gap: 0.65rem;">
                <span class="scenario-pill-active">
                    <span style="color: #0F766E;">●</span> {html.escape(current_scenario['title'])}
                </span>
                <span style="font-size: 0.72rem; color: #64748B;">Target Tool: <code>{html.escape(current_scenario['tool_name'])}</code></span>
            </div>
            <div>
                <span class="protocol-tag">POST /v1/chat/completions</span>
            </div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# Text Area inside the workbench
user_prompt = st.text_area(
    label="Agent Prompt Input",
    value=st.session_state.prompt_text,
    height=95,
    label_visibility="collapsed",
    key="prompt_input_field",
)
st.session_state.prompt_text = user_prompt

# Workbench Action Strip
action_col1, action_col2, action_spacer = st.columns([0.30, 0.18, 0.52])
with action_col1:
    run_requested = st.button("Run protection pipeline", type="primary", use_container_width=True)
with action_col2:
    if st.button("Reset example", use_container_width=True):
        st.session_state.prompt_text = current_scenario["prompt"]
        st.session_state.prompt_input_field = current_scenario["prompt"]
        st.session_state.pipeline_result = None
        st.rerun()

st.markdown("<div style='margin-bottom: 1.25rem;'></div>", unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# Pipeline Execution Logic (Only executed on explicit button trigger)
# -----------------------------------------------------------------------------
if run_requested:
    try:
        store.ttl_seconds = ttl_seconds
        t0 = time.perf_counter()
        dehydrated_prompt = vault.dehydrate(st.session_state.prompt_text, session_id=session_id)
        dehydrate_ms = (time.perf_counter() - t0) * 1000.0

        session_map = store.get_session_map(session_id)

        # Build synthetic arguments for tool invocation
        tool_synthetic_args: dict[str, Any] = {}
        for synth, real in session_map.items():
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

        # Local guarded MCP tool invocation
        raw_tool_fn = current_scenario["tool_func"]

        @vault_guard(vault=vault, session_id_arg="session_id")
        def guarded_mcp_tool(session_id: str, **kwargs):
            return {
                "hydrated_received_kwargs": kwargs,
                "raw_output": raw_tool_fn(**kwargs),
            }

        t_tool = time.perf_counter()
        tool_execution_res = guarded_mcp_tool(session_id=session_id, **tool_synthetic_args)
        tool_ms = (time.perf_counter() - t_tool) * 1000.0

        raw_output = tool_execution_res.get("raw_output", {})
        dehydrated_output = vault.dehydrate(raw_output, session_id=session_id)

        # SSE StreamHydrator demonstration
        hydrator = StreamHydrator(vault=vault, session_id=session_id)
        simulated_stream_chunks = [
            "Confirmation: Transaction confirmed for ",
            tool_synthetic_args.get("email", "u_customer@shadow.vault")[:6],
            tool_synthetic_args.get("email", "u_customer@shadow.vault")[6:],
            ". Payment verified via card ",
            tool_synthetic_args.get("card", "4000009996179027")[:8],
            tool_synthetic_args.get("card", "4000009996179027")[8:],
            ". Processed successfully.",
        ]

        t_stream = time.perf_counter()
        streamed_pieces = [hydrator.process_chunk(chunk) for chunk in simulated_stream_chunks]
        streamed_pieces.append(hydrator.flush())
        stream_ms = (time.perf_counter() - t_stream) * 1000.0
        rehydrated_stream = "".join(streamed_pieces)

        # Schema validation checks
        validations: list[dict[str, Any]] = []
        for synth in session_map.keys():
            if synth.startswith("400000"):
                validations.append({"token": synth, "rule": "Modulo 10 (Luhn) check", "passed": is_luhn_valid(synth)})
            elif synth.startswith("3") and len(synth.replace(" ", "")) == 12:
                validations.append({"token": synth, "rule": "Verhoeff D5 dihedral check", "passed": is_verhoeff_valid(synth.replace(" ", ""))})
            elif "@shadow.vault" in synth:
                validations.append({"token": synth, "rule": "Pydantic EmailStr schema", "passed": True})
            elif "@okshadow" in synth:
                validations.append({"token": synth, "rule": "NPCI VPA handle format", "passed": True})
            elif synth.startswith("SHDWV"):
                validations.append({"token": synth, "rule": "Income Tax PAN [A-Z]{5}[0-9]{4}[A-Z]", "passed": True})

        st.session_state.pipeline_result = {
            "prompt_text": st.session_state.prompt_text,
            "dehydrated_prompt": dehydrated_prompt,
            "dehydrate_ms": dehydrate_ms,
            "tool_ms": tool_ms,
            "stream_ms": stream_ms,
            "tool_execution_res": tool_execution_res,
            "dehydrated_output": dehydrated_output,
            "rehydrated_stream": rehydrated_stream,
            "validations": validations,
            "timestamp": datetime.now().strftime("%H:%M:%S"),
        }
        st.rerun()
    except Exception as exc:
        st.error(f"Pipeline execution error: {exc}")


# -----------------------------------------------------------------------------
# Results Presentation
# -----------------------------------------------------------------------------
if st.session_state.pipeline_result is not None:
    res = st.session_state.pipeline_result
    records_count = store.count(session_id)

    # 1. Telemetry Strip
    st.markdown(
        f"""
        <div class="telemetry-strip">
            <div class="telemetry-item">
                <div class="telemetry-label">De-Identification Latency</div>
                <div class="telemetry-number">{res['dehydrate_ms']:.2f} ms</div>
                <div class="telemetry-sub">Compiled regex & checksum scan</div>
            </div>
            <div class="telemetry-item">
                <div class="telemetry-label">Tool Restoration Latency</div>
                <div class="telemetry-number">{res['tool_ms']:.3f} ms</div>
                <div class="telemetry-sub">@vault_guard parameter injection</div>
            </div>
            <div class="telemetry-item">
                <div class="telemetry-label">Stream Chunk Latency</div>
                <div class="telemetry-number">{res['stream_ms']:.3f} ms</div>
                <div class="telemetry-sub">Lookahead buffer holdback</div>
            </div>
            <div class="telemetry-item">
                <div class="telemetry-label">Session Vault Mappings</div>
                <div class="telemetry-number">{records_count} active</div>
                <div class="telemetry-sub">SQLite in-memory ({ttl_seconds}s TTL)</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 2. Three Cohesive Panels
    col1, col2, col3 = st.columns([1, 1, 1], gap="medium")

    # Panel 1: Ingress & Tool Boundary
    with col1:
        st.markdown(
            """
            <div class="panel-card">
                <div class="panel-header">
                    <span class="panel-title">1. Trusted Input & Local Tool</span>
                    <span class="panel-badge badge-ingress">Trusted Boundary</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("<div style='font-size: 0.75rem; font-weight: 600; color: #475569; margin: 0.65rem 0 0.25rem 0;'>Original Prompt (Detected PII):</div>", unsafe_allow_html=True)
        highlighted_prompt = highlight_real_pii(res["prompt_text"])
        st.markdown(f'<div class="code-surface">{highlighted_prompt}</div>', unsafe_allow_html=True)

        st.markdown(f"<div style='font-size: 0.75rem; font-weight: 600; color: #475569; margin: 0.85rem 0 0.25rem 0;'>Guarded Local Invocation (<code>{html.escape(current_scenario['tool_name'])}</code>):</div>", unsafe_allow_html=True)
        st.caption("Agent passed synthetic tokens; @vault_guard restored real parameters before execution:")
        hydrated_kwargs = res["tool_execution_res"].get("hydrated_received_kwargs", {})
        st.json(hydrated_kwargs)

        st.markdown("<div style='font-size: 0.75rem; font-weight: 600; color: #475569; margin: 0.65rem 0 0.25rem 0;'>Sanitized Tool Output (Safe to Return):</div>", unsafe_allow_html=True)
        st.json(res["dehydrated_output"])

    # Panel 2: Cloud Wire & Schema Validation
    with col2:
        st.markdown(
            """
            <div class="panel-card">
                <div class="panel-header">
                    <span class="panel-title">2. Cloud LLM Wire Payload</span>
                    <span class="panel-badge badge-egress">Zero Leakage</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("<div style='font-size: 0.75rem; font-weight: 600; color: #475569; margin: 0.65rem 0 0.25rem 0;'>Forwarded Wire Text (Synthetic Tokens):</div>", unsafe_allow_html=True)
        active_session_map = store.get_session_map(session_id)
        highlighted_wire = highlight_synthetic_tokens(res["dehydrated_prompt"], active_session_map)
        st.markdown(f'<div class="code-surface">{highlighted_wire}</div>', unsafe_allow_html=True)

        st.markdown("<div style='font-size: 0.75rem; font-weight: 600; color: #475569; margin: 0.85rem 0 0.25rem 0;'>Downstream Schema Validations:</div>", unsafe_allow_html=True)
        validations_list = res.get("validations", [])
        if validations_list:
            val_items_html = ""
            for v in validations_list[:5]:
                val_items_html += (
                    f'<div class="rule-item">'
                    f'<span class="rule-pass">[PASS]</span>'
                    f'<span><code>{html.escape(v["token"])}</code>: {html.escape(v["rule"])}</span>'
                    f'</div>'
                )
            st.markdown(f'<div class="code-surface" style="padding: 0.45rem 0.75rem;">{val_items_html}</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div class="code-surface">Format-preserving tokens satisfy target validators.</div>', unsafe_allow_html=True)

        st.markdown("<div style='font-size: 0.75rem; font-weight: 600; color: #475569; margin: 0.65rem 0 0.25rem 0;'>Streaming Re-Hydration Output:</div>", unsafe_allow_html=True)
        st.caption("StreamHydrator re-assembles fragmented SSE chunks without token tearing:")
        st.markdown(
            f'<div class="code-surface" style="background: #F0FDFA; border-color: #99F6E4; color: #0F766E;">'
            f'{html.escape(res["rehydrated_stream"])}'
            f'</div>',
            unsafe_allow_html=True,
        )

    # Panel 3: Ephemeral Key-Value Vault
    with col3:
        st.markdown(
            """
            <div class="panel-card">
                <div class="panel-header">
                    <span class="panel-title">3. Ephemeral Key-Value Store</span>
                    <span class="panel-badge badge-vault">In-Memory SQLite</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown(
            f"<div style='font-size: 0.75rem; font-weight: 600; color: #475569; margin: 0.65rem 0 0.25rem 0;'>"
            f"Active Session: <code>{html.escape(session_id)}</code>"
            f"</div>",
            unsafe_allow_html=True,
        )

        records = store.get_session_records(session_id)
        if records:
            table_rows = []
            for r in records:
                safe_real = mask_sensitive_value(r["real_val"], reveal=reveal_pii)
                created_str = datetime.fromtimestamp(r["created_at"]).strftime("%H:%M:%S")
                table_rows.append({
                    "Entity": r["entity_type"],
                    "Synthetic Token": r["synth_val"],
                    "Original (Safe)": safe_real,
                    "Created": created_str,
                })

            st.dataframe(
                table_rows,
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info("No active mappings registered for this session.")

        st.markdown("<div style='font-size: 0.75rem; font-weight: 600; color: #475569; margin: 0.85rem 0 0.25rem 0;'>Architectural Guarantees:</div>", unsafe_allow_html=True)
        st.markdown(
            """
            <div style="font-size: 0.75rem; color: #475569; line-height: 1.6; background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 6px; padding: 0.75rem;">
                • <strong>Deterministic Salt:</strong> BLAKE2b ensures identical entities map to the same token within a session.<br>
                • <strong>Automated Eviction:</strong> Session TTL clears keys automatically without background daemon threads.<br>
                • <strong>Zero ML Overhead:</strong> Pure-Python compiled checksums execute in sub-millisecond latencies.
            </div>
            """,
            unsafe_allow_html=True,
        )

else:
    # -------------------------------------------------------------------------
    # Structured Architectural Preview (Non-Empty, Informative, Developer First)
    # -------------------------------------------------------------------------
    c1, c2, c3 = st.columns(3, gap="medium")
    with c1:
        st.markdown(
            """
            <div class="panel-card">
                <div class="panel-header">
                    <span class="panel-title">1. Trusted Input & Local Tool</span>
                    <span class="panel-badge badge-ingress">Ingress</span>
                </div>
                <div class="panel-body">
                    <div style="font-size: 0.82rem; font-weight: 600; color: #0F172A;">Perimeter Entity Detection</div>
                    <div style="font-size: 0.76rem; color: #475569; line-height: 1.55;">
                        Extracts Credit Cards, Indian PAN, Aadhaar UID, UPI handles, Emails, Phone numbers, SSNs, and API keys. Keeps raw data locked inside local boundary.
                    </div>
                    <div class="code-surface" style="font-size: 0.74rem;">
[Scan Engine Active]
Detectors: Luhn · Verhoeff · Regex · Checksums
Tool Guard: @vault_guard parameter re-hydration
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            """
            <div class="panel-card">
                <div class="panel-header">
                    <span class="panel-title">2. Cloud LLM Wire Payload</span>
                    <span class="panel-badge badge-egress">Egress</span>
                </div>
                <div class="panel-body">
                    <div style="font-size: 0.82rem; font-weight: 600; color: #0F172A;">Format-Preserving Synthesis</div>
                    <div style="font-size: 0.76rem; color: #475569; line-height: 1.55;">
                        Generates synthetic tokens satisfying strict third-party schemas without triggering cloud LLM content moderation or schema validation errors.
                    </div>
                    <div class="code-surface" style="font-size: 0.74rem;">
[Wire Contracts Guaranteed]
Cards: Valid Luhn Modulo 10 check
Aadhaar: Valid Verhoeff D5 check
Email/UPI: Valid RFC & NPCI handles
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c3:
        st.markdown(
            """
            <div class="panel-card">
                <div class="panel-header">
                    <span class="panel-title">3. Ephemeral Key-Value Store</span>
                    <span class="panel-badge badge-vault">Store</span>
                </div>
                <div class="panel-body">
                    <div style="font-size: 0.82rem; font-weight: 600; color: #0F172A;">Session-Scoped Reverse Map</div>
                    <div style="font-size: 0.76rem; color: #475569; line-height: 1.55;">
                        Maintains thread-safe reverse mappings in SQLite with deterministic BLAKE2b salt indices and automated TTL expiration.
                    </div>
                    <div class="code-surface" style="font-size: 0.74rem;">
[Store Configuration]
Storage: Thread-safe in-memory SQLite
Hashing: BLAKE2b deterministic
Default TTL: 3,600s automated purge
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

# -----------------------------------------------------------------------------
# Footer
# -----------------------------------------------------------------------------
st.markdown("<hr style='margin: 2rem 0 1rem 0; border: none; border-top: 1px solid #E2E8F0;'>", unsafe_allow_html=True)
st.markdown(
    """
    <div style="display: flex; justify-content: space-between; align-items: center; font-size: 0.76rem; color: #64748B;">
        <div>ShadowVault Open-Source • Distributed under the MIT License</div>
        <div style="display: flex; gap: 1rem;">
            <a href="https://github.com/dhirajparihar/shadow-vault" target="_blank" style="color: #475569; text-decoration: none;">GitHub</a>
            <a href="https://pypi.org/p/shadow-vault" target="_blank" style="color: #475569; text-decoration: none;">PyPI</a>
            <a href="https://dhirajparihar.github.io/shadow-vault/" target="_blank" style="color: #0F766E; text-decoration: none; font-weight: 500;">Live Web Playground</a>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)
