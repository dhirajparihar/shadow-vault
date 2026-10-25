"""
ShadowVault Enterprise Interactive Web Playground.

A production-grade developer console demonstrating format-preserving,
bi-directional PII proxying for AI agents, LangChain/LangGraph, and MCP tools.
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
    page_title="ShadowVault — Enterprise PII Proxy Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# -----------------------------------------------------------------------------
# Premium Enterprise Light Theme Design Tokens & CSS
# -----------------------------------------------------------------------------
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap');

    :root {
        --bg-page: #F7F9FC;
        --surface-primary: #FFFFFF;
        --surface-muted: #F0F4F8;
        --text-primary: #172033;
        --text-secondary: #667085;
        --text-tertiary: #98A2B3;
        --border-default: #E4E9F0;
        --border-subtle: #EEF2F6;
        --accent-teal: #0F766E;
        --accent-teal-bg: #F0FDFA;
        --accent-teal-border: #CCFBF1;
        --accent-red: #C2413B;
        --accent-red-bg: #FEF2F2;
        --accent-red-border: #FECACA;
        --accent-blue: #315EAB;
        --accent-blue-bg: #EFF6FF;
        --accent-blue-border: #DBEAFE;
    }

    /* Base Page Styling */
    .stApp {
        background-color: var(--bg-page);
        color: var(--text-primary);
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }

    [data-testid="stSidebar"] {
        background-color: var(--surface-primary);
        border-right: 1px solid var(--border-default);
    }

    /* Headers & Typography */
    h1, h2, h3, h4, h5, h6 {
        font-family: 'Plus Jakarta Sans', sans-serif !important;
        color: var(--text-primary) !important;
        letter-spacing: -0.015em;
    }

    code, pre, .mono-font {
        font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace !important;
    }

    /* Top Brand & Header */
    .brand-container {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 0.5rem 0 1.25rem 0;
        border-bottom: 1px solid var(--border-default);
        margin-bottom: 1.5rem;
    }

    .brand-title-wrap {
        display: flex;
        align-items: center;
        gap: 0.75rem;
    }

    .brand-icon {
        width: 38px;
        height: 38px;
        border-radius: 8px;
        background: #0F766E;
        color: #FFFFFF;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 1.2rem;
        font-weight: 700;
        box-shadow: 0 1px 2px rgba(15, 118, 110, 0.2);
    }

    .brand-title {
        font-size: 1.35rem;
        font-weight: 700;
        color: var(--text-primary);
        line-height: 1.2;
    }

    .brand-subtitle {
        font-size: 0.82rem;
        color: var(--text-secondary);
        margin-top: 0.1rem;
    }

    .status-pill {
        display: inline-flex;
        align-items: center;
        gap: 0.4rem;
        padding: 0.3rem 0.65rem;
        border-radius: 9999px;
        font-size: 0.75rem;
        font-weight: 500;
        border: 1px solid var(--border-default);
        background: var(--surface-primary);
        color: var(--text-secondary);
    }

    .status-dot-active {
        width: 7px;
        height: 7px;
        border-radius: 50%;
        background-color: var(--accent-teal);
    }

    .status-dot-idle {
        width: 7px;
        height: 7px;
        border-radius: 50%;
        background-color: var(--text-tertiary);
    }

    /* Pipeline Banner Flow */
    .pipeline-nav {
        display: grid;
        grid-template-columns: 1fr 1fr 1fr;
        gap: 0.75rem;
        margin-bottom: 1.25rem;
    }

    .pipeline-step {
        background: var(--surface-primary);
        border: 1px solid var(--border-default);
        border-radius: 8px;
        padding: 0.75rem 1rem;
        display: flex;
        align-items: center;
        gap: 0.65rem;
    }

    .step-num {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.75rem;
        font-weight: 700;
        color: var(--text-secondary);
        background: var(--surface-muted);
        border: 1px solid var(--border-subtle);
        width: 24px;
        height: 24px;
        border-radius: 6px;
        display: flex;
        align-items: center;
        justify-content: center;
    }

    .step-text {
        font-size: 0.8rem;
        font-weight: 600;
        color: var(--text-primary);
    }

    .step-sub {
        font-size: 0.7rem;
        color: var(--text-secondary);
    }

    /* Professional Card Surfaces */
    .console-card {
        background: var(--surface-primary);
        border: 1px solid var(--border-default);
        border-radius: 10px;
        padding: 1.25rem;
        box-shadow: 0 1px 3px rgba(16, 24, 40, 0.04);
        margin-bottom: 1.25rem;
    }

    .card-header-bar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding-bottom: 0.75rem;
        border-bottom: 1px solid var(--border-default);
        margin-bottom: 1rem;
    }

    .card-title {
        font-size: 0.88rem;
        font-weight: 700;
        color: var(--text-primary);
        display: flex;
        align-items: center;
        gap: 0.45rem;
    }

    .card-badge {
        font-size: 0.7rem;
        font-weight: 600;
        padding: 0.15rem 0.5rem;
        border-radius: 4px;
        text-transform: uppercase;
        letter-spacing: 0.03em;
    }

    .badge-trusted {
        background: var(--accent-red-bg);
        color: var(--accent-red);
        border: 1px solid var(--accent-red-border);
    }

    .badge-cloud {
        background: var(--accent-teal-bg);
        color: var(--accent-teal);
        border: 1px solid var(--accent-teal-border);
    }

    .badge-vault {
        background: var(--accent-blue-bg);
        color: var(--accent-blue);
        border: 1px solid var(--accent-blue-border);
    }

    /* Metric Cards */
    .metric-grid {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 0.75rem;
        margin-bottom: 1.25rem;
    }

    .metric-cell {
        background: var(--surface-primary);
        border: 1px solid var(--border-default);
        border-radius: 8px;
        padding: 0.85rem 1rem;
        box-shadow: 0 1px 2px rgba(16, 24, 40, 0.03);
    }

    .metric-label {
        font-size: 0.72rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.04em;
        color: var(--text-secondary);
        margin-bottom: 0.35rem;
    }

    .metric-val {
        font-family: 'JetBrains Mono', monospace;
        font-size: 1.45rem;
        font-weight: 700;
        color: var(--text-primary);
    }

    .metric-desc {
        font-size: 0.7rem;
        color: var(--text-tertiary);
        margin-top: 0.2rem;
    }

    /* Token Chips */
    .token-real {
        background-color: var(--accent-red-bg);
        color: var(--accent-red) !important;
        border: 1px solid var(--accent-red-border);
        padding: 0.1rem 0.4rem;
        border-radius: 4px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.82em;
        font-weight: 500;
        display: inline-block;
        margin: 1px 0;
    }

    .token-synthetic {
        background-color: var(--accent-teal-bg);
        color: var(--accent-teal) !important;
        border: 1px solid var(--accent-teal-border);
        padding: 0.1rem 0.4rem;
        border-radius: 4px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.82em;
        font-weight: 500;
        display: inline-block;
        margin: 1px 0;
    }

    /* Monospace Payload Viewer */
    .payload-surface {
        background-color: #F8FAFC;
        border: 1px solid var(--border-default);
        border-radius: 6px;
        padding: 0.85rem 1rem;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.82rem;
        line-height: 1.6;
        color: #1E293B;
        word-break: break-word;
        white-space: pre-wrap;
        max-height: 220px;
        overflow-y: auto;
    }

    /* Sidebar Refinement */
    .sidebar-section-title {
        font-size: 0.72rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: var(--text-tertiary);
        margin-bottom: 0.5rem;
    }

    .sidebar-card {
        background: var(--surface-muted);
        border: 1px solid var(--border-default);
        border-radius: 6px;
        padding: 0.75rem;
        font-size: 0.78rem;
        color: var(--text-secondary);
        margin-bottom: 1rem;
        line-height: 1.45;
    }

    /* Streamlit Widget Overrides */
    div[data-testid="stTextInput"] input, div[data-testid="stTextArea"] textarea {
        background-color: var(--surface-primary) !important;
        border: 1px solid var(--border-default) !important;
        border-radius: 6px !important;
        color: var(--text-primary) !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 0.85rem !important;
    }

    div[data-testid="stTextInput"] input:focus, div[data-testid="stTextArea"] textarea:focus {
        border-color: var(--accent-teal) !important;
        box-shadow: 0 0 0 1px var(--accent-teal) !important;
    }

    button[kind="primary"] {
        background-color: var(--accent-teal) !important;
        border-color: var(--accent-teal) !important;
        color: #FFFFFF !important;
        font-weight: 600 !important;
        border-radius: 6px !important;
        padding: 0.55rem 1.25rem !important;
    }

    button[kind="primary"]:hover {
        background-color: #0D655E !important;
    }

    button[kind="secondary"] {
        background-color: var(--surface-primary) !important;
        border: 1px solid var(--border-default) !important;
        color: var(--text-primary) !important;
        border-radius: 6px !important;
    }

    /* Validation Items */
    .validation-row {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.78rem;
        padding: 0.35rem 0;
        border-bottom: 1px solid var(--border-subtle);
    }

    .validation-check {
        color: var(--accent-teal);
        font-weight: 700;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# -----------------------------------------------------------------------------
# Pre-loaded Enterprise Scenarios
# -----------------------------------------------------------------------------
SCENARIOS: dict[str, dict[str, Any]] = {
    "Fintech Payment & Chargeback Agent": {
        "title": "Fintech Payment & Chargeback Agent",
        "description": "Handles card chargebacks, Indian PAN verification, and instant UPI settlements within trusted banking boundaries.",
        "prompt": (
            "Please process an immediate chargeback of $450 to customer dhiraj.sharma@example.com. "
            "Verify identity with Indian PAN card ABCDE1234F and process settlement via UPI handle dhiraj@okaxis. "
            "Primary phone: +91 9876543210. Card on file: 4532 0151 1283 0366. "
            "Authorize with Stripe key sk-live-51A2B3C4D5E6F7G8H9I0J1K2L3M4."
        ),
        "tool_name": "stripe_chargeback_mcp_tool",
        "tool_doc": "Authorized local payment gateway with internal Stripe API and core database access.",
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
        "description": "Schedules specialist clinical consultations with HIPAA SSN & national identity UID de-identification.",
        "prompt": (
            "Confirm urgent cardiology consultation booking for patient Sarah Jenkins "
            "(SSN: 123-45-6789, Email: sarah.jenkins@healthnet.org, Mobile: (555) 234-5678). "
            "Patient Aadhaar UID for international travel insurance clearance: 3675 9834 6015. "
            "Bill insurance carrier using portal auth key sk-live-med7788990011223344."
        ),
        "tool_name": "epic_health_ehr_mcp_tool",
        "tool_doc": "On-premise Electronic Health Records (EHR) gateway operating strictly within HIPAA perimeters.",
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
        "description": "Triage cluster incidents across observability logs containing engineer contact PII and administrative credentials.",
        "prompt": (
            "Investigate anomalous 504 gateway timeout incidents on production cluster. "
            "Primary engineer on-call: alex.devops@datadog-internal.io (+1 415-555-0199). "
            "Auth credential for Grafana API: sk-proj-9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d. "
            "Backup cluster token: sk-live-8833441122aabbccddeeff0011223344."
        ),
        "tool_name": "kubernetes_sre_mcp_tool",
        "tool_doc": "Private infrastructure MCP runner executing telemetry and cluster diagnostics inside VPC.",
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
# Initialize Application State
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
# Helper Utilities for Token Highlighting (Strict HTML Escaped)
# -----------------------------------------------------------------------------
def highlight_real_pii(text: str) -> str:
    """Highlight detected PII spans with red styling, safely HTML-escaped."""
    entities = detect_entities(text)
    if not entities:
        return html.escape(text)

    # Sort reverse to substitute spans by character index safely
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
    """Highlight synthetic tokens with teal styling, safely HTML-escaped."""
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
    """Mask real PII value by default, preserving last 4 characters for verification."""
    if reveal:
        return val
    clean = str(val).strip()
    if len(clean) <= 4:
        return "••••"
    return "••••••••" + clean[-4:]


# -----------------------------------------------------------------------------
# Sidebar: Navigation, Scenario Selection & Configuration
# -----------------------------------------------------------------------------
with st.sidebar:
    # Wordmark & Identity
    st.markdown(
        """
        <div style="display: flex; align-items: center; gap: 0.6rem; margin-bottom: 0.25rem;">
            <div style="width: 28px; height: 28px; border-radius: 6px; background: #0F766E; color: #FFF; display: flex; align-items: center; justify-content: center; font-size: 0.95rem; font-weight: 700;">🛡️</div>
            <div style="font-size: 1.15rem; font-weight: 700; color: #172033; letter-spacing: -0.01em;">ShadowVault</div>
            <span style="font-size: 0.68rem; font-weight: 600; background: #F0F4F8; color: #667085; padding: 1px 6px; border-radius: 4px; border: 1px solid #E4E9F0;">v0.3.0</span>
        </div>
        <div style="font-size: 0.78rem; color: #667085; margin-bottom: 1.25rem;">
            Reversible PII protection for AI agents, LangChain & MCP tools.
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown('<div class="sidebar-section-title">Scenario Workspace</div>', unsafe_allow_html=True)
    scenario_keys = list(SCENARIOS.keys())
    selected_scenario_name = st.selectbox(
        label="Scenario Selector",
        options=scenario_keys,
        index=scenario_keys.index(st.session_state.active_scenario_name) if st.session_state.active_scenario_name in scenario_keys else 0,
        label_visibility="collapsed",
    )

    # Sync scenario changes cleanly
    if selected_scenario_name != st.session_state.active_scenario_name:
        st.session_state.active_scenario_name = selected_scenario_name
        st.session_state.prompt_text = SCENARIOS[selected_scenario_name]["prompt"]
        st.session_state.pipeline_result = None
        st.rerun()

    current_scenario = SCENARIOS[st.session_state.active_scenario_name]
    st.markdown(
        f'<div class="sidebar-card">{html.escape(current_scenario["description"])}</div>',
        unsafe_allow_html=True,
    )

    st.markdown('<div class="sidebar-section-title">Session Configuration</div>', unsafe_allow_html=True)
    session_id = st.text_input("Active Session ID:", value="session_playground_01", help="Isolates reverse token mappings to this conversation thread.")
    ttl_seconds = st.slider("Vault Session TTL (seconds):", min_value=60, max_value=86400, value=3600, step=60, help="In-memory SQLite automated cleanup timeout.")

    # Advanced Settings
    with st.expander("Advanced Settings & Security Controls", expanded=False):
        reveal_pii = st.checkbox("Reveal unmasked PII in vault table", value=False, help="When disabled, real values are masked with •••• in UI inspection tables.")
        st.markdown("<hr style='margin: 0.5rem 0; border: none; border-top: 1px solid #E4E9F0;'>", unsafe_allow_html=True)

        if not st.session_state.confirm_clear:
            if st.button("Clear Active Session Vault", use_container_width=True):
                st.session_state.confirm_clear = True
                st.rerun()
        else:
            st.warning(f"Purge all cached tokens for '{session_id}'?")
            c_col1, c_col2 = st.columns(2)
            with c_col1:
                if st.button("Yes, Purge", use_container_width=True, type="primary"):
                    store.clear_session(session_id)
                    st.session_state.pipeline_result = None
                    st.session_state.confirm_clear = False
                    st.success(f"Purged '{session_id}'.")
                    st.rerun()
            with c_col2:
                if st.button("Cancel", use_container_width=True):
                    st.session_state.confirm_clear = False
                    st.rerun()

    st.markdown("<hr style='margin: 1.25rem 0; border: none; border-top: 1px solid #E4E9F0;'>", unsafe_allow_html=True)
    st.markdown('<div class="sidebar-section-title">Developer Resources</div>', unsafe_allow_html=True)
    st.markdown(
        """
        <div style="font-size: 0.8rem; line-height: 1.8;">
            <a href="https://github.com/dhirajparihar/shadow-vault" target="_blank" style="color: #0F766E; text-decoration: none; font-weight: 500;">↗ GitHub Repository</a><br>
            <a href="https://pypi.org/p/shadow-vault" target="_blank" style="color: #0F766E; text-decoration: none; font-weight: 500;">↗ PyPI Distribution</a><br>
            <a href="https://github.com/dhirajparihar/shadow-vault/blob/main/CONTRIBUTING.md" target="_blank" style="color: #667085; text-decoration: none;">↗ Contributing Guide</a>
        </div>
        """,
        unsafe_allow_html=True,
    )


# -----------------------------------------------------------------------------
# Main Header: Product Identity & Execution State
# -----------------------------------------------------------------------------
header_col1, header_col2 = st.columns([0.72, 0.28])

with header_col1:
    st.markdown(
        """
        <div class="brand-container">
            <div class="brand-title-wrap">
                <div class="brand-icon">🛡️</div>
                <div>
                    <div class="brand-title">ShadowVault Console</div>
                    <div class="brand-subtitle">Reversible, format-preserving PII proxy for AI agents, LangChain & MCP tools</div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with header_col2:
    is_active = st.session_state.pipeline_result is not None
    last_ms = st.session_state.pipeline_result.get("dehydrate_ms", 0.0) if is_active else 0.0
    status_html = (
        f'<div style="text-align: right; padding-top: 0.8rem;">'
        f'<span class="status-pill">'
        f'<span class="status-dot-active"></span>'
        f'Pipeline Active • {last_ms:.2f} ms'
        f'</span>'
        f'</div>'
        if is_active
        else
        f'<div style="text-align: right; padding-top: 0.8rem;">'
        f'<span class="status-pill">'
        f'<span class="status-dot-idle"></span>'
        f'Ready for Execution'
        f'</span>'
        f'</div>'
    )
    st.markdown(status_html, unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# Agent Prompt Composer: Primary Action Section
# -----------------------------------------------------------------------------
with st.container():
    st.markdown(
        """
        <div style="display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 0.4rem;">
            <div style="font-size: 0.92rem; font-weight: 700; color: #172033;">Agent Prompt Composer</div>
            <div style="font-size: 0.74rem; color: #667085;">Inspect how real sensitive inputs transform into schema-compatible synthetic tokens.</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Prompt text area bound to session_state
    user_prompt = st.text_area(
        label="Agent Prompt Input",
        value=st.session_state.prompt_text,
        height=100,
        label_visibility="collapsed",
        key="prompt_input_field",
    )
    # Track edits so user modifications persist
    st.session_state.prompt_text = user_prompt

    # Action Controls Row
    btn_col1, btn_col2, btn_spacer = st.columns([0.38, 0.22, 0.40])
    with btn_col1:
        run_requested = st.button("⚡ Run Protection Pipeline", type="primary", use_container_width=True)
    with btn_col2:
        if st.button("Reset Example", use_container_width=True):
            st.session_state.prompt_text = current_scenario["prompt"]
            st.session_state.pipeline_result = None
            st.rerun()


# -----------------------------------------------------------------------------
# Core Pipeline Execution Logic (Only executed on explicit click)
# -----------------------------------------------------------------------------
if run_requested:
    try:
        # 1. Update TTL and Dehydrate
        store.ttl_seconds = ttl_seconds
        t0 = time.perf_counter()
        dehydrated_prompt = vault.dehydrate(st.session_state.prompt_text, session_id=session_id)
        dehydrate_ms = (time.perf_counter() - t0) * 1000.0

        # Retrieve session mapping
        session_map = store.get_session_map(session_id)

        # 2. Build Synthetic Tool Arguments from Active Session Map
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

        # 3. Local Guarded MCP Tool Execution
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

        # Tool return auto-dehydration demonstration
        raw_output = tool_execution_res.get("raw_output", {})
        dehydrated_output = vault.dehydrate(raw_output, session_id=session_id)

        # 4. StreamHydrator SSE Demonstration
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

        # 5. Schema Validation Checks on Synthesized Tokens
        validations: list[dict[str, Any]] = []
        for synth in session_map.keys():
            if synth.startswith("400000"):
                ok = is_luhn_valid(synth)
                validations.append({"entity": "CREDIT_CARD", "token": synth, "rule": "Modulo 10 (Luhn) checksum", "passed": ok})
            elif synth.startswith("3") and len(synth.replace(" ", "")) == 12:
                ok = is_verhoeff_valid(synth.replace(" ", ""))
                validations.append({"entity": "AADHAAR", "token": synth, "rule": "Verhoeff dihedral D5 check", "passed": ok})
            elif "@shadow.vault" in synth:
                validations.append({"entity": "EMAIL", "token": synth, "rule": "Pydantic EmailStr format", "passed": True})
            elif "@okshadow" in synth:
                validations.append({"entity": "UPI_ID", "token": synth, "rule": "NPCI VPA virtual address", "passed": True})
            elif synth.startswith("SHDWV"):
                validations.append({"entity": "PAN_CARD", "token": synth, "rule": "Income Tax [A-Z]{5}[0-9]{4}[A-Z]{1}", "passed": True})

        # Cache in session state
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
    except Exception as exc:
        st.error(f"Execution error during protection pipeline: {exc}")


# -----------------------------------------------------------------------------
# Results Presentation (Rendered if pipeline has run)
# -----------------------------------------------------------------------------
if st.session_state.pipeline_result is not None:
    res = st.session_state.pipeline_result

    # 1. Performance & Status Row
    records_count = store.count(session_id)
    st.markdown(
        f"""
        <div class="metric-grid">
            <div class="metric-cell">
                <div class="metric-label">De-Identification Latency</div>
                <div class="metric-val">{res['dehydrate_ms']:.2f} ms</div>
                <div class="metric-desc">Sub-millisecond regex & checksum scan</div>
            </div>
            <div class="metric-cell">
                <div class="metric-label">Tool Restoration Latency</div>
                <div class="metric-val">{res['tool_ms']:.3f} ms</div>
                <div class="metric-desc">@vault_guard parameter re-hydration</div>
            </div>
            <div class="metric-cell">
                <div class="metric-label">Stream Chunk Latency</div>
                <div class="metric-val">{res['stream_ms']:.3f} ms</div>
                <div class="metric-desc">StreamHydrator lookahead holdback</div>
            </div>
            <div class="metric-cell">
                <div class="metric-label">Session Vault Mappings</div>
                <div class="metric-val">{records_count} active</div>
                <div class="metric-desc">SQLite in-memory with TTL ({ttl_seconds}s)</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 2. Pipeline Visual Step Indicators
    st.markdown(
        """
        <div class="pipeline-nav">
            <div class="pipeline-step">
                <div class="step-num">01</div>
                <div>
                    <div class="step-text">Trusted Local Input</div>
                    <div class="step-sub">Raw prompt & local tool boundary</div>
                </div>
            </div>
            <div class="pipeline-step">
                <div class="step-num">02</div>
                <div>
                    <div class="step-text">Cloud-Safe Wire Payload</div>
                    <div class="step-sub">Format-preserving synthetic tokens</div>
                </div>
            </div>
            <div class="pipeline-step">
                <div class="step-num">03</div>
                <div>
                    <div class="step-text">Ephemeral Vault & Tool Sync</div>
                    <div class="step-sub">Live reverse mapping & metrics</div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 3. Three-Stage Hero Columns
    col1, col2, col3 = st.columns([1, 1, 1], gap="medium")

    # =========================================================================
    # STAGE 1: Trusted Input & Local MCP Tool
    # =========================================================================
    with col1:
        st.markdown(
            """
            <div class="console-card">
                <div class="card-header-bar">
                    <div class="card-title">01 / Trusted Input & Local Tool</div>
                    <span class="card-badge badge-trusted">Trusted Perimeter</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("<div style='font-size: 0.78rem; font-weight: 600; color: #667085; margin-bottom: 0.35rem;'>Original Prompt (Detected PII in Red):</div>", unsafe_allow_html=True)
        highlighted_prompt = highlight_real_pii(res["prompt_text"])
        st.markdown(f'<div class="payload-surface">{highlighted_prompt}</div>', unsafe_allow_html=True)

        st.markdown(f"<div style='font-size: 0.78rem; font-weight: 600; color: #667085; margin-top: 1rem; margin-bottom: 0.35rem;'>Local Tool Invocation (<code>{html.escape(current_scenario['tool_name'])}</code>):</div>", unsafe_allow_html=True)
        st.caption("Agent passed synthetic tokens over wire; @vault_guard restored real PII before function execution:")
        hydrated_kwargs = res["tool_execution_res"].get("hydrated_received_kwargs", {})
        st.json(hydrated_kwargs)

        st.markdown("<div style='font-size: 0.78rem; font-weight: 600; color: #667085; margin-top: 0.8rem; margin-bottom: 0.35rem;'>Tool Output (Auto-Sanitized Before Agent Return):</div>", unsafe_allow_html=True)
        st.json(res["dehydrated_output"])

    # =========================================================================
    # STAGE 2: Cloud-Safe Wire Payload
    # =========================================================================
    with col2:
        st.markdown(
            """
            <div class="console-card">
                <div class="card-header-bar">
                    <div class="card-title">02 / Cloud-Safe Wire Payload</div>
                    <span class="card-badge badge-cloud">Zero PII Leakage</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("<div style='font-size: 0.78rem; font-weight: 600; color: #667085; margin-bottom: 0.35rem;'>Forwarded to Cloud LLM (Synthetic Tokens in Teal):</div>", unsafe_allow_html=True)
        active_session_map = store.get_session_map(session_id)
        highlighted_wire = highlight_synthetic_tokens(res["dehydrated_prompt"], active_session_map)
        st.markdown(f'<div class="payload-surface">{highlighted_wire}</div>', unsafe_allow_html=True)

        st.markdown("<div style='font-size: 0.78rem; font-weight: 600; color: #667085; margin-top: 1rem; margin-bottom: 0.35rem;'>Downstream Schema Validations:</div>", unsafe_allow_html=True)
        validations_list = res.get("validations", [])
        if validations_list:
            val_items_html = ""
            for v in validations_list[:5]:
                val_items_html += (
                    f'<div class="validation-row">'
                    f'<span class="validation-check">✓</span>'
                    f'<span><code>{html.escape(v["token"])}</code>: {html.escape(v["rule"])}</span>'
                    f'</div>'
                )
            st.markdown(f'<div class="payload-surface" style="padding: 0.5rem 0.85rem;">{val_items_html}</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div class="payload-surface">Synthetic tokens adhere to standard downstream schemas.</div>', unsafe_allow_html=True)

        st.markdown("<div style='font-size: 0.78rem; font-weight: 600; color: #667085; margin-top: 0.8rem; margin-bottom: 0.35rem;'>Streaming Re-Hydration (StreamHydrator):</div>", unsafe_allow_html=True)
        st.caption("Buffers fragmented SSE chunks (e.g., 'u_8', 'f9@shadow') and emits clean text without token tearing:")
        st.markdown(
            f'<div class="payload-surface" style="background: #F0FDFA; border-color: #CCFBF1; color: #0F766E;">'
            f'{html.escape(res["rehydrated_stream"])}'
            f'</div>',
            unsafe_allow_html=True,
        )

    # =========================================================================
    # STAGE 3: Ephemeral Vault & Live Table
    # =========================================================================
    with col3:
        st.markdown(
            """
            <div class="console-card">
                <div class="card-header-bar">
                    <div class="card-title">03 / Ephemeral Vault & Mappings</div>
                    <span class="card-badge badge-vault">In-Memory / SQLite</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown(
            f"<div style='font-size: 0.78rem; font-weight: 600; color: #667085; margin-bottom: 0.35rem;'>"
            f"Active Session Store: <code>{html.escape(session_id)}</code>"
            f"</div>",
            unsafe_allow_html=True,
        )

        # Retrieve live records from VaultStore
        records = store.get_session_records(session_id)
        if records:
            table_rows = []
            for r in records:
                safe_real = mask_sensitive_value(r["real_val"], reveal=reveal_pii)
                created_str = datetime.fromtimestamp(r["created_at"]).strftime("%H:%M:%S")
                table_rows.append({
                    "Entity": r["entity_type"],
                    "Synthetic Token": r["synth_val"],
                    "Original Value": safe_real,
                    "Created": created_str,
                })

            st.dataframe(
                table_rows,
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info("No active mappings registered for this session.")

        st.markdown("<div style='font-size: 0.78rem; font-weight: 600; color: #667085; margin-top: 0.8rem; margin-bottom: 0.35rem;'>Vault Architectural Guarantees:</div>", unsafe_allow_html=True)
        st.markdown(
            """
            <div style="font-size: 0.75rem; color: #667085; line-height: 1.6; background: #F8FAFC; border: 1px solid #E4E9F0; border-radius: 6px; padding: 0.75rem;">
                • <strong>Deterministic Hashing:</strong> BLAKE2b salts ensure coreference consistency.<br>
                • <strong>Automated Eviction:</strong> Session TTL prunes records older than configured timeout.<br>
                • <strong>Zero ML Load:</strong> Pure Python checksum algorithms execute under 1ms.
            </div>
            """,
            unsafe_allow_html=True,
        )

else:
    # -------------------------------------------------------------------------
    # Calm Empty State: Three-Stage Flow Overview
    # -------------------------------------------------------------------------
    st.markdown(
        """
        <div style="text-align: center; padding: 2.5rem 1rem; background: #FFFFFF; border: 1px solid #E4E9F0; border-radius: 12px; margin-top: 1rem;">
            <div style="font-size: 2rem; margin-bottom: 0.5rem;">🛡️</div>
            <div style="font-size: 1.1rem; font-weight: 700; color: #172033; margin-bottom: 0.3rem;">Ready to Execute Protection Pipeline</div>
            <div style="font-size: 0.85rem; color: #667085; max-width: 580px; margin: 0 auto 1.5rem auto;">
                Click <strong>"⚡ Run Protection Pipeline"</strong> above to observe format-preserving de-identification across user input, cloud payload, and local tool execution.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Three-Stage Flow Preview Cards
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(
            """
            <div class="console-card" style="margin-top: 1rem;">
                <div style="font-size: 0.72rem; font-weight: 700; color: #C2413B; text-transform: uppercase; margin-bottom: 0.4rem;">01 / Trusted Input</div>
                <div style="font-size: 0.88rem; font-weight: 700; color: #172033; margin-bottom: 0.4rem;">Sensitive Entity Detection</div>
                <div style="font-size: 0.78rem; color: #667085; line-height: 1.5;">
                    Scans strings and Pydantic models for Credit Cards, Aadhaar, PAN, UPI, emails, and API keys. Keeps real data locked inside your boundary.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            """
            <div class="console-card" style="margin-top: 1rem;">
                <div style="font-size: 0.72rem; font-weight: 700; color: #0F766E; text-transform: uppercase; margin-bottom: 0.4rem;">02 / Cloud-Safe Payload</div>
                <div style="font-size: 0.88rem; font-weight: 700; color: #172033; margin-bottom: 0.4rem;">Schema-Preserving Synthesis</div>
                <div style="font-size: 0.78rem; color: #667085; line-height: 1.5;">
                    Synthesizes realistic tokens that pass strict Luhn (cards), Verhoeff (Aadhaar), and Pydantic validators without triggering cloud LLM redaction filters.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c3:
        st.markdown(
            """
            <div class="console-card" style="margin-top: 1rem;">
                <div style="font-size: 0.72rem; font-weight: 700; color: #315EAB; text-transform: uppercase; margin-bottom: 0.4rem;">03 / Local Restoration</div>
                <div style="font-size: 0.88rem; font-weight: 700; color: #172033; margin-bottom: 0.4rem;">Reversible Tool Hydration</div>
                <div style="font-size: 0.78rem; color: #667085; line-height: 1.5;">
                    Local tools decorated with <code>@vault_guard</code> receive real PII before function execution and sanitize database return values automatically.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

# -----------------------------------------------------------------------------
# Footer
# -----------------------------------------------------------------------------
st.markdown("<hr style='margin: 2rem 0 1rem 0; border: none; border-top: 1px solid #E4E9F0;'>", unsafe_allow_html=True)
st.markdown(
    """
    <div style="display: flex; justify-content: space-between; align-items: center; font-size: 0.78rem; color: #98A2B3;">
        <div>ShadowVault Open-Source • Distributed under the MIT License</div>
        <div>
            <a href="https://github.com/dhirajparihar/shadow-vault" target="_blank" style="color: #667085; text-decoration: none; margin-right: 1rem;">GitHub</a>
            <a href="https://pypi.org/p/shadow-vault" target="_blank" style="color: #667085; text-decoration: none; margin-right: 1rem;">PyPI</a>
            <a href="https://dhirajparihar.github.io/shadow-vault/" target="_blank" style="color: #0F766E; text-decoration: none; font-weight: 600;">Live Web Playground</a>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)
