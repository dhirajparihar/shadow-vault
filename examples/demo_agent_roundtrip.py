"""
Zero-API-Key Interactive CLI Demo for shadow-vault.

Demonstrates the complete 4-stage bi-directional PII proxy lifecycle:
  Stage 1: User Input (Raw PII)
  Stage 2: What the Cloud LLM Sees (Format-Preserving Synthetic Tokens)
  Stage 3: Local MCP Tool Execution (Automatic Hydration & Return Dehydration)
  Stage 4: Live SSE Stream Re-Hydration (Chunked Streaming without Token Tearing)

Usage:
  python examples/demo_agent_roundtrip.py
"""

from __future__ import annotations

import os
import sys
import time

# Reconfigure stdout to utf-8 if possible
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure shadow_vault is importable when running directly from workspace root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from shadow_vault import (
    ShadowVault,
    StreamHydrator,
    is_luhn_valid,
    is_synthetic,
    is_verhoeff_valid,
    vault_guard,
)

# Enable ANSI escape code processing on Windows
os.system("")

# ANSI Color Constants
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_DIM = "\033[2m"
C_RED = "\033[1;31m"
C_GREEN = "\033[1;32m"
C_YELLOW = "\033[1;33m"
C_BLUE = "\033[1;34m"
C_MAGENTA = "\033[1;35m"
C_CYAN = "\033[1;36m"
C_WHITE = "\033[1;37m"


def print_banner() -> None:
    banner = f"""
{C_CYAN}{C_BOLD}================================================================================
                    SHADOW-VAULT : BI-DIRECTIONAL PII PROXY                     
       Format-Preserving Anonymization for AI Agents, LangChain & MCP           
================================================================================{C_RESET}
"""
    print(banner)


def print_section(title: str, subtitle: str) -> None:
    print(f"\n{C_YELLOW}{C_BOLD}[>] {title}{C_RESET}")
    print(f"{C_DIM}    {subtitle}{C_RESET}\n")


def print_box(content: str, color: str = C_WHITE, title: str | None = None) -> None:
    lines = content.strip().split("\n")
    max_len = max(len(line) for line in lines) if lines else 40
    width = max(max_len + 4, 76)

    border_color = color
    if title:
        header = f"+-- [ {title} ] " + ("-" * (width - len(title) - 8)) + "+"
    else:
        header = "+" + ("-" * (width - 2)) + "+"
    footer = "+" + ("-" * (width - 2)) + "+"

    print(f"{border_color}{header}{C_RESET}")
    for line in lines:
        padding = " " * (width - len(line) - 4)
        print(f"{border_color}|{C_RESET}  {line}{padding}{border_color}|{C_RESET}")
    print(f"{border_color}{footer}{C_RESET}")


def main() -> None:
    print_banner()

    vault = ShadowVault()
    session_id = "agent_interactive_demo"

    # ========================================================================
    # STAGE 1: User Input (Raw PII)
    # ========================================================================
    print_section(
        "STAGE 1: USER INPUT (Contains Highly Sensitive PII)",
        "The end-user submits a query with email, Indian PAN, UPI ID, mobile, and API key.",
    )

    raw_user_prompt = (
        "Please charge my pending invoice to dhiraj.sharma@example.com. "
        "My Indian PAN card is ABCDE1234F and pay via UPI dhiraj@okaxis. "
        "Primary mobile is +91 9876543210. "
        "Stripe key for auth: sk-live-51A2B3C4D5E6F7G8H9I0J1K2L3M4."
    )

    print_box(raw_user_prompt, color=C_RED, title="Raw Sensitive Prompt from Client")
    print(f"  {C_RED}[!] Sensitive items detected:{C_RESET}")
    print(f"    * Email:    {C_BOLD}dhiraj.sharma@example.com{C_RESET}")
    print(f"    * PAN Card: {C_BOLD}ABCDE1234F{C_RESET}")
    print(f"    * UPI ID:   {C_BOLD}dhiraj@okaxis{C_RESET}")
    print(f"    * Phone:    {C_BOLD}+91 9876543210{C_RESET}")
    print(f"    * API Key:  {C_BOLD}sk-live-51A2B3C4D5E6F7G8H9I0J1K2L3M4{C_RESET}")

    time.sleep(0.3)

    # ========================================================================
    # STAGE 2: What the Cloud LLM Sees (Format-Preserving Tokens)
    # ========================================================================
    print_section(
        "STAGE 2: WHAT THE CLOUD LLM SEES (Zero PII Leakage)",
        "ShadowVault automatically tokenizes entities into format-preserving synthetics.",
    )

    dehydrated_prompt = vault.dehydrate(raw_user_prompt, session_id=session_id)
    print_box(dehydrated_prompt, color=C_GREEN, title="Safe Payload Forwarded to Cloud LLM")

    session_map = vault.get_session_map(session_id)
    print(f"  {C_GREEN}[+] Format-Preserving Mapping Active in Vault Store:{C_RESET}")
    for synth, real in session_map.items():
        print(f"    * {C_CYAN}{synth:36}{C_RESET} {C_DIM}<--->{C_RESET} {C_WHITE}{real}{C_RESET}")

    time.sleep(0.3)

    # ========================================================================
    # STAGE 3: Local MCP Tool Execution (@vault_guard)
    # ========================================================================
    print_section(
        "STAGE 3: LOCAL MCP TOOL EXECUTION (Automatic Reversible Hydration)",
        "The LLM invokes an MCP tool. @vault_guard hydrates parameters and dehydrates outputs.",
    )

    synth_email = vault.store.get_synth_val(session_id, "dhiraj.sharma@example.com")
    synth_pan = vault.store.get_synth_val(session_id, "ABCDE1234F")
    synth_upi = vault.store.get_synth_val(session_id, "dhiraj@okaxis")

    # Define a guarded tool
    @vault_guard(vault=vault, session_id_arg="session_id")
    def charge_and_sync_db(
        customer_email: str,
        pan: str,
        upi_id: str,
        session_id: str = "default",
    ) -> dict[str, str]:
        # Inside the tool function: Real data is received!
        print(f"    {C_BLUE}[Local MCP Tool Execution]{C_RESET}")
        print(f"      Hydrated Customer Email: {C_BOLD}{customer_email}{C_RESET}")
        print(f"      Hydrated Indian PAN:     {C_BOLD}{pan}{C_RESET}")
        print(f"      Hydrated UPI Handle:     {C_BOLD}{upi_id}{C_RESET}")

        # The tool performs a database query and retrieves fresh sensitive customer records
        return {
            "status": "PAYMENT_CONFIRMED",
            "account_owner": customer_email,
            "pan_verified": pan,
            "backup_mobile": "+91 9123456789",  # Fresh PII returned from internal database!
            "virtual_card": "4532 0151 1283 0366",  # Fresh Credit Card returned from database!
        }

    print(f"  {C_DIM}1. AI Agent invokes tool with synthetic tokens:{C_RESET}")
    print(f"     email='{synth_email}', pan='{synth_pan}', upi='{synth_upi}'\n")

    tool_result = charge_and_sync_db(
        customer_email=synth_email,
        pan=synth_pan,
        upi_id=synth_upi,
        session_id=session_id,
    )

    print(f"\n  {C_DIM}2. Result automatically sanitized before returning back to Agent:{C_RESET}")
    print_box(
        str(tool_result),
        color=C_CYAN,
        title="Sanitized Tool Output (Safe to append to Agent State)",
    )
    print(f"    * {C_GREEN}Backup mobile auto-dehydrated to:{C_RESET} {tool_result['backup_mobile']}")
    print(f"    * {C_GREEN}Virtual card auto-dehydrated to: {C_RESET} {tool_result['virtual_card']}")

    time.sleep(0.3)

    # ========================================================================
    # STAGE 4: Live SSE Stream Re-Hydration
    # ========================================================================
    print_section(
        "STAGE 4: LIVE SSE STREAM RE-HYDRATION (Zero Token Tearing)",
        "The LLM streams output in small chunks. StreamHydrator smoothly re-hydrates tokens.",
    )

    synth_backup_phone = tool_result["backup_mobile"]
    synth_card = tool_result["virtual_card"]

    simulated_llm_stream_chunks = [
        "Receipt: Your payment ",
        "was successful! ",
        "A confirmation has been ",
        f"sent to {synth_email[:6]}",  # Token torn across chunk 1
        f"{synth_email[6:16]}",       # Token torn across chunk 2
        f"{synth_email[16:]}. ",      # Token completed
        "Card on file: ",
        f"{synth_card[:8]}",          # Card torn across chunk 1
        f"{synth_card[8:]}. ",        # Card completed
        "SMS sent to your backup: ",
        f"{synth_backup_phone[:7]}",  # Phone torn
        f"{synth_backup_phone[7:]}. ",# Phone completed
        "Thank you for using ShadowVault!",
    ]

    print(f"  {C_MAGENTA}Incoming LLM Chunks (Simulating SSE Stream):{C_RESET}")
    stream_hydrator = vault.stream(session_id=session_id)

    print(f"  {C_WHITE}Live Output to User Terminal: {C_RESET}", end="", flush=True)

    for chunk in simulated_llm_stream_chunks:
        emitted = stream_hydrator.process_chunk(chunk)
        if emitted:
            for char in emitted:
                sys.stdout.write(char)
                sys.stdout.flush()
                time.sleep(0.005)
        time.sleep(0.03)

    final_flushed = stream_hydrator.flush()
    if final_flushed:
        for char in final_flushed:
            sys.stdout.write(char)
            sys.stdout.flush()
            time.sleep(0.005)

    print("\n")
    print(f"{C_GREEN}{C_BOLD}[OK] All 4 stages completed successfully! Zero API keys required.{C_RESET}\n")

    vault.close()


if __name__ == "__main__":
    main()
