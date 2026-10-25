"""
shadow-vault: A bi-directional, format-preserving reversible PII proxy for AI agents,
LangChain/LangGraph, and MCP tools.
"""

from shadow_vault.detectors import (
    DetectedEntity,
    EntityType,
    calculate_verhoeff,
    detect_aadhaar,
    detect_api_keys,
    detect_credit_cards,
    detect_emails,
    detect_entities,
    detect_pan_cards,
    detect_phones,
    detect_ssns,
    detect_upi_ids,
    is_luhn_valid,
    is_verhoeff_valid,
)
from shadow_vault.engine import ShadowVault
from shadow_vault.integrations.decorators import vault_guard
from shadow_vault.integrations.langchain import (
    ProtectedTool,
    ShadowVaultChatWrapper,
    protect_tool,
)
from shadow_vault.integrations.mcp_proxy import MCPVaultInterceptor
from shadow_vault.integrations.proxy_server import create_proxy_app
from shadow_vault.store import VaultStore
from shadow_vault.stream import StreamHydrator
from shadow_vault.synthesizer import (
    SYNTHETIC_PREFIXES,
    calculate_luhn_check_digit,
    is_synthetic,
    synthesize_token,
)

__version__ = "0.3.0"

__all__ = [
    # Engine & Store
    "ShadowVault",
    "VaultStore",
    "StreamHydrator",
    # Integrations
    "vault_guard",
    "protect_tool",
    "ProtectedTool",
    "ShadowVaultChatWrapper",
    "MCPVaultInterceptor",
    "create_proxy_app",
    # Synthesis
    "synthesize_token",
    "is_synthetic",
    "calculate_luhn_check_digit",
    "SYNTHETIC_PREFIXES",
    # Detection
    "DetectedEntity",
    "EntityType",
    "detect_entities",
    "detect_upi_ids",
    "detect_emails",
    "detect_credit_cards",
    "detect_aadhaar",
    "detect_pan_cards",
    "detect_phones",
    "detect_api_keys",
    "detect_ssns",
    # Mathematical Checksums
    "is_luhn_valid",
    "is_verhoeff_valid",
    "calculate_verhoeff",
]
