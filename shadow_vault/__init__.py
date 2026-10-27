"""
shadow-vault: A bi-directional, format-preserving reversible PII proxy for AI agents,
LangChain/LangGraph, and MCP tools.
"""

from shadow_vault.crypto import (
    blind_index,
    decrypt_value,
    derive_key,
    encrypt_value,
)
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
from shadow_vault.integrations.mcp_proxy import MCPVaultInterceptor, run_mcp_stdio_proxy
from shadow_vault.policy import (
    FailClosedAction,
    PIILeakBlockedError,
    PolicyManager,
    ToolPolicy,
    UnmappedTokenError,
)
from shadow_vault.store import VaultStore
from shadow_vault.stream import StreamHydrator

# Optional framework integrations (only loaded if dependencies installed)
try:
    from shadow_vault.integrations.langchain import (
        ProtectedTool,
        ShadowVaultChatWrapper,
        protect_tool,
    )
except ImportError:
    pass

try:
    from shadow_vault.integrations.proxy_server import create_proxy_app
except ImportError:
    pass

try:
    from shadow_vault.integrations.presidio import PresidioDetector
except ImportError:
    pass

from shadow_vault.synthesizer import (
    SYNTHETIC_PREFIXES,
    calculate_luhn_check_digit,
    find_synthetic_tokens,
    is_synthetic,
    synthesize_token,
)

__version__ = "0.4.1"

__all__ = [
    # Engine & Store
    "ShadowVault",
    "VaultStore",
    "StreamHydrator",
    # Policies & Security
    "ToolPolicy",
    "PolicyManager",
    "FailClosedAction",
    "UnmappedTokenError",
    "PIILeakBlockedError",
    # Cryptography
    "encrypt_value",
    "decrypt_value",
    "derive_key",
    "blind_index",
    # Integrations
    "vault_guard",
    "protect_tool",
    "ProtectedTool",
    "ShadowVaultChatWrapper",
    "MCPVaultInterceptor",
    "run_mcp_stdio_proxy",
    "create_proxy_app",
    "PresidioDetector",
    # Synthesis
    "synthesize_token",
    "is_synthetic",
    "find_synthetic_tokens",
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
