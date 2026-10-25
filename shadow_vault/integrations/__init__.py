"""
Framework integrations for shadow-vault: LangChain/LangGraph, MCP, decorators, and FastAPI proxy.
"""

from shadow_vault.integrations.decorators import vault_guard
from shadow_vault.integrations.langchain import (
    ProtectedTool,
    ShadowVaultChatWrapper,
    protect_tool,
)
from shadow_vault.integrations.mcp_proxy import MCPVaultInterceptor
from shadow_vault.integrations.proxy_server import create_proxy_app

__all__ = [
    "vault_guard",
    "protect_tool",
    "ProtectedTool",
    "ShadowVaultChatWrapper",
    "MCPVaultInterceptor",
    "create_proxy_app",
]
