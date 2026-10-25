"""
Unit tests for LangChain / LangGraph integrations (protect_tool and ShadowVaultChatWrapper).
"""

from __future__ import annotations

from typing import Any, AsyncIterator, Iterator, List, Optional
import pytest

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import (
    AIMessage,
    AIMessageChunk,
    BaseMessage,
    HumanMessage,
    ToolCall,
)
from langchain_core.outputs import ChatGeneration, ChatGenerationChunk, ChatResult
from langchain_core.tools import tool

from shadow_vault.engine import ShadowVault
from shadow_vault.integrations.langchain import ShadowVaultChatWrapper, protect_tool
from shadow_vault.synthesizer import is_synthetic


# ============================================================================
# Mock Language Model for Testing
# ============================================================================


class MockChatModel(BaseChatModel):
    """Mock LLM to record received messages and return simulated responses."""

    received_messages: list[list[BaseMessage]] = []
    response_content: str = ""
    response_tool_calls: list[dict[str, Any]] = []

    def _generate(
        self,
        messages: List[BaseMessage],
        stop: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> ChatResult:
        self.received_messages.append(messages)
        ai_msg = AIMessage(
            content=self.response_content or f"Echo: {messages[-1].content}",
            tool_calls=self.response_tool_calls,
        )
        return ChatResult(generations=[ChatGeneration(message=ai_msg)])

    async def _agenerate(
        self,
        messages: List[BaseMessage],
        stop: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> ChatResult:
        return self._generate(messages, stop=stop, **kwargs)

    def _stream(
        self,
        messages: List[BaseMessage],
        stop: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> Iterator[ChatGenerationChunk]:
        self.received_messages.append(messages)
        full_text = self.response_content or f"Echo: {messages[-1].content}"
        # Break into 3 chunks for stream testing
        k = max(1, len(full_text) // 3)
        chunks = [full_text[:k], full_text[k : 2 * k], full_text[2 * k :]]
        for c in chunks:
            if c:
                yield ChatGenerationChunk(message=AIMessageChunk(content=c))

    async def _astream(
        self,
        messages: List[BaseMessage],
        stop: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> AsyncIterator[ChatGenerationChunk]:
        for chunk in self._stream(messages, stop=stop, **kwargs):
            yield chunk

    @property
    def _llm_type(self) -> str:
        return "mock_chat_model"


# ============================================================================
# Tool Protection Tests
# ============================================================================


def test_protect_tool_sync_invocation() -> None:
    """Test protect_tool hydrates inputs and dehydrates outputs on sync tools."""
    vault = ShadowVault()
    session_id = "sess_tool_sync"

    real_email = "alice@example.com"
    synth_email = vault.dehydrate(real_email, session_id=session_id)
    assert is_synthetic(synth_email)

    received_in_tool: str = ""

    @tool
    def user_lookup(email: str) -> dict[str, str]:
        """Look up user record by email."""
        nonlocal received_in_tool
        received_in_tool = email
        return {
            "email": email,
            "card": "4532 0151 1283 0366",
            "phone": "+91 9876543210",
        }

    protected = protect_tool(user_lookup, vault=vault, session_id=session_id)

    # Agent invokes tool with synthetic email
    result = protected.invoke({"email": synth_email})

    # Tool received hydrated real email
    assert received_in_tool == real_email

    # Tool result has all PII dehydrated back into format-preserving tokens
    assert is_synthetic(result["card"])
    assert "4532 0151 1283 0366" not in result["card"]
    assert is_synthetic(result["phone"])
    assert "+91 9876543210" not in result["phone"]
    assert result["email"] == synth_email

    vault.close()


@pytest.mark.asyncio
async def test_protect_tool_async_invocation() -> None:
    """Test protect_tool hydrates inputs and dehydrates outputs on async tools."""
    vault = ShadowVault()
    session_id = "sess_tool_async"

    real_phone = "+91 9876543210"
    synth_phone = vault.dehydrate(real_phone, session_id=session_id)
    assert is_synthetic(synth_phone)

    @tool
    async def async_fetch_profile(phone: str) -> str:
        """Fetch user profile asynchronously."""
        return f"Profile for {phone}: card is 4532 0151 1283 0366"

    protected = protect_tool(async_fetch_profile, vault=vault, session_id=session_id)

    # Async invocation
    result = await protected.ainvoke({"phone": synth_phone})

    # Output is dehydrated
    assert is_synthetic(synth_phone)
    assert "+91 9876543210" not in result
    assert "4532 0151 1283 0366" not in result

    # Hydrate restores full original text
    restored = vault.hydrate(result, session_id=session_id)
    assert restored == f"Profile for {real_phone}: card is 4532 0151 1283 0366"

    vault.close()


# ============================================================================
# Chat Model Wrapper Tests
# ============================================================================


def test_chat_wrapper_dehydrates_prompts_and_hydrates_responses() -> None:
    """Test prompt history is dehydrated before LLM and hydrated on response."""
    vault = ShadowVault()
    session_id = "sess_chat_wrapper"

    real_email = "dev@enterprise.com"
    llm = MockChatModel()
    llm.received_messages = []
    llm.response_content = ""

    wrapper = ShadowVaultChatWrapper(
        llm=llm,
        vault=vault,
        session_id=session_id,
        hydrate_output=True,
    )

    user_msg = HumanMessage(content=f"Contact me at {real_email}")
    response = wrapper.invoke([user_msg])

    # 1. Underlying LLM received dehydrated prompt
    assert len(llm.received_messages) == 1
    llm_received_content = llm.received_messages[0][0].content
    assert real_email not in llm_received_content
    assert "@shadow.vault" in llm_received_content

    # 2. Final response returned to user is re-hydrated
    assert real_email in response.content

    vault.close()


def test_chat_wrapper_preserves_synthetic_tool_calls() -> None:
    """Test tool-call arguments remain synthetic to keep agent state history PII-free."""
    vault = ShadowVault()
    session_id = "sess_tool_calls"

    real_email = "victim@domain.com"
    synth_email = vault.dehydrate(real_email, session_id=session_id)

    llm = MockChatModel()
    llm.received_messages = []
    # LLM issues a tool call with synthetic argument
    llm.response_content = ""
    llm.response_tool_calls = [
        {
            "name": "lookup_user",
            "args": {"email": synth_email},
            "id": "call_123",
            "type": "tool_call",
        }
    ]

    wrapper = ShadowVaultChatWrapper(
        llm=llm,
        vault=vault,
        session_id=session_id,
        hydrate_output=True,
    )

    response = wrapper.invoke([HumanMessage(content="Check user status")])

    # Tool calls must STAY synthetic so agent message history stays PII-free!
    assert len(response.tool_calls) == 1
    call_arg = response.tool_calls[0]["args"]["email"]
    assert call_arg == synth_email
    assert is_synthetic(call_arg)
    assert real_email not in call_arg

    vault.close()


def test_chat_wrapper_streaming() -> None:
    """Test streaming chunks are hydrated in real time via StreamHydrator."""
    vault = ShadowVault()
    session_id = "sess_stream_wrapper"

    real_email = "streamer@example.com"
    synth_email = vault.dehydrate(real_email, session_id=session_id)

    llm = MockChatModel()
    llm.received_messages = []
    # LLM streams output containing synthetic token
    llm.response_content = f"User email is {synth_email}. End."

    wrapper = ShadowVaultChatWrapper(
        llm=llm,
        vault=vault,
        session_id=session_id,
        hydrate_output=True,
    )

    chunks: list[str] = []
    for chunk in wrapper.stream([HumanMessage(content="Who is this?")]):
        if chunk.content:
            chunks.append(chunk.content)

    full_output = "".join(chunks)
    assert real_email in full_output
    assert synth_email not in full_output
    assert full_output == f"User email is {real_email}. End."

    vault.close()
