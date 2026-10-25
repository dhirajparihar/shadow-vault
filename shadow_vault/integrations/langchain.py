"""
LangChain and LangGraph integration: BaseTool protection and ChatModel wrapper.
"""

from __future__ import annotations

from typing import (
    Any,
    AsyncIterator,
    Callable,
    Iterator,
    List,
    Optional,
    Sequence,
    Type,
    Union,
)
from pydantic import BaseModel, Field

try:
    from langchain_core.language_models.chat_models import BaseChatModel
    from langchain_core.messages import (
        AIMessage,
        AIMessageChunk,
        BaseMessage,
        ChatMessage,
        FunctionMessage,
        HumanMessage,
        SystemMessage,
        ToolMessage,
    )
    from langchain_core.outputs import ChatGeneration, ChatGenerationChunk, ChatResult
    from langchain_core.tools import BaseTool
except ImportError:  # pragma: no cover
    raise ImportError(
        "langchain-core is required for LangChain integration. "
        "Install it via `pip install 'shadow-vault[langchain]'` or `pip install langchain-core`."
    )

from shadow_vault.engine import ShadowVault


class ProtectedTool(BaseTool):
    """Wrapper around a LangChain BaseTool that dehydrates outputs and hydrates inputs."""

    underlying_tool: BaseTool = Field(description="The wrapped LangChain BaseTool")
    vault: ShadowVault = Field(description="ShadowVault engine instance")
    session_id: str = Field(default="default", description="Session scope identifier")

    def __init__(
        self,
        tool: BaseTool,
        vault: ShadowVault,
        session_id: str = "default",
        **kwargs: Any,
    ) -> None:
        super().__init__(
            name=tool.name,
            description=tool.description,
            args_schema=tool.args_schema,
            return_direct=tool.return_direct,
            underlying_tool=tool,
            vault=vault,
            session_id=session_id,
            **kwargs,
        )

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        """Hydrate inputs from LLM, execute tool with real PII, dehydrate outputs."""
        hydrated_args = [self.vault.hydrate(a, session_id=self.session_id) for a in args]
        hydrated_kwargs = {
            k: self.vault.hydrate(v, session_id=self.session_id) for k, v in kwargs.items()
        }

        # Handle tools invoked with a single positional dict or keyword arguments
        if hydrated_kwargs:
            result = self.underlying_tool.invoke(hydrated_kwargs)
        elif hydrated_args:
            result = self.underlying_tool.invoke(hydrated_args[0])
        else:
            result = self.underlying_tool.invoke({})

        # Dehydrate sensitive data returned by tool before it enters state or reaches LLM
        return self.vault.dehydrate(result, session_id=self.session_id)

    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        """Asynchronously hydrate inputs, execute tool, dehydrate outputs."""
        hydrated_args = [self.vault.hydrate(a, session_id=self.session_id) for a in args]
        hydrated_kwargs = {
            k: self.vault.hydrate(v, session_id=self.session_id) for k, v in kwargs.items()
        }

        if hydrated_kwargs:
            result = await self.underlying_tool.ainvoke(hydrated_kwargs)
        elif hydrated_args:
            result = await self.underlying_tool.ainvoke(hydrated_args[0])
        else:
            result = await self.underlying_tool.ainvoke({})

        return self.vault.dehydrate(result, session_id=self.session_id)


def protect_tool(
    tool: BaseTool,
    vault: ShadowVault,
    session_id: str = "default",
) -> BaseTool:
    """Wrap a LangChain BaseTool so inputs are hydrated and outputs are dehydrated.

    Args:
        tool: Target BaseTool to protect.
        vault: ShadowVault engine.
        session_id: Target session identifier.

    Returns:
        A ProtectedTool instance wrapping the original tool.
    """
    return ProtectedTool(tool=tool, vault=vault, session_id=session_id)


class ShadowVaultChatWrapper(BaseChatModel):
    """LangChain BaseChatModel wrapper that anonymizes prompts and manages responses."""

    llm: Any = Field(description="Underlying BaseChatModel")
    vault: ShadowVault = Field(description="ShadowVault engine")
    session_id: str = Field(default="default", description="Session identifier")
    hydrate_output: bool = Field(
        default=True,
        description="Whether to hydrate final text output (set False for agent intermediate steps)",
    )

    def _dehydrate_messages(self, messages: list[BaseMessage]) -> list[BaseMessage]:
        """Dehydrate all content within message history before sending to the LLM."""
        dehydrated: list[BaseMessage] = []
        for msg in messages:
            if isinstance(msg.content, str):
                new_content = self.vault.dehydrate(msg.content, session_id=self.session_id)
            elif isinstance(msg.content, list):
                new_content = [
                    self.vault.dehydrate(block, session_id=self.session_id)
                    for block in msg.content
                ]
            else:
                new_content = msg.content

            cloned = msg.model_copy(update={"content": new_content})
            dehydrated.append(cloned)
        return dehydrated

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        """Dehydrate message history, call LLM, and process response generations."""
        dehydrated_msgs = self._dehydrate_messages(messages)
        chat_result: ChatResult = self.llm._generate(dehydrated_msgs, stop=stop, **kwargs)

        processed_gens: list[ChatGeneration] = []
        for gen in chat_result.generations:
            msg = gen.message
            # If model produced tool calls, keep them synthetic so agent state remains PII-free
            has_tool_calls = hasattr(msg, "tool_calls") and bool(msg.tool_calls)
            if has_tool_calls or not self.hydrate_output:
                processed_gens.append(gen)
            else:
                if isinstance(msg.content, str):
                    hydrated_content = self.vault.hydrate(msg.content, session_id=self.session_id)
                    new_msg = msg.model_copy(update={"content": hydrated_content})
                    processed_gens.append(
                        ChatGeneration(message=new_msg, generation_info=gen.generation_info)
                    )
                else:
                    processed_gens.append(gen)

        return ChatResult(generations=processed_gens, llm_output=chat_result.llm_output)

    async def _agenerate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        """Asynchronously dehydrate message history, call LLM, and process response."""
        dehydrated_msgs = self._dehydrate_messages(messages)
        chat_result: ChatResult = await self.llm._agenerate(dehydrated_msgs, stop=stop, **kwargs)

        processed_gens: list[ChatGeneration] = []
        for gen in chat_result.generations:
            msg = gen.message
            has_tool_calls = hasattr(msg, "tool_calls") and bool(msg.tool_calls)
            if has_tool_calls or not self.hydrate_output:
                processed_gens.append(gen)
            else:
                if isinstance(msg.content, str):
                    hydrated_content = self.vault.hydrate(msg.content, session_id=self.session_id)
                    new_msg = msg.model_copy(update={"content": hydrated_content})
                    processed_gens.append(
                        ChatGeneration(message=new_msg, generation_info=gen.generation_info)
                    )
                else:
                    processed_gens.append(gen)

        return ChatResult(generations=processed_gens, llm_output=chat_result.llm_output)

    def _stream(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        **kwargs: Any,
    ) -> Iterator[ChatGenerationChunk]:
        """Stream chunks using StreamHydrator to assemble and hydrate split tokens."""
        dehydrated_msgs = self._dehydrate_messages(messages)
        stream_hydrator = self.vault.stream(session_id=self.session_id)

        for chunk in self.llm._stream(dehydrated_msgs, stop=stop, **kwargs):
            msg = chunk.message
            has_tool_calls = (hasattr(msg, "tool_calls") and bool(msg.tool_calls)) or (
                hasattr(msg, "tool_call_chunks") and bool(msg.tool_call_chunks)
            )

            if has_tool_calls or not self.hydrate_output:
                yield chunk
            else:
                if isinstance(msg.content, str):
                    emitted = stream_hydrator.process_chunk(msg.content)
                    if emitted:
                        new_msg = msg.model_copy(update={"content": emitted})
                        yield ChatGenerationChunk(
                            message=new_msg, generation_info=chunk.generation_info
                        )
                else:
                    yield chunk

        if self.hydrate_output:
            flushed = stream_hydrator.flush()
            if flushed:
                yield ChatGenerationChunk(message=AIMessageChunk(content=flushed))

    async def _astream(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[ChatGenerationChunk]:
        """Asynchronously stream chunks with StreamHydrator."""
        dehydrated_msgs = self._dehydrate_messages(messages)
        stream_hydrator = self.vault.stream(session_id=self.session_id)

        async for chunk in self.llm._astream(dehydrated_msgs, stop=stop, **kwargs):
            msg = chunk.message
            has_tool_calls = (hasattr(msg, "tool_calls") and bool(msg.tool_calls)) or (
                hasattr(msg, "tool_call_chunks") and bool(msg.tool_call_chunks)
            )

            if has_tool_calls or not self.hydrate_output:
                yield chunk
            else:
                if isinstance(msg.content, str):
                    emitted = stream_hydrator.process_chunk(msg.content)
                    if emitted:
                        new_msg = msg.model_copy(update={"content": emitted})
                        yield ChatGenerationChunk(
                            message=new_msg, generation_info=chunk.generation_info
                        )
                else:
                    yield chunk

        if self.hydrate_output:
            flushed = stream_hydrator.flush()
            if flushed:
                yield ChatGenerationChunk(message=AIMessageChunk(content=flushed))

    def bind_tools(
        self,
        tools: Sequence[Union[dict[str, Any], Type[BaseModel], Callable, BaseTool]],
        **kwargs: Any,
    ) -> Any:
        """Bind tools to the underlying model while preserving ShadowVault wrapping."""
        bound = self.llm.bind_tools(tools, **kwargs)
        return ShadowVaultChatWrapper(
            llm=bound,
            vault=self.vault,
            session_id=self.session_id,
            hydrate_output=self.hydrate_output,
        )

    @property
    def _llm_type(self) -> str:
        return "shadow_vault_chat_wrapper"
