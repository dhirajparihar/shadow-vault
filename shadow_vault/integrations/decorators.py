"""
Python function decorators for bi-directional PII dehydration and hydration.
"""

from __future__ import annotations

import functools
import inspect
from typing import Any, Callable, TypeVar

from shadow_vault.engine import ShadowVault

F = TypeVar("F", bound=Callable[..., Any])


def _extract_session_id(
    func: Callable[..., Any],
    session_id_arg: str,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> str:
    """Extract session identifier from function invocation arguments or default."""
    if session_id_arg in kwargs and kwargs[session_id_arg] is not None:
        return str(kwargs[session_id_arg])

    try:
        sig = inspect.signature(func)
        bound = sig.bind_partial(*args, **kwargs)
        if session_id_arg in bound.arguments and bound.arguments[session_id_arg] is not None:
            return str(bound.arguments[session_id_arg])
    except Exception:
        pass

    return "default"


def vault_guard(
    vault: ShadowVault,
    session_id_arg: str = "session_id",
) -> Callable[[F], F]:
    """Decorator guarding sync and async Python functions against PII leakage.

    1. Intercepts incoming *args and **kwargs, hydrating synthetic tokens to real values
       right before function execution.
    2. Executes the function with real values (e.g. database query, payment processing).
    3. Dehydrates the return value before returning back to the AI agent or caller,
       ensuring any new PII is masked with format-preserving synthetic tokens.

    Args:
        vault: ShadowVault instance managing the session mappings.
        session_id_arg: Name of the argument holding the session identifier.

    Returns:
        Decorated function with automatic bi-directional PII conversion.
    """

    def decorator(func: F) -> F:
        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                session_id = _extract_session_id(func, session_id_arg, args, kwargs)
                # Hydrate inputs from synthetic to real PII
                hydrated_args = [vault.hydrate(arg, session_id=session_id) for arg in args]
                hydrated_kwargs = {
                    k: vault.hydrate(v, session_id=session_id) for k, v in kwargs.items()
                }
                # Execute with real data
                result = await func(*hydrated_args, **hydrated_kwargs)
                # Dehydrate outputs to synthetic tokens
                return vault.dehydrate(result, session_id=session_id)

            return async_wrapper  # type: ignore[return-value]

        else:

            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                session_id = _extract_session_id(func, session_id_arg, args, kwargs)
                # Hydrate inputs from synthetic to real PII
                hydrated_args = [vault.hydrate(arg, session_id=session_id) for arg in args]
                hydrated_kwargs = {
                    k: vault.hydrate(v, session_id=session_id) for k, v in kwargs.items()
                }
                # Execute with real data
                result = func(*hydrated_args, **hydrated_kwargs)
                # Dehydrate outputs to synthetic tokens
                return vault.dehydrate(result, session_id=session_id)

            return sync_wrapper  # type: ignore[return-value]

    return decorator
