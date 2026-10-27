"""
Standard logging filter for intercepting and scrubbing real PII from application logs and traces.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from shadow_vault.engine import ShadowVault


class VaultLogFilter(logging.Filter):
    """Python logging.Filter that intercepts log records and scrubs real PII.

    Replaces detected sensitive entities in log messages and string arguments
    with format-preserving synthetic tokens before they reach log formatters,
    handlers, or external log sinks (Datadog, CloudWatch, OpenTelemetry, stdout).

    Example:
        import logging
        from shadow_vault import ShadowVault, VaultLogFilter

        vault = ShadowVault()
        logger = logging.getLogger("agent")
        logger.addFilter(VaultLogFilter(vault, session_id="run_123"))

        logger.info("Processing card 4532 0151 1283 0366 for alice@example.com")
        # Log sink receives: "Processing card 4000009995970590 for u_c09753@shadow.vault"
    """

    def __init__(self, vault: ShadowVault, session_id: str = "default") -> None:
        super().__init__()
        self.vault = vault
        self.session_id = session_id

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            if isinstance(record.msg, str):
                record.msg = self.vault.dehydrate(record.msg, session_id=self.session_id)

            if record.args:
                if isinstance(record.args, dict):
                    record.args = {
                        k: (self.vault.dehydrate(v, session_id=self.session_id) if isinstance(v, str) else v)
                        for k, v in record.args.items()
                    }
                elif isinstance(record.args, tuple):
                    record.args = tuple(
                        (self.vault.dehydrate(arg, session_id=self.session_id) if isinstance(arg, str) else arg)
                        for arg in record.args
                    )
        except Exception:
            # Never crash application logging on filter failure
            pass
        return True


# Alias for backward and intuitive discovery
ShadowVaultLoggingFilter = VaultLogFilter
