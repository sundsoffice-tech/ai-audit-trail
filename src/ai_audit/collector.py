"""
ai_audit.collector — ContextVar-based ReceiptCollector (no prop-drilling).

The ``ReceiptCollector`` accumulates check results, input/output hashes,
and action decisions throughout the pipeline. It is set as the ambient
context via a ``ContextVar`` so that deep functions can call
``get_current_collector()`` without any parameter changes.

Usage::

    collector = ReceiptCollector(
        trace_id=trace_id,
        session_id=session_id,
        tenant_id=tenant_id,
        model_id=model_id,
    )
    # ... pipeline runs, deep functions call get_current_collector().add_check() ...
    receipt_id = collector.emit(store)
    collector.cleanup()  # Reset ContextVar
"""

from __future__ import annotations

import asyncio
import logging
from contextvars import ContextVar
from typing import Any

from ai_audit.hashing import canonicalize_input, hash_output, hash_state
from ai_audit.models import CheckRecord, DecisionReceipt, ReceiptAction
from ai_audit.pii import PiiConfig, obfuscate_text

logger = logging.getLogger(__name__)

# Ambient context — accessible from any depth in the call stack
_current_collector: ContextVar[ReceiptCollector | None] = ContextVar(
    "current_receipt_collector", default=None
)


def get_current_collector() -> ReceiptCollector | None:
    """Return the active ReceiptCollector for this async context, or None."""
    return _current_collector.get()


class ReceiptCollector:
    """Accumulates audit data throughout a single request lifecycle.

    On construction, sets itself as the ambient ``ContextVar`` so that
    any function in the call stack can contribute checks via
    ``get_current_collector()``.

    Parameters:
        trace_id:   Request correlation ID.
        session_id: Chat / request session ID.
        tenant_id:  Multi-tenant isolation scope.
        model_id:   LLM model identifier.
    """

    def __init__(
        self,
        trace_id: str = "",
        session_id: str = "",
        tenant_id: str = "",
        model_id: str = "",
        pii_config: PiiConfig | None = None,
    ) -> None:
        self._receipt = DecisionReceipt(
            trace_id=trace_id,
            session_id=session_id,
            tenant_id=tenant_id,
            model_id=model_id,
        )
        self._checks: list[CheckRecord] = []
        self._pii_config = pii_config
        self._token = _current_collector.set(self)

    # ------------------------------------------------------------------
    # Builder API (called from various pipeline stages)
    # ------------------------------------------------------------------

    def set_input(self, text: str) -> None:
        """Set the canonicalised input hash (NFKC + whitespace + lowercase).

        If a ``pii_config`` was provided at construction, PII is stripped from
        *text* **before** hashing — ensuring the stored hash never reflects raw
        personal data (GDPR Art. 17 compliance).
        """
        if self._pii_config is not None:
            text = obfuscate_text(text, self._pii_config)
        self._receipt.input_c14n = canonicalize_input(text)

    def set_output(self, text: str) -> None:
        """Set the output hash (raw SHA-256).

        PII is stripped before hashing when ``pii_config`` is set.
        """
        if self._pii_config is not None:
            text = obfuscate_text(text, self._pii_config)
        self._receipt.output_hash = hash_output(text)

    def set_state(self, parts: list[str]) -> None:
        """Set the state digest from ordered context components."""
        self._receipt.state_digest = hash_state(parts)

    def set_action(self, action: ReceiptAction) -> None:
        """Set the terminal action for this request."""
        self._receipt.action = action

    def set_model(self, model_id: str) -> None:
        """Update model provenance (may change during routing)."""
        self._receipt.model_id = model_id

    def set_config_digest(self, digest: str) -> None:
        """Set the configuration digest (model config hash)."""
        self._receipt.config_digest = digest

    def add_check(
        self,
        name: str,
        *,
        score: float = 0.0,
        threshold: float = 0.0,
        fired: bool = False,
        detail: dict[str, Any] | None = None,
        version: str = "1.0",
    ) -> None:
        """Record a check/gate evaluation.

        Parameters:
            name:      Check identifier (e.g. ``"safety_pre"``).
            score:     Numeric score from the check.
            threshold: Decision threshold.
            fired:     Whether the check changed routing/outcome.
            detail:    Arbitrary metadata dict.
            version:   Schema version for forward-compat.
        """
        self._checks.append(
            CheckRecord(
                name=name,
                version=version,
                score=score,
                threshold=threshold,
                fired=fired,
                detail=detail or {},
            )
        )

    def add_reason(self, code: str) -> None:
        """Add a reason code to the receipt."""
        self._receipt.reason_codes.append(code)

    def add_nist_tag(self, tag: str) -> None:
        """Add a NIST framework tag (e.g. ``"AC-6"``, ``"AU-3"``)."""
        self._receipt.nist_tags.append(tag)

    # ------------------------------------------------------------------
    # Emission (seals + stores the receipt)
    # ------------------------------------------------------------------

    def emit(self, store: object) -> str:
        """Seal with Ed25519, link to hash-chain, and store.

        Returns:
            The ``receipt_id`` of the emitted receipt.
        """
        from ai_audit.keys import get_signing_key
        from ai_audit.receipt_store import ReceiptStore as ReceiptStoreType

        if not isinstance(store, ReceiptStoreType):
            raise TypeError(f"store must be a ReceiptStore instance, got {type(store).__name__}")

        self._receipt.checks = self._checks

        # Atomic seal + append (prevents TOCTOU race on chain tip)
        store.atomic_seal_and_append(self._receipt, get_signing_key())

        # Fire-and-forget Redis persistence (if configured)
        if store._redis is not None:
            try:
                asyncio.get_running_loop()
                if store._use_lua and store._lua_script is not None:
                    asyncio.create_task(store._lua_redis_commit(self._receipt))
                else:
                    asyncio.create_task(store._atomic_redis_commit(self._receipt))
            except RuntimeError:
                pass  # No event-loop (sync tests / CLI) — skip Redis

        logger.debug(
            "Receipt emitted: %s action=%s checks=%d",
            self._receipt.receipt_id,
            self._receipt.action.value,
            len(self._checks),
        )
        return self._receipt.receipt_id

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def cleanup(self) -> None:
        """Reset the ContextVar to prevent leaking into subsequent requests."""
        try:
            _current_collector.reset(self._token)
        except ValueError:
            _current_collector.set(None)

    @property
    def receipt(self) -> DecisionReceipt:
        """Read-only access to the underlying receipt (for testing)."""
        return self._receipt
