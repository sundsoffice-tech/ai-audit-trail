"""OpenAI Python SDK adapter — emits Decision Receipts for chat-completion calls.

Two usage patterns:

1. Manual: emit a receipt from an existing call::

    from openai import OpenAI
    from ai_audit.integrations.openai import emit_chat_completion_receipt

    client = OpenAI()
    messages = [{"role": "user", "content": "Hello"}]
    response = client.chat.completions.create(model="gpt-4o-mini", messages=messages)

    emit_chat_completion_receipt(
        store, tenant_id="acme", model="gpt-4o-mini",
        messages=messages, response=response,
    )

2. Drop-in wrap: instrument a client so every chat.completions.create call is audited::

    from ai_audit.integrations.openai import AuditedOpenAI

    client = AuditedOpenAI(store=store, tenant_id="acme")
    response = client.chat.completions.create(model="gpt-4o-mini", messages=[...])
    # receipt emitted automatically

Optional dep: ``pip install openai>=1.0``.
"""

from __future__ import annotations

import logging
import uuid
from typing import TYPE_CHECKING, Any

from ai_audit.collector import ReceiptCollector
from ai_audit.models import ReceiptAction
from ai_audit.pii import PiiConfig

if TYPE_CHECKING:
    from ai_audit.receipt_store import ReceiptStore

logger = logging.getLogger(__name__)


def _flatten_messages(messages: list[dict[str, Any]]) -> str:
    """Flatten an OpenAI message list to a single canonical string for hashing."""
    parts: list[str] = []
    for msg in messages:
        role = msg.get("role", "")
        content = msg.get("content", "")
        if isinstance(content, list):
            text_parts = [
                p.get("text", "") for p in content if isinstance(p, dict) and p.get("type") == "text"
            ]
            content = "\n".join(text_parts)
        parts.append(f"{role}: {content}")
    return "\n".join(parts)


def _extract_response_text(response: Any) -> str:
    """Extract assistant content from an OpenAI ChatCompletion response."""
    try:
        choice = response.choices[0]
        msg = choice.message
        content = msg.content or ""
        if isinstance(content, list):
            content = "\n".join(
                p.get("text", "") for p in content if isinstance(p, dict) and p.get("type") == "text"
            )
        return str(content)
    except (AttributeError, IndexError, KeyError):
        return ""


def _extract_finish_reason(response: Any) -> str:
    try:
        return str(response.choices[0].finish_reason or "")
    except (AttributeError, IndexError):
        return ""


def emit_chat_completion_receipt(
    store: ReceiptStore,
    *,
    tenant_id: str,
    model: str,
    messages: list[dict[str, Any]],
    response: Any,
    trace_id: str = "",
    session_id: str = "",
    pii_config: PiiConfig | None = None,
) -> str:
    """Emit one Receipt for an OpenAI chat.completions.create call.

    Returns the emitted receipt_id.
    """
    collector = ReceiptCollector(
        trace_id=trace_id or uuid.uuid4().hex,
        tenant_id=tenant_id,
        session_id=session_id,
        model_id=model,
        pii_config=pii_config,
    )
    collector.set_input(_flatten_messages(messages))
    collector.set_output(_extract_response_text(response))

    finish = _extract_finish_reason(response)
    if finish:
        collector.add_reason(f"openai.finish_reason={finish}")
    if finish == "content_filter":
        collector.set_action(ReceiptAction.REJECT)
    elif finish == "length":
        collector.set_action(ReceiptAction.ALLOW)
        collector.add_reason("truncated_by_length")
    else:
        collector.set_action(ReceiptAction.ALLOW)

    try:
        return collector.emit(store)
    finally:
        collector.cleanup()


class AuditedOpenAI:
    """Lazy proxy around an ``openai.OpenAI`` client that emits receipts.

    Usage::

        client = AuditedOpenAI(store=store, tenant_id="acme")
        response = client.chat.completions.create(model="gpt-4o-mini", messages=[...])

    Construction lazily imports ``openai``; raises ImportError with install hint
    if the SDK is missing. Pass ``client=...`` to wrap a pre-configured instance.
    """

    def __init__(
        self,
        *,
        store: ReceiptStore,
        tenant_id: str = "default",
        client: Any | None = None,
        pii_config: PiiConfig | None = None,
        **openai_kwargs: Any,
    ) -> None:
        if client is None:
            try:
                from openai import OpenAI
            except ImportError as e:  # pragma: no cover
                raise ImportError(
                    "AuditedOpenAI requires 'openai>=1.0'. "
                    "Install with: pip install ai-audit-trail[openai]"
                ) from e
            client = OpenAI(**openai_kwargs)

        self._client = client
        self._store = store
        self._tenant_id = tenant_id
        self._pii_config = pii_config
        self.chat = _AuditedChatNamespace(self)

    @property
    def raw(self) -> Any:
        """Underlying OpenAI client — for non-audited calls (embeddings, etc.)."""
        return self._client


class _AuditedChatNamespace:
    def __init__(self, parent: AuditedOpenAI) -> None:
        self._parent = parent
        self.completions = _AuditedCompletions(parent)


class _AuditedCompletions:
    def __init__(self, parent: AuditedOpenAI) -> None:
        self._parent = parent

    def create(self, *, model: str, messages: list[dict[str, Any]], **kwargs: Any) -> Any:
        # The openai SDK has a stricter TypedDict for messages; we accept the
        # plain dict shape because that's what most users (and the test suite)
        # construct. Cast at the SDK boundary.
        response = self._parent._client.chat.completions.create(
            model=model, messages=messages, **kwargs  # type: ignore[arg-type, unused-ignore]
        )
        try:
            emit_chat_completion_receipt(
                self._parent._store,
                tenant_id=self._parent._tenant_id,
                model=model,
                messages=messages,
                response=response,
                pii_config=self._parent._pii_config,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("AuditedOpenAI: emit failed: %s", exc)
        return response


__all__ = ["AuditedOpenAI", "emit_chat_completion_receipt"]
