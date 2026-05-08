"""LangChain callback handler that auto-emits Decision Receipts.

Drop-in usage::

    from langchain_openai import ChatOpenAI
    from ai_audit import AuditConfig, init_audit_config, ReceiptStore
    from ai_audit.integrations.langchain import AuditCallbackHandler

    init_audit_config(AuditConfig.from_env())
    store = ReceiptStore()
    handler = AuditCallbackHandler(store=store, tenant_id="acme")

    llm = ChatOpenAI(callbacks=[handler])
    llm.invoke("What is 2+2?")

The handler creates one Receipt per LLM call, hooked at ``on_llm_start`` and
sealed at ``on_llm_end`` / ``on_llm_error``.

Optional dep: ``pip install langchain-core``.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any
from uuid import UUID

from ai_audit.collector import ReceiptCollector
from ai_audit.models import ReceiptAction
from ai_audit.pii import PiiConfig

if TYPE_CHECKING:
    from langchain_core.outputs import LLMResult

    from ai_audit.receipt_store import ReceiptStore

try:
    from langchain_core.callbacks import BaseCallbackHandler
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "ai_audit.integrations.langchain requires 'langchain-core'. "
        "Install with: pip install ai-audit-trail[langchain]"
    ) from e

logger = logging.getLogger(__name__)


class AuditCallbackHandler(BaseCallbackHandler):  # type: ignore[misc, unused-ignore]
    """LangChain callback emitting one DecisionReceipt per LLM call.

    Parameters:
        store:         ReceiptStore to persist receipts in.
        tenant_id:     Multi-tenant scope identifier.
        session_id:    Session correlation ID (defaults to empty).
        pii_config:    Optional PiiConfig for redaction before hashing.
    """

    def __init__(
        self,
        *,
        store: ReceiptStore,
        tenant_id: str = "default",
        session_id: str = "",
        pii_config: PiiConfig | None = None,
    ) -> None:
        super().__init__()
        self.store = store
        self.tenant_id = tenant_id
        self.session_id = session_id
        self.pii_config = pii_config
        self._collectors: dict[str, ReceiptCollector] = {}

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        model_id = (
            serialized.get("kwargs", {}).get("model_name")
            or serialized.get("kwargs", {}).get("model")
            or "unknown"
        )
        collector = ReceiptCollector(
            trace_id=str(run_id),
            tenant_id=self.tenant_id,
            session_id=self.session_id,
            model_id=model_id,
            pii_config=self.pii_config,
        )
        if prompts:
            collector.set_input(prompts[0])
        self._collectors[str(run_id)] = collector

    def on_llm_end(
        self, response: LLMResult, *, run_id: UUID, **kwargs: Any
    ) -> None:
        collector = self._collectors.pop(str(run_id), None)
        if collector is None:
            return
        text = ""
        if response.generations and response.generations[0]:
            text = response.generations[0][0].text
        collector.set_output(text)
        collector.set_action(ReceiptAction.ALLOW)
        try:
            collector.emit(self.store)
        except Exception as exc:  # noqa: BLE001
            logger.warning("AuditCallbackHandler: emit failed: %s", exc)
        collector.cleanup()

    def on_llm_error(
        self, error: BaseException, *, run_id: UUID, **kwargs: Any
    ) -> None:
        collector = self._collectors.pop(str(run_id), None)
        if collector is None:
            return
        collector.set_output(f"error={type(error).__name__}: {error}")
        collector.set_action(ReceiptAction.FAIL_RETRY)
        try:
            collector.emit(self.store)
        except Exception as exc:  # noqa: BLE001
            logger.warning("AuditCallbackHandler: emit failed: %s", exc)
        collector.cleanup()


__all__ = ["AuditCallbackHandler"]
