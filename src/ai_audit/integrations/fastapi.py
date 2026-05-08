"""FastAPI/Starlette middleware that auto-emits Decision Receipts.

Drop-in usage::

    from fastapi import FastAPI
    from ai_audit import AuditConfig, init_audit_config, ReceiptStore
    from ai_audit.integrations.fastapi import AuditMiddleware

    init_audit_config(AuditConfig.from_env())
    store = ReceiptStore()

    app = FastAPI()
    app.add_middleware(
        AuditMiddleware,
        store=store,
        tenant_id="acme",
        path_prefix="/v1/ai/",   # only audit AI endpoints
    )

The middleware captures request body as input, response status as output, and
maps HTTP status codes to ``ReceiptAction`` (allow/reject/fail_retry).

Optional dep: ``pip install fastapi`` (Starlette is a transitive dep).
"""

from __future__ import annotations

import logging
import uuid
from typing import TYPE_CHECKING

from ai_audit.collector import ReceiptCollector
from ai_audit.models import ReceiptAction
from ai_audit.pii import PiiConfig

if TYPE_CHECKING:
    from starlette.requests import Request
    from starlette.responses import Response

    from ai_audit.receipt_store import ReceiptStore

try:
    from starlette.middleware.base import BaseHTTPMiddleware
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "ai_audit.integrations.fastapi requires 'fastapi' (or 'starlette'). "
        "Install with: pip install ai-audit-trail[fastapi]"
    ) from e

logger = logging.getLogger(__name__)


class AuditMiddleware(BaseHTTPMiddleware):  # type: ignore[misc, unused-ignore]
    """Starlette/FastAPI middleware that emits one DecisionReceipt per request.

    Parameters:
        app:           ASGI app (injected by Starlette).
        store:         ReceiptStore instance to persist receipts in.
        tenant_id:     Multi-tenant scope identifier.
        path_prefix:   Only audit requests whose path starts with this prefix.
                       Default ``""`` audits all requests.
        capture_body:  If True, includes the (decoded) request body in the
                       input hash. Default True. Disable for binary endpoints.
        max_body_bytes:Max bytes of body to read for hashing. Default 64 KiB.
        pii_config:    Optional PiiConfig for input/output redaction before hashing.
        trace_header:  HTTP header name for the trace correlation ID.
        session_header:HTTP header name for the session ID.
    """

    def __init__(  # type: ignore[no-untyped-def]
        self,
        app,
        *,
        store: ReceiptStore,
        tenant_id: str = "default",
        path_prefix: str = "",
        capture_body: bool = True,
        max_body_bytes: int = 65_536,
        pii_config: PiiConfig | None = None,
        trace_header: str = "x-trace-id",
        session_header: str = "x-session-id",
    ) -> None:
        super().__init__(app)
        self.store = store
        self.tenant_id = tenant_id
        self.path_prefix = path_prefix
        self.capture_body = capture_body
        self.max_body_bytes = max_body_bytes
        self.pii_config = pii_config
        self.trace_header = trace_header
        self.session_header = session_header

    async def dispatch(  # type: ignore[no-untyped-def]
        self, request: Request, call_next
    ) -> Response:
        from typing import cast

        if self.path_prefix and not request.url.path.startswith(self.path_prefix):
            return cast("Response", await call_next(request))

        trace_id = request.headers.get(self.trace_header) or uuid.uuid4().hex
        session_id = request.headers.get(self.session_header, "")
        collector = ReceiptCollector(
            trace_id=trace_id,
            tenant_id=self.tenant_id,
            session_id=session_id,
            pii_config=self.pii_config,
        )

        if self.capture_body:
            try:
                body = await request.body()
                if body:
                    collector.set_input(body[: self.max_body_bytes].decode("utf-8", errors="replace"))
            except Exception as exc:  # noqa: BLE001
                logger.debug("AuditMiddleware: could not read body: %s", exc)

        try:
            response = cast("Response", await call_next(request))
            collector.set_output(f"status={response.status_code}")
            collector.set_action(
                ReceiptAction.ALLOW if response.status_code < 400 else ReceiptAction.REJECT
            )
            return response
        except Exception as exc:
            collector.set_output(f"error={type(exc).__name__}")
            collector.set_action(ReceiptAction.FAIL_RETRY)
            raise
        finally:
            try:
                collector.emit(self.store)
            except Exception as exc:  # noqa: BLE001
                logger.warning("AuditMiddleware: emit failed: %s", exc)
            collector.cleanup()


__all__ = ["AuditMiddleware"]
