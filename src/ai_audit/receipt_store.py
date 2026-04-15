"""
ai_audit.receipt_store — Atomic Redis Pipeline Store for Decision Receipts.

In-memory primary store with fire-and-forget Redis persistence via
atomic ``MULTI/EXEC`` pipelines (one network roundtrip, crash-consistent).

Indices maintained:
- ``receipt:{tenant_id}:{receipt_id}`` → Full receipt JSON
- ``receipt_chain:{tenant_id}`` → Latest chain tip hash
- ``receipt_session:{session_id}`` → Set of receipt IDs
- ``receipt_trace:{trace_id}`` → Set of receipt IDs

LRU eviction: In-memory store caps at ``max_size`` entries to prevent
unbounded growth. Oldest entries are evicted first.

Redis is optional — the store works fully in-memory without it.
"""

from __future__ import annotations

import asyncio
import logging
from collections import OrderedDict
from typing import Any

import orjson

from ai_audit.models import DecisionReceipt

logger = logging.getLogger(__name__)


class ReceiptStore:
    """Append-only store for Decision Receipts with optional Redis persistence.

    Parameters:
        redis_client:  Optional sync Redis client (``redis.Redis``).
        ttl:           Redis key TTL in seconds (default: 30 days).
        max_size:      Max in-memory receipts before LRU eviction.
    """

    def __init__(
        self,
        redis_client: Any | None = None,
        ttl: int = 2_592_000,
        max_size: int = 50_000,
    ) -> None:
        self._redis = redis_client
        self._ttl = ttl
        self._max_size = max_size

        self._receipts: OrderedDict[str, DecisionReceipt] = OrderedDict()
        self._chain_tips: dict[str, str] = {}
        self._session_index: dict[str, set[str]] = {}
        self._trace_index: dict[str, set[str]] = {}

    def get_chain_tip(self, tenant_id: str) -> str:
        """Return the receipt_hash of the latest receipt for this tenant."""
        tip_id = self._chain_tips.get(tenant_id)
        if tip_id and tip_id in self._receipts:
            return self._receipts[tip_id].receipt_hash
        return ""

    def append(self, receipt: DecisionReceipt) -> None:
        """Store a sealed receipt (in-memory + fire-and-forget Redis).

        O(1) for in-memory storage. Schedules an async Redis commit via
        ``asyncio.create_task()`` if a Redis client is available.
        """
        while len(self._receipts) >= self._max_size:
            evicted_id, _ = self._receipts.popitem(last=False)
            logger.debug("Receipt LRU eviction: %s", evicted_id)

        self._receipts[receipt.receipt_id] = receipt
        self._chain_tips[receipt.tenant_id] = receipt.receipt_id

        if receipt.session_id:
            self._session_index.setdefault(receipt.session_id, set()).add(receipt.receipt_id)
        if receipt.trace_id:
            self._trace_index.setdefault(receipt.trace_id, set()).add(receipt.receipt_id)

        if self._redis is not None:
            try:
                asyncio.get_running_loop()
                asyncio.create_task(self._atomic_redis_commit(receipt))
            except RuntimeError:
                pass  # No event-loop (sync tests / CLI) — skip Redis

    async def _atomic_redis_commit(self, receipt: DecisionReceipt) -> None:
        """Atomic MULTI/EXEC pipeline — one network roundtrip, crash-consistent."""
        if self._redis is None:
            return
        try:
            payload = orjson.dumps(receipt.model_dump(mode="json"))
            pipe = self._redis.pipeline(transaction=True)

            pipe.setex(f"receipt:{receipt.tenant_id}:{receipt.receipt_id}", self._ttl, payload)
            pipe.set(f"receipt_chain:{receipt.tenant_id}", receipt.receipt_hash)
            if receipt.session_id:
                pipe.sadd(f"receipt_session:{receipt.session_id}", receipt.receipt_id)
            if receipt.trace_id:
                pipe.sadd(f"receipt_trace:{receipt.trace_id}", receipt.receipt_id)

            await asyncio.to_thread(pipe.execute)
        except Exception as e:
            logger.warning("Receipt Redis commit failed (best-effort): %s", e)

    # ------------------------------------------------------------------
    # Query API
    # ------------------------------------------------------------------

    def get(self, receipt_id: str) -> DecisionReceipt | None:
        """Retrieve a single receipt by ID."""
        return self._receipts.get(receipt_id)

    def get_by_session(self, session_id: str) -> list[DecisionReceipt]:
        """Retrieve all receipts for a session, ordered by timestamp."""
        receipt_ids = self._session_index.get(session_id, set())
        receipts = [self._receipts[rid] for rid in receipt_ids if rid in self._receipts]
        return sorted(receipts, key=lambda r: r.timestamp)

    def get_by_trace(self, trace_id: str) -> list[DecisionReceipt]:
        """Retrieve all receipts for a trace (single request lifecycle)."""
        receipt_ids = self._trace_index.get(trace_id, set())
        receipts = [self._receipts[rid] for rid in receipt_ids if rid in self._receipts]
        return sorted(receipts, key=lambda r: r.timestamp)

    def get_by_tenant(self, tenant_id: str, limit: int = 100) -> list[DecisionReceipt]:
        """Retrieve recent receipts for a tenant (newest first)."""
        matching = [r for r in self._receipts.values() if r.tenant_id == tenant_id]
        matching.sort(key=lambda r: r.timestamp, reverse=True)
        return matching[:limit]

    @property
    def count(self) -> int:
        """Total number of in-memory receipts."""
        return len(self._receipts)
