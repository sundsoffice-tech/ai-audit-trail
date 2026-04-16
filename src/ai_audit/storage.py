"""
ai_audit.storage — Storage Backend ABCs for Hot/Cold tiering.

Provides abstract interfaces so the host application can plug in any
persistence backend without modifying ai-audit internals.

Backends:
- ``StorageBackend`` ABC — write/read/query/healthcheck
- ``InMemoryBackend`` — reference implementation (dev/test)

Future backends (implemented by host application):
- ``RedisHotBackend`` — TTL-based hot storage
- ``PostgresColdBackend`` — JSONB partitioned by tenant+month
- ``S3ArchiveBackend`` — compressed archive (gzip/zstd)

NB 005c5140 (Performance) validated — 2026-04-16.
NB correction: streaming _tier_down, no full-RAM materialisation.
"""

from __future__ import annotations

import abc
from collections import OrderedDict

from ai_audit.batch import BatchSeal
from ai_audit.models import DecisionReceipt


class StorageBackend(abc.ABC):
    """Abstract base class for receipt storage backends.

    Implement this to integrate with your persistence layer.
    All methods are synchronous; for async backends, wrap with
    ``asyncio.to_thread`` or implement an async subclass.
    """

    @abc.abstractmethod
    def write_receipt(self, receipt: DecisionReceipt) -> None:
        """Persist a single receipt."""

    @abc.abstractmethod
    def write_batch_seal(self, seal: BatchSeal) -> None:
        """Persist a batch seal."""

    @abc.abstractmethod
    def read_receipt(self, receipt_id: str) -> DecisionReceipt | None:
        """Retrieve a receipt by ID."""

    @abc.abstractmethod
    def read_batch_seal(self, batch_id: str) -> BatchSeal | None:
        """Retrieve a batch seal by ID."""

    @abc.abstractmethod
    def query_by_tenant(self, tenant_id: str, limit: int = 100) -> list[DecisionReceipt]:
        """Query receipts by tenant ID."""

    @abc.abstractmethod
    def healthcheck(self) -> bool:
        """Return True if the backend is healthy and writable."""


class InMemoryBackend(StorageBackend):
    """In-memory reference implementation for development and testing.

    Uses OrderedDict with optional LRU eviction.
    """

    def __init__(self, max_receipts: int = 50_000) -> None:
        self._max = max_receipts
        self._receipts: OrderedDict[str, DecisionReceipt] = OrderedDict()
        self._seals: dict[str, BatchSeal] = {}

    def write_receipt(self, receipt: DecisionReceipt) -> None:
        while len(self._receipts) >= self._max:
            self._receipts.popitem(last=False)
        self._receipts[receipt.receipt_id] = receipt

    def write_batch_seal(self, seal: BatchSeal) -> None:
        self._seals[seal.batch_id] = seal

    def read_receipt(self, receipt_id: str) -> DecisionReceipt | None:
        return self._receipts.get(receipt_id)

    def read_batch_seal(self, batch_id: str) -> BatchSeal | None:
        return self._seals.get(batch_id)

    def query_by_tenant(self, tenant_id: str, limit: int = 100) -> list[DecisionReceipt]:
        matching = [r for r in self._receipts.values() if r.tenant_id == tenant_id]
        matching.sort(key=lambda r: r.timestamp, reverse=True)
        return matching[:limit]

    def healthcheck(self) -> bool:
        return True

    @property
    def receipt_count(self) -> int:
        return len(self._receipts)

    @property
    def seal_count(self) -> int:
        return len(self._seals)
