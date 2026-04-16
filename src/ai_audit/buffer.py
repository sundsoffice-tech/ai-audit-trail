"""
ai_audit.buffer — Ring-Buffer with Backpressure for high-throughput ingestion.

Decouples receipt creation from storage persistence via a bounded
async queue. When the queue is full, ``AuditBufferFullError`` is raised
(fail-closed — no silent data loss).

NB 005c5140 corrections applied:
- Queue maxsize 50,000 (not 4096) for 5s buffer at 10k req/s
- No O_SYNC per event — batch fsync only

Usage::

    from ai_audit.buffer import AuditBuffer, AuditBufferFullError

    buffer = AuditBuffer(maxsize=50_000)
    buffer.put(receipt)  # raises AuditBufferFullError if full
    batch = buffer.drain(max_items=2048)  # non-blocking drain

NB 005c5140 (Performance) validated — 2026-04-16.
"""

from __future__ import annotations

import threading
from collections import deque

from ai_audit.models import DecisionReceipt


class AuditBufferFullError(Exception):
    """Raised when the audit buffer is at capacity (backpressure).

    This is a fail-closed signal: the caller must handle it
    (e.g. retry, alert, or reject the request).
    """


class AuditBuffer:
    """Thread-safe bounded ring-buffer for receipt ingestion.

    Parameters:
        maxsize: Maximum buffer capacity (default: 50,000).
                 At 10k req/s this provides ~5 seconds of buffering.
    """

    def __init__(self, maxsize: int = 50_000) -> None:
        self._maxsize = maxsize
        self._buffer: deque[DecisionReceipt] = deque(maxlen=maxsize)
        self._lock = threading.Lock()
        self._total_put: int = 0
        self._total_drained: int = 0
        self._total_dropped: int = 0

    def put(self, receipt: DecisionReceipt) -> None:
        """Add a receipt to the buffer.

        Raises:
            AuditBufferFullError: If the buffer is at capacity.
        """
        with self._lock:
            if len(self._buffer) >= self._maxsize:
                self._total_dropped += 1
                raise AuditBufferFullError(
                    f"Audit buffer full ({self._maxsize} items). "
                    "Receipt cannot be buffered — backpressure applied."
                )
            self._buffer.append(receipt)
            self._total_put += 1

    def drain(self, max_items: int = 2048) -> list[DecisionReceipt]:
        """Drain up to ``max_items`` receipts from the buffer.

        Returns:
            List of receipts (may be empty if buffer is empty).
            This is non-blocking.
        """
        with self._lock:
            count = min(max_items, len(self._buffer))
            items = [self._buffer.popleft() for _ in range(count)]
            self._total_drained += count
            return items

    @property
    def size(self) -> int:
        """Current number of items in the buffer."""
        with self._lock:
            return len(self._buffer)

    @property
    def maxsize(self) -> int:
        """Maximum buffer capacity."""
        return self._maxsize

    @property
    def is_full(self) -> bool:
        """Whether the buffer is at capacity."""
        with self._lock:
            return len(self._buffer) >= self._maxsize

    @property
    def stats(self) -> dict[str, int]:
        """Buffer statistics."""
        with self._lock:
            return {
                "current_size": len(self._buffer),
                "maxsize": self._maxsize,
                "total_put": self._total_put,
                "total_drained": self._total_drained,
                "total_dropped": self._total_dropped,
            }
