"""Tests for Ring-Buffer with Backpressure."""

import pytest

from ai_audit import (
    AuditConfig,
    ReceiptAction,
    ReceiptCollector,
    ReceiptStore,
    init_audit_config,
    reset_signing_key,
)
from ai_audit.buffer import AuditBuffer, AuditBufferFullError


def setup_function() -> None:
    reset_signing_key()
    init_audit_config(AuditConfig(is_production=False))


def _make_receipt(idx: int = 0):
    store = ReceiptStore()
    c = ReceiptCollector(trace_id=f"t{idx}", tenant_id="acme")
    c.set_input(f"query {idx}")
    c.set_output(f"answer {idx}")
    c.set_action(ReceiptAction.ALLOW)
    rid = c.emit(store)
    c.cleanup()
    return store.get(rid)


def test_put_and_drain() -> None:
    """Basic put/drain roundtrip."""
    buf = AuditBuffer(maxsize=100)
    r = _make_receipt()
    assert r is not None
    buf.put(r)
    assert buf.size == 1

    items = buf.drain(max_items=10)
    assert len(items) == 1
    assert buf.size == 0


def test_backpressure_on_full() -> None:
    """Buffer must raise AuditBufferFullError when full."""
    buf = AuditBuffer(maxsize=3)
    for i in range(3):
        r = _make_receipt(i)
        assert r is not None
        buf.put(r)

    assert buf.is_full

    r = _make_receipt(99)
    assert r is not None
    with pytest.raises(AuditBufferFullError):
        buf.put(r)


def test_drain_respects_max_items() -> None:
    """Drain should return at most max_items."""
    buf = AuditBuffer(maxsize=100)
    for i in range(10):
        r = _make_receipt(i)
        assert r is not None
        buf.put(r)

    items = buf.drain(max_items=3)
    assert len(items) == 3
    assert buf.size == 7


def test_drain_empty_buffer() -> None:
    """Draining an empty buffer should return empty list."""
    buf = AuditBuffer(maxsize=100)
    assert buf.drain() == []


def test_stats() -> None:
    """Stats should track put/drain/dropped counts."""
    buf = AuditBuffer(maxsize=2)
    for i in range(2):
        r = _make_receipt(i)
        assert r is not None
        buf.put(r)

    # Try to add one more — should be dropped
    r = _make_receipt(99)
    assert r is not None
    with pytest.raises(AuditBufferFullError):
        buf.put(r)

    buf.drain(max_items=1)

    stats = buf.stats
    assert stats["total_put"] == 2
    assert stats["total_drained"] == 1
    assert stats["total_dropped"] == 1
    assert stats["current_size"] == 1
