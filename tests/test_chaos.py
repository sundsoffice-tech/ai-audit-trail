"""Chaos and stress tests for enterprise resilience.

These tests verify that ai-audit-trail behaves correctly under
concurrent access, high throughput, and error conditions.
"""

import threading

from ai_audit import (
    AuditConfig,
    ReceiptAction,
    ReceiptCollector,
    ReceiptStore,
    get_verify_key_hex,
    init_audit_config,
    reset_signing_key,
    verify_chain,
)
from ai_audit.buffer import AuditBuffer, AuditBufferFullError
from ai_audit.keys import DefaultKeyProvider


def setup_function() -> None:
    reset_signing_key()
    init_audit_config(AuditConfig(is_production=False))


def test_concurrent_appends() -> None:
    """Multiple threads appending to the same store should not corrupt data."""
    store = ReceiptStore()
    errors: list[Exception] = []

    def worker(thread_id: int) -> None:
        try:
            for i in range(50):
                c = ReceiptCollector(
                    trace_id=f"thread-{thread_id}-{i}",
                    tenant_id="acme",
                )
                c.set_input(f"query from thread {thread_id}")
                c.set_output(f"answer {i}")
                c.set_action(ReceiptAction.ALLOW)
                c.emit(store)
                c.cleanup()
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Errors during concurrent appends: {errors}"
    assert store.count == 200  # 4 threads × 50 receipts


def test_concurrent_key_loading() -> None:
    """Multiple threads calling _load() should get the same key (thread-safe)."""
    config = AuditConfig(is_production=False)
    provider = DefaultKeyProvider(config)
    keys: list[bytes] = []
    errors: list[Exception] = []

    def worker() -> None:
        try:
            key = provider.get_signing_key()
            keys.append(key.encode())
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    assert len(keys) == 10
    # All threads should get the same key
    assert len(set(keys)) == 1


def test_buffer_concurrent_put_drain() -> None:
    """Concurrent put and drain operations should not lose or corrupt data."""
    buf = AuditBuffer(maxsize=1000)
    store = ReceiptStore()
    put_count = 0
    drain_count = 0
    errors: list[Exception] = []
    lock = threading.Lock()

    def producer(thread_id: int) -> None:
        nonlocal put_count
        for i in range(100):
            c = ReceiptCollector(trace_id=f"p{thread_id}-{i}", tenant_id="acme")
            c.set_input(f"q{i}")
            c.set_output(f"a{i}")
            c.set_action(ReceiptAction.ALLOW)
            c.emit(store)
            c.cleanup()
            r = store.get(c._receipt.receipt_id)
            if r is None:
                continue
            try:
                buf.put(r)
                with lock:
                    put_count += 1
            except AuditBufferFullError:
                pass
            except Exception as e:
                errors.append(e)

    def consumer() -> None:
        nonlocal drain_count
        for _ in range(50):
            items = buf.drain(max_items=20)
            with lock:
                drain_count += len(items)

    producers = [threading.Thread(target=producer, args=(t,)) for t in range(3)]
    consumers = [threading.Thread(target=consumer) for _ in range(2)]

    for t in producers + consumers:
        t.start()
    for t in producers:
        t.join()
    # Drain remaining
    for t in consumers:
        t.join()
    remaining = buf.drain(max_items=10000)
    drain_count += len(remaining)

    assert not errors, f"Errors: {errors}"
    assert drain_count + buf.size <= put_count  # no data created from nothing


def test_high_throughput_seal_verify() -> None:
    """1000 receipts sealed and verified in sequence (no corruption)."""
    from datetime import UTC, datetime, timedelta

    store = ReceiptStore()
    base_time = datetime.now(UTC)

    for i in range(1000):
        c = ReceiptCollector(trace_id=f"t{i}", tenant_id="acme")
        c.set_input(f"query {i}")
        c.set_output(f"answer {i}")
        c.set_action(ReceiptAction.ALLOW)
        c._receipt.timestamp = base_time + timedelta(microseconds=i)
        c.emit(store)
        c.cleanup()

    receipts = store.get_by_tenant("acme", limit=2000)
    result = verify_chain(receipts, get_verify_key_hex())
    assert result.valid
    assert result.verified_receipts == 1000
