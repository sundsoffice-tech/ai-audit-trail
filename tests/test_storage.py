"""Tests for Storage Backend ABCs."""


from ai_audit import (
    AuditConfig,
    ReceiptAction,
    ReceiptCollector,
    ReceiptStore,
    init_audit_config,
    reset_signing_key,
)
from ai_audit.batch import BatchSeal
from ai_audit.storage import InMemoryBackend


def setup_function() -> None:
    reset_signing_key()
    init_audit_config(AuditConfig(is_production=False))


def _make_receipt(tenant: str = "acme", idx: int = 0):
    store = ReceiptStore()
    c = ReceiptCollector(trace_id=f"t{idx}", tenant_id=tenant)
    c.set_input(f"query {idx}")
    c.set_output(f"answer {idx}")
    c.set_action(ReceiptAction.ALLOW)
    rid = c.emit(store)
    c.cleanup()
    return store.get(rid)


def test_inmemory_write_read() -> None:
    """InMemoryBackend should store and retrieve receipts."""
    backend = InMemoryBackend()
    receipt = _make_receipt()
    assert receipt is not None

    backend.write_receipt(receipt)
    assert backend.receipt_count == 1

    retrieved = backend.read_receipt(receipt.receipt_id)
    assert retrieved is not None
    assert retrieved.receipt_id == receipt.receipt_id


def test_inmemory_query_by_tenant() -> None:
    """query_by_tenant should return matching receipts."""
    backend = InMemoryBackend()
    for i in range(5):
        r = _make_receipt("acme", i)
        assert r is not None
        backend.write_receipt(r)
    for i in range(3):
        r = _make_receipt("other", i + 10)
        assert r is not None
        backend.write_receipt(r)

    acme_receipts = backend.query_by_tenant("acme")
    assert len(acme_receipts) == 5


def test_inmemory_lru_eviction() -> None:
    """InMemoryBackend should evict oldest when at capacity."""
    backend = InMemoryBackend(max_receipts=3)
    receipts = []
    for i in range(5):
        r = _make_receipt(idx=i)
        assert r is not None
        backend.write_receipt(r)
        receipts.append(r)

    assert backend.receipt_count == 3
    assert backend.read_receipt(receipts[0].receipt_id) is None  # evicted
    assert backend.read_receipt(receipts[4].receipt_id) is not None  # latest


def test_inmemory_batch_seal() -> None:
    """InMemoryBackend should store and retrieve batch seals."""
    backend = InMemoryBackend()
    seal = BatchSeal(batch_id="b1", tenant_id="acme", leaf_count=10)
    backend.write_batch_seal(seal)

    assert backend.seal_count == 1
    retrieved = backend.read_batch_seal("b1")
    assert retrieved is not None
    assert retrieved.leaf_count == 10


def test_inmemory_healthcheck() -> None:
    """InMemoryBackend healthcheck should always return True."""
    assert InMemoryBackend().healthcheck()


def test_read_nonexistent() -> None:
    """Reading non-existent IDs should return None."""
    backend = InMemoryBackend()
    assert backend.read_receipt("nonexistent") is None
    assert backend.read_batch_seal("nonexistent") is None
