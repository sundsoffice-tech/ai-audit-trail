"""Basic smoke tests for ai-audit."""

from ai_audit import (
    AuditConfig,
    ReceiptAction,
    ReceiptCollector,
    ReceiptStore,
    build_compliance_summary,
    canonicalize_input,
    get_verify_key_hex,
    init_audit_config,
    reset_signing_key,
    verify_chain,
)
from ai_audit.keys import get_signing_key


def setup_function():
    reset_signing_key()
    init_audit_config(AuditConfig(is_production=False))


def test_import():
    assert ReceiptCollector is not None
    assert ReceiptStore is not None


def test_receipt_roundtrip():
    store = ReceiptStore()
    collector = ReceiptCollector(trace_id="t1", tenant_id="acme", session_id="s1")
    collector.set_input("Hello world")
    collector.add_check("safety", score=0.1, threshold=0.8, fired=False)
    collector.set_output("Hi there!")
    collector.set_action(ReceiptAction.ALLOW)
    receipt_id = collector.emit(store)
    collector.cleanup()

    assert store.count == 1
    r = store.get(receipt_id)
    assert r is not None
    assert r.action == ReceiptAction.ALLOW
    assert r.receipt_hash != ""
    assert r.signature != ""


def test_chain_verification():
    store = ReceiptStore()
    for i in range(3):
        c = ReceiptCollector(trace_id=f"t{i}", tenant_id="acme")
        c.set_input(f"query {i}")
        c.set_output(f"answer {i}")
        c.set_action(ReceiptAction.ALLOW)
        c.emit(store)
        c.cleanup()

    receipts = store.get_by_tenant("acme")
    result = verify_chain(receipts, get_verify_key_hex())
    assert result.valid
    assert result.verified_receipts == 3


def test_canonicalize_input():
    a = canonicalize_input("Hello   World")
    b = canonicalize_input("hello world")
    assert a == b


def test_compliance_summary():
    store = ReceiptStore()
    for _i in range(30):  # 30 all-ALLOW receipts → SPRT converges to CERTIFIED
        c = ReceiptCollector(tenant_id="test")
        c.set_action(ReceiptAction.ALLOW)
        c.emit(store)
        c.cleanup()

    receipts = store.get_by_tenant("test")
    summary = build_compliance_summary(receipts, chain_intact=True)
    assert summary.sprt_status == "CERTIFIED"
    assert summary.total_receipts == 30


def _make_chain(count: int = 3) -> tuple:
    """Helper: create a sealed chain and return (store, receipts, verify_key_hex)."""
    store = ReceiptStore()
    for i in range(count):
        c = ReceiptCollector(trace_id=f"t{i}", tenant_id="acme")
        c.set_input(f"query {i}")
        c.set_output(f"answer {i}")
        c.set_action(ReceiptAction.ALLOW)
        c.emit(store)
        c.cleanup()
    receipts = store.get_by_tenant("acme")
    return store, receipts, get_verify_key_hex()


def test_forged_signature_detected():
    """Bit-flip in Ed25519 signature must be detected."""
    _, receipts, vk = _make_chain()
    sorted_receipts = sorted(receipts, key=lambda r: r.timestamp)
    # Flip one bit in the second receipt's signature
    target = sorted_receipts[1]
    sig_bytes = bytearray(bytes.fromhex(target.signature))
    sig_bytes[0] ^= 0x01
    target.signature = sig_bytes.hex()

    result = verify_chain(sorted_receipts, vk)
    assert not result.valid
    assert result.first_failure_idx == 1
    assert "forgery" in result.error.lower() or "signature" in result.error.lower()


def test_hash_mismatch_detected():
    """Overwriting receipt_hash while keeping signature must be detected."""
    _, receipts, vk = _make_chain()
    # Sort like verify_chain does, then corrupt the first receipt's hash
    sorted_receipts = sorted(receipts, key=lambda r: r.timestamp)
    sorted_receipts[0].receipt_hash = "0" * 64

    result = verify_chain(sorted_receipts, vk)
    assert not result.valid
    assert result.first_failure_idx == 0
    assert "hash" in result.error.lower()


def test_chain_break_detected():
    """Altering prev_receipt_hash must break chain linkage (re-sealed to bypass signature check)."""
    _, receipts, vk = _make_chain()
    sorted_receipts = sorted(receipts, key=lambda r: r.timestamp)
    # Change prev_receipt_hash on the third receipt, then re-seal so
    # the signature is valid but the chain link is broken.
    target = sorted_receipts[2]
    target.prev_receipt_hash = "dead" * 16
    target.seal(get_signing_key())

    result = verify_chain(sorted_receipts, vk)
    assert not result.valid
    assert result.first_failure_idx == 2
    assert "chain" in result.error.lower()


def test_inserted_receipt_detected():
    """A receipt inserted between two existing ones must break the chain."""
    _, receipts, vk = _make_chain()
    sorted_receipts = sorted(receipts, key=lambda r: r.timestamp)

    # Create an extra receipt with a timestamp between receipt 0 and 1
    from datetime import timedelta

    fake = ReceiptCollector(trace_id="fake", tenant_id="acme")
    fake.set_input("injected")
    fake.set_output("evil")
    fake.set_action(ReceiptAction.ALLOW)
    fake_store = ReceiptStore()
    fake.emit(fake_store)
    fake.cleanup()

    injected = fake_store.get_by_tenant("acme")[0]
    # Place it between receipt 0 and 1 by adjusting timestamp
    injected.timestamp = sorted_receipts[0].timestamp + timedelta(microseconds=1)
    # Its prev_receipt_hash won't match the actual chain
    injected.prev_receipt_hash = sorted_receipts[0].receipt_hash

    tampered_chain = sorted_receipts[:1] + [injected] + sorted_receipts[1:]
    result = verify_chain(tampered_chain, vk)
    assert not result.valid
    assert "chain" in result.error.lower() or "signature" in result.error.lower() or "hash" in result.error.lower()


def test_verify_empty_chain_returns_false():
    """verify_chain([]) must return valid=False (fail-closed, not fail-open)."""
    result = verify_chain([], get_verify_key_hex())
    assert not result.valid
    assert result.total_receipts == 0
    assert "no receipts" in result.error.lower()


def test_chain_tip_after_lru_eviction():
    """Chain tip must survive LRU eviction via aget_chain_tip Redis fallback.

    Without Redis, the sync get_chain_tip returns "" after eviction.
    This test verifies the in-memory eviction behaviour.
    """
    store = ReceiptStore(max_size=2)
    ids = []
    for i in range(3):
        c = ReceiptCollector(trace_id=f"t{i}", tenant_id="acme")
        c.set_input(f"query {i}")
        c.set_output(f"answer {i}")
        c.set_action(ReceiptAction.ALLOW)
        rid = c.emit(store)
        ids.append(rid)
        c.cleanup()

    # After 3 inserts with max_size=2, oldest receipt was evicted
    assert store.count == 2
    assert store.get(ids[0]) is None  # evicted
    # Chain tip still works because tip_id points to latest receipt
    tip = store.get_chain_tip("acme")
    assert tip != ""


def test_seal_payload_cached():
    """seal() must use the same payload bytes for hash and signature (ToCToU fix)."""
    store = ReceiptStore()
    c = ReceiptCollector(trace_id="t1", tenant_id="acme")
    c.set_input("test")
    c.set_output("result")
    c.set_action(ReceiptAction.ALLOW)
    rid = c.emit(store)
    c.cleanup()

    r = store.get(rid)
    assert r is not None
    # Verify that hash matches seal_payload
    import hashlib
    expected_hash = hashlib.sha256(r.seal_payload()).hexdigest()
    assert r.receipt_hash == expected_hash


def test_no_hacca_imports():
    """Ensure no HACCA internal imports leak into the package."""
    import importlib
    import pkgutil

    import ai_audit

    for _importer, modname, _ in pkgutil.walk_packages(
        path=ai_audit.__path__,
        prefix="ai_audit.",
    ):
        mod = importlib.import_module(modname)
        for attr in dir(mod):
            assert "packages." not in attr
            assert "apps." not in attr
