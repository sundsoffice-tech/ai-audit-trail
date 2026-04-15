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
