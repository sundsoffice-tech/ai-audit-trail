"""Smoke-tests for ai_audit.mcp_server tool functions (does not run the server).

The MCP transport is exercised by the MCP SDK; we only need to ensure our
tool-decorated functions return shapes the SDK can serialise and that the
business logic delegates correctly to the underlying verifier / crosswalk.
"""

from __future__ import annotations

import base64

import pytest

mcp_pkg = pytest.importorskip("mcp")

import nacl.signing  # noqa: E402

from ai_audit import (  # noqa: E402
    AuditConfig,
    ReceiptAction,
    ReceiptCollector,
    ReceiptStore,
    export_evidence_package,
    get_verify_key_hex,
    init_audit_config,
    reset_signing_key,
)
from ai_audit.mcp_server import (  # noqa: E402
    compliance_summary,
    list_compliance_controls,
    verify_chain,
    verify_evidence_package,
    verify_receipt,
)


def _seed_chain(n: int = 5) -> tuple[list, str]:
    """Reset state, mint n receipts, return (receipts, verify_key_hex)."""
    reset_signing_key()
    seed_hex = nacl.signing.SigningKey.generate().encode().hex()
    init_audit_config(AuditConfig(signing_key_hex=seed_hex))
    store = ReceiptStore()
    for i in range(n):
        c = ReceiptCollector(trace_id=f"t-{i}", tenant_id="acme")
        c.set_input(f"q-{i}")
        c.set_output(f"a-{i}")
        c.set_action(ReceiptAction.ALLOW if i != 1 else ReceiptAction.REJECT)
        c.emit(store)
        c.cleanup()
    return store.get_by_tenant("acme"), get_verify_key_hex()


# ---------------------------------------------------------------------------
# verify_receipt
# ---------------------------------------------------------------------------


def test_verify_receipt_valid() -> None:
    receipts, vk = _seed_chain(1)
    out = verify_receipt(receipts[0].model_dump_json(), vk)
    assert out["valid"] is True
    assert out["receipt_id"] == receipts[0].receipt_id


def test_verify_receipt_bad_json_returns_invalid() -> None:
    out = verify_receipt("not json", "00" * 32)
    assert out["valid"] is False
    assert "invalid receipt JSON" in out["error"]


def test_verify_receipt_wrong_key_returns_invalid() -> None:
    receipts, _vk = _seed_chain(1)
    other_vk = nacl.signing.SigningKey.generate().verify_key.encode().hex()
    out = verify_receipt(receipts[0].model_dump_json(), other_vk)
    assert out["valid"] is False


# ---------------------------------------------------------------------------
# verify_chain
# ---------------------------------------------------------------------------


def test_verify_chain_round_trip() -> None:
    receipts, vk = _seed_chain(5)
    jsonl = "\n".join(r.model_dump_json() for r in receipts)
    out = verify_chain(jsonl, vk)
    assert out["valid"] is True
    assert out["verified_receipts"] == 5
    assert out["total_receipts"] == 5
    assert out["first_failure_idx"] == -1


def test_verify_chain_detects_tamper() -> None:
    receipts, vk = _seed_chain(3)
    receipts[1].action = ReceiptAction.ALLOW   # was REJECT
    jsonl = "\n".join(r.model_dump_json() for r in receipts)
    out = verify_chain(jsonl, vk)
    assert out["valid"] is False
    assert out["first_failure_idx"] == 1
    assert out["failed_receipt_id"] == receipts[1].receipt_id


def test_verify_chain_handles_blank_lines() -> None:
    receipts, vk = _seed_chain(2)
    jsonl = "\n".join(r.model_dump_json() for r in receipts) + "\n\n"
    out = verify_chain(jsonl, vk)
    assert out["valid"] is True
    assert out["total_receipts"] == 2


# ---------------------------------------------------------------------------
# verify_evidence_package
# ---------------------------------------------------------------------------


def test_verify_evidence_package_round_trip(tmp_path) -> None:
    from ai_audit.keys import get_signing_key

    receipts, vk = _seed_chain(3)
    bundle_path = tmp_path / "bundle.zip"
    export_evidence_package(
        receipts,
        verify_key_hex=vk,
        signing_key=get_signing_key(),
        output_path=str(bundle_path),
        tenant_id="acme",
    )

    zip_b64 = base64.b64encode(bundle_path.read_bytes()).decode()
    out = verify_evidence_package(zip_b64)
    assert out["valid"] is True
    assert "receipts.jsonl" in out["files_in_bundle"]
    assert out["error"] == ""


def test_verify_evidence_package_bad_base64() -> None:
    out = verify_evidence_package("!!!not-base64!!!")
    assert out["valid"] is False
    assert "bad base64" in out["error"]


def test_verify_evidence_package_not_a_zip() -> None:
    raw = b"definitely not a zip"
    out = verify_evidence_package(base64.b64encode(raw).decode())
    assert out["valid"] is False
    assert "ZIP" in out["error"] or "not a valid" in out["error"]


def test_verify_evidence_package_size_cap() -> None:
    raw = b"\x00" * (51 * 1024 * 1024)
    out = verify_evidence_package(base64.b64encode(raw).decode())
    assert out["valid"] is False
    assert "50 MiB" in out["error"]


# ---------------------------------------------------------------------------
# compliance_summary
# ---------------------------------------------------------------------------


def test_compliance_summary_aggregates() -> None:
    receipts, _vk = _seed_chain(5)  # 4 ALLOW + 1 REJECT
    jsonl = "\n".join(r.model_dump_json() for r in receipts)
    out = compliance_summary(jsonl)
    assert out["total_receipts"] == 5
    assert out["allow_rate"] == pytest.approx(4 / 5)
    assert out["reject_rate"] == pytest.approx(1 / 5)
    assert "allow" in out["action_counts"]
    assert "sprt_status" in out


def test_compliance_summary_empty_jsonl() -> None:
    out = compliance_summary("")
    assert out["total_receipts"] == 0
    assert out["reject_rate"] == 0.0


# ---------------------------------------------------------------------------
# list_compliance_controls
# ---------------------------------------------------------------------------


def test_list_compliance_controls_static() -> None:
    out = list_compliance_controls("")
    assert out["nist_function_map"] == {}
    assert isinstance(out["controls"], list)
    assert len(out["controls"]) > 0
    frameworks = {c["framework"] for c in out["controls"]}
    assert "ISO 42001" in frameworks
    assert "NIST AI RMF" in frameworks


def test_list_compliance_controls_with_receipts() -> None:
    receipts, _vk = _seed_chain(3)
    jsonl = "\n".join(r.model_dump_json() for r in receipts)
    out = list_compliance_controls(jsonl)
    assert out["nist_function_map"] != {}
    assert "GOVERN" in out["nist_function_map"]
    assert "MEASURE" in out["nist_function_map"]
    for _func, body in out["nist_function_map"].items():
        assert "status" in body
        assert "coverage" in body
