"""ai-audit-trail MCP server — exposes read-only verification tools to AI agents.

Run as a stdio MCP server::

    ai-audit-mcp                       # console-script entry-point
    python -m ai_audit.mcp_server      # equivalent

Or configure in Claude Desktop / Cline / Cursor::

    {
      "mcpServers": {
        "ai-audit-trail": {
          "command": "ai-audit-mcp",
          "args": []
        }
      }
    }

Why only verification tools (no signing, no key generation):
    Allowing an LLM agent to *forge* signed audit receipts would defeat the
    entire tamper-evidence guarantee. The server therefore exposes:

      - verify_receipt          (single receipt JSON)
      - verify_chain            (JSONL stream of receipts)
      - verify_evidence_package (base64-encoded evidence ZIP bundle)
      - compliance_summary      (aggregate metrics)
      - list_compliance_controls (read-only crosswalk lookup)

    Signing keys, KMS access, and ``ReceiptCollector.emit`` remain in the
    application's trust boundary — never under agent control.

Optional dep: ``pip install ai-audit-trail[mcp]``.
"""

from __future__ import annotations

import base64
import io
import logging
import zipfile
from typing import Any

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "ai_audit.mcp_server requires 'mcp>=1.0'. "
        "Install with: pip install ai-audit-trail[mcp]"
    ) from e

from ai_audit.crosswalk import build_crosswalk, nist_function_map
from ai_audit.dashboard import build_compliance_summary
from ai_audit.export import verify_evidence_package as _verify_zip_path
from ai_audit.models import DecisionReceipt
from ai_audit.verifier import verify_chain as _verify_chain

logger = logging.getLogger(__name__)

mcp = FastMCP("ai-audit-trail")


# ---------------------------------------------------------------------------
# Tool: verify_receipt
# ---------------------------------------------------------------------------


@mcp.tool()  # type: ignore[misc, unused-ignore]
def verify_receipt(receipt_json: str, public_key_hex: str) -> dict[str, Any]:
    """Verify a single signed Decision Receipt against an Ed25519 public key.

    Args:
        receipt_json:    A JSON object string of one DecisionReceipt.
        public_key_hex:  Hex-encoded 32-byte Ed25519 verification key.

    Returns:
        A dict with ``valid`` (bool), ``error`` (str), and ``receipt_id`` (str).
        ``valid=True`` means the signature matches and the self-hash is correct.
        Chain linkage is *not* checked here — use ``verify_chain`` for that.
    """
    try:
        receipt = DecisionReceipt.model_validate_json(receipt_json)
    except Exception as exc:  # noqa: BLE001
        return {"valid": False, "error": f"invalid receipt JSON: {exc}", "receipt_id": ""}

    result = _verify_chain([receipt], public_key_hex)
    return {
        "valid": bool(result.valid),
        "error": result.error or "",
        "receipt_id": receipt.receipt_id,
    }


# ---------------------------------------------------------------------------
# Tool: verify_chain
# ---------------------------------------------------------------------------


@mcp.tool()  # type: ignore[misc, unused-ignore]
def verify_chain(receipts_jsonl: str, public_key_hex: str) -> dict[str, Any]:
    """Verify an ordered hash-chain of signed receipts.

    Args:
        receipts_jsonl:  JSON-Lines stream — one DecisionReceipt JSON per line,
                         in chain order (oldest first).
        public_key_hex:  Hex-encoded 32-byte Ed25519 verification key.

    Returns:
        Dict with ``valid`` (bool), ``verified_receipts``, ``total_receipts``,
        ``first_failure_idx`` (-1 if all pass), ``failed_receipt_id``, and
        ``error``.
    """
    receipts: list[DecisionReceipt] = []
    for i, line in enumerate(receipts_jsonl.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            receipts.append(DecisionReceipt.model_validate_json(line))
        except Exception as exc:  # noqa: BLE001
            return {
                "valid": False,
                "verified_receipts": 0,
                "total_receipts": i,
                "first_failure_idx": i,
                "failed_receipt_id": "",
                "error": f"invalid receipt at line {i}: {exc}",
            }

    result = _verify_chain(receipts, public_key_hex)
    return {
        "valid": bool(result.valid),
        "verified_receipts": result.verified_receipts,
        "total_receipts": result.total_receipts,
        "first_failure_idx": result.first_failure_idx,
        "failed_receipt_id": result.failed_receipt_id,
        "error": result.error or "",
    }


# ---------------------------------------------------------------------------
# Tool: verify_evidence_package
# ---------------------------------------------------------------------------


@mcp.tool()  # type: ignore[misc, unused-ignore]
def verify_evidence_package(zip_b64: str) -> dict[str, Any]:
    """Verify a base64-encoded evidence-package ZIP bundle offline.

    Args:
        zip_b64:  Base64-encoded contents of an evidence-package ZIP produced
                  by ``ai_audit.export_evidence_package(...)``.

    Returns:
        Dict with ``valid`` (bool), ``files_in_bundle``, and ``error``.
    """
    try:
        raw = base64.b64decode(zip_b64, validate=True)
    except Exception as exc:  # noqa: BLE001
        return {"valid": False, "files_in_bundle": [], "error": f"bad base64: {exc}"}

    # ZIP-only safety check: must look like a ZIP, must not be huge
    if len(raw) > 50 * 1024 * 1024:
        return {"valid": False, "files_in_bundle": [], "error": "bundle exceeds 50 MiB cap"}

    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            files = zf.namelist()
    except zipfile.BadZipFile:
        return {"valid": False, "files_in_bundle": [], "error": "not a valid ZIP archive"}

    # Write to a temp file because the verifier API takes a path.
    import os
    import tempfile

    tmp_path: str | None = None
    try:
        fd, tmp_path = tempfile.mkstemp(suffix=".zip", prefix="ai-audit-mcp-")
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
        ok = _verify_zip_path(tmp_path)
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    return {
        "valid": bool(ok),
        "files_in_bundle": files,
        "error": "" if ok else "verification failed (see verify.py inside the bundle for details)",
    }


# ---------------------------------------------------------------------------
# Tool: compliance_summary
# ---------------------------------------------------------------------------


@mcp.tool()  # type: ignore[misc, unused-ignore]
def compliance_summary(receipts_jsonl: str) -> dict[str, Any]:
    """Aggregate compliance metrics for a list of Decision Receipts.

    Args:
        receipts_jsonl:  JSON-Lines stream of DecisionReceipts.

    Returns:
        Dict with ``total_receipts``, ``action_counts``, ``action_distribution``,
        ``reject_rate``, ``allow_rate``, ``sprt_status`` (CERTIFIED / MONITORING /
        FLAGGED), ``compliance_confidence``, ``avg_quality_score``, and
        ``check_fire_rates``.
    """
    receipts: list[DecisionReceipt] = []
    for line in receipts_jsonl.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            receipts.append(DecisionReceipt.model_validate_json(line))
        except Exception:  # noqa: BLE001
            continue

    summary = build_compliance_summary(receipts)
    return {
        "total_receipts": summary.total_receipts,
        "action_counts": dict(summary.action_counts),
        "action_distribution": summary.action_distribution,
        "reject_rate": round(summary.reject_rate, 6),
        "allow_rate": round(summary.allow_rate, 6),
        "sprt_status": summary.sprt_status,
        "compliance_confidence": round(summary.compliance_confidence, 6),
        "avg_quality_score": round(summary.avg_quality_score, 6),
        "check_fire_rates": dict(summary.check_fire_rates),
        "is_certified": summary.is_certified,
        "is_flagged": summary.is_flagged,
    }


# ---------------------------------------------------------------------------
# Tool: list_compliance_controls
# ---------------------------------------------------------------------------


@mcp.tool()  # type: ignore[misc, unused-ignore]
def list_compliance_controls(receipts_jsonl: str = "") -> dict[str, Any]:
    """List the compliance controls covered by ai-audit-trail's crosswalks.

    When ``receipts_jsonl`` is empty the response is the static catalogue of
    supported controls (ISO 42001, NIST AI RMF, EU AI Act). When receipts are
    provided, each control entry is enriched with the coverage and status
    derived from those receipts.

    Args:
        receipts_jsonl:  Optional JSONL stream of DecisionReceipts. When given,
                         coverage / status are computed from these receipts.

    Returns:
        Dict with ``controls`` (list) and ``nist_function_map`` (dict).
    """
    receipts: list[DecisionReceipt] = []
    for line in receipts_jsonl.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            receipts.append(DecisionReceipt.model_validate_json(line))
        except Exception:  # noqa: BLE001
            continue

    crosswalk = build_crosswalk(receipts)
    return {
        "controls": [
            {
                "framework": c.framework,
                "control_id": c.control_id,
                "description": c.description,
                "evidence_fields": list(c.evidence_fields),
                "coverage": round(c.coverage, 4),
                "status": c.status.value if hasattr(c.status, "value") else str(c.status),
            }
            for c in crosswalk
        ],
        "nist_function_map": (
            {
                func_name: {
                    "control_id": cw.control_id,
                    "coverage": round(cw.coverage, 4),
                    "status": cw.status.value if hasattr(cw.status, "value") else str(cw.status),
                }
                for func_name, cw in nist_function_map(receipts).items()
            }
            if receipts
            else {}
        ),
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Console-script entry point: run the stdio MCP server."""
    logging.basicConfig(level=logging.INFO, stream=__import__("sys").stderr)
    logger.info("ai-audit-trail MCP server starting (stdio transport)")
    mcp.run()


if __name__ == "__main__":
    main()
