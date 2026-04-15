"""
ai_audit.verifier — Ed25519 + SHA-256 Chain Verifier for Decision Receipts.

Three-stage verification:
1. **Ed25519 Signature** — cryptographic non-repudiation (libsodium).
2. **SHA-256 Self-Hash** — payload integrity (detect bit-flips/corruption).
3. **Hash-Chain Linkage** — timeline integrity (detect insertions/deletions).

Usage::

    from ai_audit import verify_chain, get_verify_key_hex

    result = verify_chain(receipts, get_verify_key_hex())
    assert result.valid

Chain-break callback::

    def alert(tenant_id: str) -> None:
        print(f"Chain broken for tenant {tenant_id}!")

    result = verify_chain(receipts, pub_key_hex, on_chain_break=alert)
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

import nacl.exceptions
import nacl.signing

from ai_audit.models import DecisionReceipt


@dataclass
class VerificationResult:
    """Result of a chain verification operation.

    Attributes:
        valid:              All checks passed.
        total_receipts:     Number of receipts in the chain.
        verified_receipts:  Number of receipts that passed all checks.
        first_failure_idx:  Index of the first failing receipt (-1 if all pass).
        error:              Human-readable error description.
        failed_receipt_id:  ID of the first failing receipt.
        details:            Per-receipt verification detail.
    """

    valid: bool = True
    total_receipts: int = 0
    verified_receipts: int = 0
    first_failure_idx: int = -1
    error: str = ""
    failed_receipt_id: str = ""
    details: list[dict[str, object]] = field(default_factory=list)


def verify_chain(
    receipts: list[DecisionReceipt],
    public_key_hex: str,
    *,
    on_chain_break: Callable[[str], None] | None = None,
) -> VerificationResult:
    """Verify a chain of Decision Receipts (Ed25519 + SHA-256 + Chain-Linkage).

    Parameters:
        receipts:       List of receipts to verify (any order — sorted internally).
        public_key_hex: Hex-encoded Ed25519 public key (from ``get_verify_key_hex()``).
        on_chain_break: Optional callback invoked with ``tenant_id`` when a
                        hash-chain break is detected. Use this to integrate with
                        monitoring systems (Prometheus, alerting, etc.) without
                        creating a hard dependency.

    Returns:
        ``VerificationResult`` with ``valid=True`` if all checks pass.
    """
    if not receipts:
        return VerificationResult(valid=True, total_receipts=0, verified_receipts=0)

    verify_key = nacl.signing.VerifyKey(bytes.fromhex(public_key_hex))
    receipts_sorted = sorted(receipts, key=lambda r: r.timestamp)
    prev_hash = ""
    verified_count = 0

    for i, receipt in enumerate(receipts_sorted):
        detail: dict[str, object] = {
            "receipt_id": receipt.receipt_id,
            "index": i,
        }

        # 1. Ed25519 Signature Verification
        try:
            verify_key.verify(
                receipt.seal_payload(),
                bytes.fromhex(receipt.signature),
            )
            detail["signature"] = "valid"
        except nacl.exceptions.BadSignatureError:
            detail["signature"] = "FORGED"
            return VerificationResult(
                valid=False,
                total_receipts=len(receipts_sorted),
                verified_receipts=verified_count,
                first_failure_idx=i,
                error=f"Ed25519 signature forgery detected at receipt {receipt.receipt_id}",
                failed_receipt_id=receipt.receipt_id,
                details=[detail],
            )
        except Exception as e:
            detail["signature"] = f"error: {e}"
            return VerificationResult(
                valid=False,
                total_receipts=len(receipts_sorted),
                verified_receipts=verified_count,
                first_failure_idx=i,
                error=f"Signature verification error at receipt {receipt.receipt_id}: {e}",
                failed_receipt_id=receipt.receipt_id,
                details=[detail],
            )

        # 2. SHA-256 Self-Hash Integrity
        expected_hash = receipt.compute_hash()
        if receipt.receipt_hash != expected_hash:
            detail["hash"] = "MISMATCH"
            return VerificationResult(
                valid=False,
                total_receipts=len(receipts_sorted),
                verified_receipts=verified_count,
                first_failure_idx=i,
                error=f"SHA-256 hash mismatch at receipt {receipt.receipt_id}",
                failed_receipt_id=receipt.receipt_id,
                details=[detail],
            )
        detail["hash"] = "valid"

        # 3. Hash-Chain Linkage (skip first receipt — it has no predecessor)
        if i > 0 and receipt.prev_receipt_hash != prev_hash:
            detail["chain"] = "BROKEN"
            if on_chain_break is not None:
                on_chain_break(receipt.tenant_id)
            return VerificationResult(
                valid=False,
                total_receipts=len(receipts_sorted),
                verified_receipts=verified_count,
                first_failure_idx=i,
                error=(
                    f"Hash-chain broken at receipt {receipt.receipt_id} "
                    f"(expected prev={prev_hash[:16]}..., "
                    f"got={receipt.prev_receipt_hash[:16]}...)"
                ),
                failed_receipt_id=receipt.receipt_id,
                details=[detail],
            )
        detail["chain"] = "valid"

        prev_hash = receipt.receipt_hash
        verified_count += 1

    return VerificationResult(
        valid=True,
        total_receipts=len(receipts_sorted),
        verified_receipts=verified_count,
    )
