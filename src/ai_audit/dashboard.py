"""
ai_audit.dashboard — SPRT Continuous Certification for Compliance Monitoring.

Implements Sequential Probability Ratio Test (SPRT) for runtime compliance
certification. The system continuously monitors reject rates and quality
scores, transitioning between states:

- ``CERTIFIED``:  Reject rate below threshold with statistical confidence.
- ``MONITORING``: Insufficient data or inconclusive SPRT.
- ``FLAGGED``:    Reject rate exceeds threshold — requires investigation.
"""

from __future__ import annotations

import contextlib
import math
from dataclasses import dataclass, field
from datetime import UTC, datetime

from ai_audit.models import DecisionReceipt, ReceiptAction


@dataclass
class ComplianceSummary:
    """Aggregated compliance summary for a session or tenant.

    Attributes:
        total_receipts:        Total receipts analysed.
        action_counts:         Counts per ``ReceiptAction``.
        check_fire_rates:      Fraction of receipts where each check fired.
        avg_quality_score:     Mean quality score across supervisor post-checks.
        chain_integrity:       Whether hash-chain is intact.

        sprt_status:           ``CERTIFIED`` | ``MONITORING`` | ``FLAGGED``.
        compliance_confidence: Running SPRT confidence (0.0–1.0).
        last_verified_at:      ISO timestamp of last chain verification.
        verification_key_id:   Hex prefix of the Ed25519 public key.
    """

    total_receipts: int = 0
    action_counts: dict[str, int] = field(default_factory=dict)
    check_fire_rates: dict[str, float] = field(default_factory=dict)
    avg_quality_score: float = 0.0
    chain_integrity: bool = True

    sprt_status: str = "MONITORING"
    compliance_confidence: float = 1.0
    last_verified_at: str = ""
    verification_key_id: str = ""


# SPRT parameters
_REJECT_THRESHOLD_P0 = 0.05   # Null hypothesis: reject rate <= 5%
_REJECT_THRESHOLD_P1 = 0.15   # Alternative hypothesis: reject rate >= 15%
_SPRT_ALPHA = 0.05             # False positive rate
_SPRT_BETA = 0.10              # False negative rate
_MIN_SAMPLES = 10              # Minimum receipts before SPRT kicks in


def _sprt_boundaries() -> tuple[float, float]:
    """Compute SPRT acceptance/rejection log-likelihood boundaries."""
    lower = math.log(_SPRT_BETA / (1 - _SPRT_ALPHA))
    upper = math.log((1 - _SPRT_BETA) / _SPRT_ALPHA)
    return lower, upper


def build_compliance_summary(
    receipts: list[DecisionReceipt],
    chain_intact: bool = True,
    verify_key_hex: str = "",
) -> ComplianceSummary:
    """Build a compliance summary with SPRT certification status.

    Parameters:
        receipts:       List of Decision Receipts to analyse.
        chain_intact:   Whether the hash-chain verification passed.
        verify_key_hex: Hex-encoded Ed25519 public key ID.

    Returns:
        ``ComplianceSummary`` with SPRT status and aggregated metrics.
    """
    summary = ComplianceSummary(
        total_receipts=len(receipts),
        chain_integrity=chain_intact,
        verification_key_id=verify_key_hex[:16] if verify_key_hex else "",
        last_verified_at=datetime.now(UTC).isoformat(),
    )

    if not receipts:
        return summary

    # Action counts
    for r in receipts:
        action_key = r.action.value
        summary.action_counts[action_key] = summary.action_counts.get(action_key, 0) + 1

    # Check fire rates
    check_fires: dict[str, int] = {}
    check_totals: dict[str, int] = {}
    quality_scores: list[float] = []

    for r in receipts:
        for check in r.checks:
            check_totals[check.name] = check_totals.get(check.name, 0) + 1
            if check.fired:
                check_fires[check.name] = check_fires.get(check.name, 0) + 1
            if check.name == "supervisor_post" and "quality_score" in check.detail:
                with contextlib.suppress(ValueError, TypeError):
                    quality_scores.append(float(check.detail["quality_score"]))

    for name, total in check_totals.items():
        summary.check_fire_rates[name] = check_fires.get(name, 0) / total

    if quality_scores:
        summary.avg_quality_score = sum(quality_scores) / len(quality_scores)

    # SPRT Continuous Certification
    n = len(receipts)
    reject_count = summary.action_counts.get(ReceiptAction.REJECT.value, 0)
    reject_count += summary.action_counts.get(ReceiptAction.ESCALATE.value, 0)

    if n < _MIN_SAMPLES:
        summary.sprt_status = "MONITORING"
        summary.compliance_confidence = 1.0 - (reject_count / max(n, 1))
        return summary

    p0 = _REJECT_THRESHOLD_P0
    p1 = _REJECT_THRESHOLD_P1
    lower_bound, upper_bound = _sprt_boundaries()

    llr = 0.0
    for r in sorted(receipts, key=lambda x: x.timestamp):
        is_reject = r.action in (ReceiptAction.REJECT, ReceiptAction.ESCALATE)
        if is_reject:
            llr += math.log(p1 / max(p0, 1e-10))
        else:
            llr += math.log((1 - p1) / max(1 - p0, 1e-10))

    if llr <= lower_bound:
        summary.sprt_status = "CERTIFIED"
        summary.compliance_confidence = 1.0 - (reject_count / n)
    elif llr >= upper_bound:
        summary.sprt_status = "FLAGGED"
        summary.compliance_confidence = max(0.0, 1.0 - (reject_count / n))
    else:
        summary.sprt_status = "MONITORING"
        summary.compliance_confidence = 1.0 - (reject_count / n)

    if not chain_intact:
        summary.sprt_status = "FLAGGED"

    return summary
