"""
ai_audit.contracts — Agent Behavioral Contracts with (p, δ, k)-Satisfaction.

World-first: Machine-readable behavioral contracts cryptographically bound
to the audit trail. Transforms abstract EU AI Act requirements into
testable specifications with mathematical guarantees.

**Key concepts:**
- **Hard Constraints (Invariants):** Must never be violated (e.g. "never leak PII")
- **Soft Constraints (Bounds):** Tolerable deviation up to δ (e.g. "reject rate ≤ 5%")
- **(p, δ, k)-Satisfaction:** The agent satisfies hard rules with probability p,
  soft deviations stay within δ, and recovers within k steps after violation.
- **Reliability Index Θ:** Single metric combining compliance, drift, and recovery.

Usage::

    from ai_audit.contracts import BehavioralContract, Constraint, ContractMonitor

    contract = BehavioralContract(
        contract_id="safety-v1",
        constraints=[
            Constraint(name="no_pii_leak", kind="hard", field="action", operator="!=", value="reject"),
            Constraint(name="reject_rate", kind="soft", field="reject_rate", operator="<=", value=0.05, delta=0.10),
        ],
    )
    monitor = ContractMonitor(contract)
    for receipt in receipts:
        state = monitor.evaluate(receipt)
    print(state.reliability_index)  # Θ ∈ [0, 1]

NB ee9616a5 (CHEF) + NB a861f2b3 (Agentic) validated — 2026-04-16.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from ai_audit.models import DecisionReceipt


@dataclass
class Constraint:
    """A single behavioral constraint.

    Attributes:
        name:      Human-readable constraint name.
        kind:      ``"hard"`` (invariant) or ``"soft"`` (bounded deviation).
        field:     Receipt field to evaluate (e.g. "action", "checks.safety.score").
        operator:  Comparison: ``"=="``, ``"!="``, ``"<"``, ``"<="``, ``">"``, ``">="``, ``"in"``, ``"not_in"``.
        value:     Expected value or threshold.
        delta:     Maximum tolerable deviation for soft constraints (default: 0.0).
    """

    name: str = ""
    kind: str = "hard"  # "hard" or "soft"
    field: str = ""
    operator: str = "=="
    value: object = None
    delta: float = 0.0


@dataclass
class BehavioralContract:
    """A set of behavioral constraints for an AI agent.

    Attributes:
        contract_id:  Unique contract identifier (versioned).
        tenant_id:    Tenant this contract applies to.
        constraints:  List of hard and soft constraints.
        description:  Human-readable description.
    """

    contract_id: str = ""
    tenant_id: str = ""
    constraints: list[Constraint] = field(default_factory=list)
    description: str = ""

    @property
    def hard_constraints(self) -> list[Constraint]:
        return [c for c in self.constraints if c.kind == "hard"]

    @property
    def soft_constraints(self) -> list[Constraint]:
        return [c for c in self.constraints if c.kind == "soft"]


@dataclass
class SatisfactionState:
    """(p, δ, k)-Satisfaction snapshot.

    Attributes:
        p:                    Hard constraint satisfaction probability (0.0–1.0).
        delta:                Maximum observed soft constraint deviation.
        k:                    Steps to recover after last violation (0 = no violation).
        reliability_index:    Θ = weighted combination of p, δ, k (0.0–1.0).
        total_evaluations:    Total receipts evaluated.
        hard_violations:      Total hard constraint violations.
        soft_violations:      Total soft constraint violations (beyond δ).
        last_violation_step:  Step number of most recent violation (-1 = none).
        recovered:            Whether the agent recovered after last violation.
        status:               ``"COMPLIANT"`` | ``"DEGRADED"`` | ``"VIOLATED"``.
        updated_at:           ISO 8601 timestamp.
    """

    p: float = 1.0
    delta: float = 0.0
    k: int = 0
    reliability_index: float = 1.0
    total_evaluations: int = 0
    hard_violations: int = 0
    soft_violations: int = 0
    last_violation_step: int = -1
    recovered: bool = True
    status: str = "COMPLIANT"
    updated_at: str = ""


def _extract_field(receipt: DecisionReceipt, field_path: str) -> object:
    """Extract a value from a receipt by dotted field path."""
    if field_path == "action":
        return receipt.action.value
    if field_path == "model_id":
        return receipt.model_id
    if field_path == "tenant_id":
        return receipt.tenant_id
    if "." in field_path:
        parts = field_path.split(".", 1)
        if parts[0] == "checks" and receipt.checks:
            for check in receipt.checks:
                if check.name == parts[1]:
                    return check.score
            # Try sub-field like checks.safety.fired
            if "." in parts[1]:
                check_name, attr = parts[1].split(".", 1)
                for check in receipt.checks:
                    if check.name == check_name:
                        return getattr(check, attr, None)
    return getattr(receipt, field_path, None)


def _evaluate_constraint(constraint: Constraint, value: object) -> bool:
    """Evaluate a single constraint against a value. Returns True if satisfied."""
    op = constraint.operator
    expected = constraint.value

    if value is None:
        return op == "==" and expected is None

    if op == "==":
        return value == expected
    if op == "!=":
        return value != expected
    if op in ("<", "<=", ">", ">="):
        try:
            v = float(value)  # type: ignore[arg-type]
            e = float(expected)  # type: ignore[arg-type]
            if op == "<":
                return v < e
            if op == "<=":
                return v <= e
            if op == ">":
                return v > e
            return v >= e
        except (TypeError, ValueError):
            return False
    if op == "in":
        return value in expected  # type: ignore[operator]
    if op == "not_in":
        return value not in expected  # type: ignore[operator]
    return False


class ContractMonitor:
    """Evaluates receipts against a BehavioralContract.

    Tracks (p, δ, k)-satisfaction incrementally.
    """

    def __init__(self, contract: BehavioralContract) -> None:
        self._contract = contract
        self._total: int = 0
        self._hard_violations: int = 0
        self._soft_violations: int = 0
        self._max_delta: float = 0.0
        self._last_violation_step: int = -1
        self._steps_since_violation: int = 0
        self._recovery_k: int = 0
        self._consecutive_clean: int = 0

    def evaluate(self, receipt: DecisionReceipt) -> SatisfactionState:
        """Evaluate a receipt against the contract.

        Returns:
            Updated :class:`SatisfactionState`.
        """
        self._total += 1
        violated = False

        # Check hard constraints
        for c in self._contract.hard_constraints:
            val = _extract_field(receipt, c.field)
            if not _evaluate_constraint(c, val):
                self._hard_violations += 1
                violated = True

        # Check soft constraints
        for c in self._contract.soft_constraints:
            val = _extract_field(receipt, c.field)
            if not _evaluate_constraint(c, val):
                # Measure deviation
                try:
                    actual = float(val)  # type: ignore[arg-type]
                    expected = float(c.value)  # type: ignore[arg-type]
                    deviation = abs(actual - expected)
                    self._max_delta = max(self._max_delta, deviation)
                    if deviation > c.delta:
                        self._soft_violations += 1
                        violated = True
                except (TypeError, ValueError):
                    self._soft_violations += 1
                    violated = True

        if violated:
            self._last_violation_step = self._total
            self._consecutive_clean = 0
            self._recovery_k = 0  # Reset recovery distance on new violation
        else:
            self._consecutive_clean += 1
            if self._last_violation_step > 0:
                self._recovery_k = self._total - self._last_violation_step

        return self.state

    @property
    def state(self) -> SatisfactionState:
        """Current (p, δ, k)-satisfaction state."""
        p = 1.0 - (self._hard_violations / max(self._total, 1))
        k = self._recovery_k
        recovered = self._consecutive_clean >= 3 or self._last_violation_step == -1

        # Reliability Index Θ = 0.5·p + 0.3·(1-δ_norm) + 0.2·recovery_score
        delta_norm = min(self._max_delta, 1.0)
        recovery_score = 1.0 if recovered else max(0.0, 1.0 - k / 100)
        theta = 0.5 * p + 0.3 * (1.0 - delta_norm) + 0.2 * recovery_score

        if self._hard_violations > 0 and not recovered:
            status = "VIOLATED"
        elif self._soft_violations > 0 or self._max_delta > 0:
            status = "DEGRADED"
        else:
            status = "COMPLIANT"

        return SatisfactionState(
            p=p,
            delta=self._max_delta,
            k=k,
            reliability_index=round(theta, 4),
            total_evaluations=self._total,
            hard_violations=self._hard_violations,
            soft_violations=self._soft_violations,
            last_violation_step=self._last_violation_step,
            recovered=recovered,
            status=status,
            updated_at=datetime.now(UTC).isoformat(),
        )

    def reset(self) -> None:
        """Reset the monitor (e.g. for a new epoch)."""
        self._total = 0
        self._hard_violations = 0
        self._soft_violations = 0
        self._max_delta = 0.0
        self._last_violation_step = -1
        self._steps_since_violation = 0
        self._recovery_k = 0
        self._consecutive_clean = 0
