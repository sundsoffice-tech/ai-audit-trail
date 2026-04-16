"""
ai_audit.telemetry — OpenTelemetry instrumentation for SRE observability.

Emits metrics and traces so platform teams can set SLAs, build dashboards,
and configure alerts for audit trail health.

**Metrics emitted:**
- ``ai_audit.seal_duration_seconds`` — histogram of seal() latency
- ``ai_audit.append_total`` — counter of receipts appended
- ``ai_audit.redis_fallback_total`` — counter of Redis fallback events
- ``ai_audit.chain_break_total`` — counter of chain integrity failures
- ``ai_audit.drift_score`` — gauge of current JSD drift score
- ``ai_audit.buffer_size`` — gauge of ring-buffer occupancy
- ``ai_audit.epoch_sealed_total`` — counter of epoch seals

**Graceful degradation:** If ``opentelemetry-api`` is not installed, all
instrumentation is silently no-op. The library never requires OTel as a
hard dependency.

Usage::

    from ai_audit.telemetry import get_meter, record_seal, record_append

    record_seal(duration_seconds=0.000045)
    record_append(tenant_id="acme")

NB 005c5140 (Performance) + NB ee9616a5 (CHEF) validated — 2026-04-16.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Graceful OTel import — no-op if not installed
# ---------------------------------------------------------------------------

_meter: Any = None
_tracer: Any = None

# Metric instruments (initialised lazily)
_seal_histogram: Any = None
_append_counter: Any = None
_redis_fallback_counter: Any = None
_chain_break_counter: Any = None
_drift_gauge: Any = None
_buffer_gauge: Any = None
_epoch_counter: Any = None

_INITIALISED = False


def _ensure_initialised() -> None:
    """Lazily initialise OTel instruments on first use."""
    global _meter, _tracer, _seal_histogram, _append_counter  # noqa: PLW0603
    global _redis_fallback_counter, _chain_break_counter  # noqa: PLW0603
    global _drift_gauge, _buffer_gauge, _epoch_counter, _INITIALISED  # noqa: PLW0603

    if _INITIALISED:
        return
    _INITIALISED = True

    try:
        from opentelemetry import metrics, trace

        _meter = metrics.get_meter("ai_audit", "0.2.0")
        _tracer = trace.get_tracer("ai_audit", "0.2.0")

        _seal_histogram = _meter.create_histogram(
            name="ai_audit.seal_duration_seconds",
            description="Time to seal a receipt (hash + sign)",
            unit="s",
        )
        _append_counter = _meter.create_counter(
            name="ai_audit.append_total",
            description="Total receipts appended",
        )
        _redis_fallback_counter = _meter.create_counter(
            name="ai_audit.redis_fallback_total",
            description="Redis fallback events (chain tip recovery from Redis)",
        )
        _chain_break_counter = _meter.create_counter(
            name="ai_audit.chain_break_total",
            description="Chain integrity failures detected",
        )
        _drift_gauge = _meter.create_gauge(
            name="ai_audit.drift_score",
            description="Current Jensen-Shannon Divergence drift score",
        )
        _buffer_gauge = _meter.create_gauge(
            name="ai_audit.buffer_size",
            description="Ring-buffer current occupancy",
        )
        _epoch_counter = _meter.create_counter(
            name="ai_audit.epoch_sealed_total",
            description="Total epochs sealed",
        )
    except ImportError:
        pass  # OTel not installed — all instruments stay None (no-op)


def get_meter() -> Any:
    """Return the OTel Meter (or None if OTel is not installed)."""
    _ensure_initialised()
    return _meter


def get_tracer() -> Any:
    """Return the OTel Tracer (or None if OTel is not installed)."""
    _ensure_initialised()
    return _tracer


# ---------------------------------------------------------------------------
# Recording functions — safe to call even without OTel
# ---------------------------------------------------------------------------

def record_seal(duration_seconds: float, *, tenant_id: str = "") -> None:
    """Record a seal() operation duration."""
    _ensure_initialised()
    if _seal_histogram is not None:
        _seal_histogram.record(duration_seconds, {"tenant_id": tenant_id})


def record_append(*, tenant_id: str = "", async_mode: bool = False) -> None:
    """Record a receipt append."""
    _ensure_initialised()
    if _append_counter is not None:
        _append_counter.add(1, {"tenant_id": tenant_id, "async": str(async_mode)})


def record_redis_fallback(*, tenant_id: str = "") -> None:
    """Record a Redis fallback event (chain tip recovered from Redis)."""
    _ensure_initialised()
    if _redis_fallback_counter is not None:
        _redis_fallback_counter.add(1, {"tenant_id": tenant_id})


def record_chain_break(*, tenant_id: str = "") -> None:
    """Record a chain integrity failure."""
    _ensure_initialised()
    if _chain_break_counter is not None:
        _chain_break_counter.add(1, {"tenant_id": tenant_id})


def record_drift(score: float, *, tenant_id: str = "") -> None:
    """Record the current drift score."""
    _ensure_initialised()
    if _drift_gauge is not None:
        _drift_gauge.set(score, {"tenant_id": tenant_id})


def record_buffer_size(size: int) -> None:
    """Record ring-buffer occupancy."""
    _ensure_initialised()
    if _buffer_gauge is not None:
        _buffer_gauge.set(size)


def record_epoch_sealed(*, tenant_id: str = "") -> None:
    """Record an epoch seal event."""
    _ensure_initialised()
    if _epoch_counter is not None:
        _epoch_counter.add(1, {"tenant_id": tenant_id})
