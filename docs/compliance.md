# Compliance crosswalks

`ai-audit-trail` ships with formal mappings between Decision Receipt fields
and three regulatory frameworks. The mappings are deterministic — given a
list of receipts, the library returns coverage statistics per control.

```python
from ai_audit import build_crosswalk, nist_function_map, build_compliance_summary

receipts = store.get_by_tenant("acme")

# Per-control coverage
crosswalk = build_crosswalk(receipts)
for c in crosswalk:
    print(f"{c.framework} {c.control_id}: {c.status}  ({c.coverage:.0%})")

# NIST AI RMF function-level rollup
nist = nist_function_map(receipts)
print(nist)  # {"GOVERN": "PASS", "MAP": "PASS", "MEASURE": "PASS", "MANAGE": "PASS"}

# SPRT-certified summary with reject_rate, allow_rate, action_distribution
summary = build_compliance_summary(receipts)
print(f"Reject rate: {summary.reject_rate:.1%}  Status: {summary.sprt_status}")
```

## ISO/IEC 42001

| Control | What it covers | Receipt fields used |
| --- | --- | --- |
| **A.6.2.8** | Logging of AI system activities | timestamp, trace_id, action, checks |
| **A.7.5** | Data provenance | input_c14n, state_digest, model_id |
| **A.6.2.6** | AI system performance evaluation | checks (scores, thresholds, fired) |
| **A.8.4** | AI system output controls | output_hash, action, reason_codes |
| **A.5.3** | AI risk assessment | reason_codes, NIST tags, escalation actions |

## NIST AI RMF (1.0)

| Function | Receipt fields used |
| --- | --- |
| **GOVERN** | config_digest, NIST tags, signing-key provenance |
| **MAP** | model_id, checks (context identification) |
| **MEASURE** | scores, SPRT certification, drift detection |
| **MANAGE** | action, reason_codes, escalation chain |

`nist_function_map()` returns a dict of function → status (`PASS` / `MONITORING` / `FLAGGED`)
with per-function coverage percentage.

## EU AI Act

The library covers articles primarily concerned with operational record-keeping:

### EU AI Act Art. 9 — Risk management system

Receipts surface ongoing risk evidence: the `checks` list includes the safety,
fairness, and supervisor evaluations applied at decision time. Aggregating
over a tenant with `build_compliance_summary` produces the running reject
rate that Art. 9 expects to be monitored continuously.

### EU AI Act Art. 12 — Automatic recording of events

Article 12 requires automatic, traceable, *tamper-evident* event logs. This
is the article most other logging tools fail. Each `DecisionReceipt` is:

- automatic (emitted from middleware / collector, not manual)
- traceable (signed `trace_id` and `session_id`)
- tamper-evident (Ed25519 signature + SHA-256 hash chain)

### EU AI Act Art. 13 — Transparency / instructions for use

`config_digest` and `model_id` provide cryptographic anchors for the model
configuration in effect at decision time, so transparency disclosures can be
matched to specific receipts.

### EU AI Act Art. 17 — Quality management system

The `ComplianceReportGenerator` produces per-period reports binding receipts
to ISO 42001 / NIST AI RMF controls — the QMS evidence trail.

### EU AI Act Art. 18 — Documentation retention

Evidence-package export plus the 30-day default Redis TTL plus the optional
`PostgresColdBackend` / `S3ArchiveBackend` cover the 10-year retention horizon
that Art. 18 mandates for high-risk systems.

## What this is *not*

A library cannot deliver compliance on its own. `ai-audit-trail` provides the
**technical record-keeping primitives** (Art. 12 / A.6.2.8 / GOVERN) plus
*supporting* evidence for several adjacent controls. It does not:

- replace your AI risk assessment process (Art. 9 — organisational)
- replace your data-governance and conformity-assessment work (Art. 10 / 43)
- replace human oversight (Art. 14 — operational)
- substitute legal advice or constitute a notified body opinion

See the
[Shared Responsibility Model](https://github.com/sundsoffice-tech/ai-audit-trail#shared-responsibility-model)
for the boundary between what the library guarantees and what your organisation
must do.
