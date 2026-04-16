# ai-audit-trail

[![PyPI version](https://img.shields.io/pypi/v/ai-audit-trail.svg)](https://pypi.org/project/ai-audit-trail/)
[![Python](https://img.shields.io/pypi/pyversions/ai-audit-trail.svg)](https://pypi.org/project/ai-audit-trail/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/sundsoffice-tech/ai-audit-trail/actions/workflows/ci.yml/badge.svg)](https://github.com/sundsoffice-tech/ai-audit-trail/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-196%20passed-brightgreen)](https://github.com/sundsoffice-tech/ai-audit-trail)
[![mypy](https://img.shields.io/badge/mypy-strict-blue)](https://github.com/sundsoffice-tech/ai-audit-trail)

> **Cryptographically verifiable evidence of conformity for AI systems.**
> Tamper-evident Decision Receipts with Ed25519 signatures, SHA-256 hash-chains,
> and formal compliance mappings — no blockchain, no SaaS, no lock-in.

---

## What this library provides

`ai-audit-trail` provides the **technical building blocks** that support EU AI Act, ISO 42001, and NIST AI RMF compliance. It does not, by itself, guarantee regulatory compliance — compliance is an organizational obligation that extends beyond any single software component. See our [Shared Responsibility Model](#shared-responsibility-model) below.

---

## Installation

```bash
pip install ai-audit-trail                    # Core (Ed25519 + SHA-256 + PII)
pip install "ai-audit-trail[redis]"           # + Redis persistence
pip install "ai-audit-trail[otel]"            # + OpenTelemetry metrics
pip install "ai-audit-trail[all]"             # Everything
```

**Requirements:** Python 3.11+ | No external services required | Works air-gapped

---

## Quickstart

```python
from ai_audit import (
    AuditConfig, init_audit_config,
    ReceiptCollector, ReceiptStore, ReceiptAction,
    verify_chain, get_verify_key_hex,
)

# 1. Configure once at startup
init_audit_config(AuditConfig(is_production=False))
store = ReceiptStore()

# 2. Wrap every AI request
collector = ReceiptCollector(trace_id="req-1", tenant_id="acme")
collector.set_input("What is our GDPR policy?")
collector.add_check("safety", score=0.02, threshold=0.8, fired=False)
collector.set_output("Our GDPR policy states that...")
collector.set_action(ReceiptAction.ALLOW)
collector.emit(store)
collector.cleanup()

# 3. Verify tamper-evidence
result = verify_chain(store.get_by_tenant("acme"), get_verify_key_hex())
assert result.valid  # Ed25519 + SHA-256 + hash-chain verified
```

---

## Architecture Overview

```
Receipt Creation        Verification & Compliance       Agentic AI Audit
─────────────────       ──────────────────────────      ──────────────────
ReceiptCollector   ──>  verify_chain()                  ToolCallReceipt
  set_input()           build_compliance_summary()      TraceGraph (DAG)
  add_check()           build_crosswalk()               BehavioralContract
  set_output()          export_evidence_package()       ProvenanceChain
  set_action()          SPRTMonitor
  emit()                DriftMonitor
       │                EpochManager
       v
  ReceiptStore     ──>  StorageBackend ABC
  (in-memory LRU)       InMemoryBackend
  + Redis (optional)    (your custom backends)
  + AuditBuffer
```

---

## Core Features

### Decision Receipts (Ed25519 + SHA-256 + Hash-Chain)

Every AI pipeline decision produces a **Decision Receipt** — a cryptographically sealed, hash-chained record:

| What's proven | How |
|---|---|
| Input integrity | SHA-256 of NFKC-normalized, PII-stripped input |
| Output integrity | SHA-256 of generated output |
| Check results | Ordered check records with scores and thresholds |
| Decision | Action taken (ALLOW / REJECT / ESCALATE / ...) |
| Model provenance | Model ID + config digest |
| Non-repudiation | Ed25519 signature (libsodium) |
| Ordering | Hash-chain linkage (prev_receipt_hash) |

**Three-stage verification (< 0.1 ms per receipt):**

```
Ed25519 signature  →  detects forgery
SHA-256 self-hash  →  detects corruption
Hash-chain link    →  detects insertions / deletions / reordering
```

### PII Redaction (GDPR Art. 17)

Personal data is stripped **before** hashing — the audit log never contains raw PII.

```python
from ai_audit import PiiConfig, PiiMode, PiiType

config = PiiConfig(
    enabled_types=frozenset({PiiType.EMAIL, PiiType.PHONE, PiiType.IP}),
    mode=PiiMode.REDACT,  # or HASH (SHA-256) or MASK (a***m)
)
collector = ReceiptCollector(tenant_id="acme", pii_config=config)
```

| Mode | `alice@corp.com` becomes |
|------|--------------------------|
| `REDACT` | `[EMAIL]` |
| `HASH` | `3d4e5f8a...` (deterministic SHA-256) |
| `MASK` | `a***@c***.com` |

### Crypto-Shredding (GDPR Right to Erasure)

Encrypt PII fields with per-tenant AES-256-GCM keys. Destroy the key = data permanently unreadable, hash-chain intact.

```python
from ai_audit.shredding import AESGCMDEKStore, encrypt_field, shred_tenant

dek_store = AESGCMDEKStore()
dek_store.create_dek("tenant-acme")

field = encrypt_field("sensitive PII", dek_store, "tenant-acme")
shred_tenant("tenant-acme", dek_store)  # Key destroyed — data unrecoverable
# Hash-chain remains mathematically intact (hashes ciphertext, not plaintext)
```

---

## Compliance & Governance

### ISO 42001 / NIST AI RMF Crosswalk

Maps receipt data directly to recognized management controls with evidence pointers.

```python
from ai_audit.crosswalk import build_crosswalk, nist_function_map

crosswalk = build_crosswalk(receipts, chain_intact=True)
for entry in crosswalk:
    print(f"[{entry.status}] {entry.framework} {entry.control_id} — {entry.control_name}")

nist = nist_function_map(receipts)
print(nist["GOVERN"].coverage)   # 0.0–1.0
print(nist["MEASURE"].status)    # PASS / PARTIAL / FAIL
```

**ISO 42001 Controls:** A.6.2.8 (Logging), A.7.5 (Provenance), A.6.2.6 (Performance), A.8.4 (Output), A.5.3 (Risk)
**NIST AI RMF:** GOVERN, MAP, MEASURE, MANAGE — with quantitative coverage scores

### EU AI Act Compliance Reports

```python
from ai_audit.report import ComplianceReportGenerator

gen = ComplianceReportGenerator(summary, verify_key_hex=get_verify_key_hex())
gen.to_markdown()   # Documentation portals
gen.to_json()       # Automated pipelines
gen.to_html()       # Air-gapped servers
```

Covers Art. 9 (Risk), Art. 12 (Record-Keeping), Art. 13 (Transparency), Art. 17 (Quality), Art. 18 (Logging).

### Evidence Package Export (Offline Verification)

Self-contained signed ZIP for external auditors — no system access required.

```python
from ai_audit.export import export_evidence_package, verify_evidence_package

export_evidence_package(receipts, verify_key_hex, signing_key, "audit_2026.zip")
# Bundle: receipts.jsonl + chain_metadata.json + public_key.hex + manifest.json (signed) + verify.py

# Auditor verifies offline:
# python -m ai_audit verify audit_2026.zip
```

### Continuous Certification (SPRT)

Sequential Probability Ratio Test — live compliance status per tenant.

```python
from ai_audit.sprt import SPRTMonitor

monitor = SPRTMonitor(tenant_id="acme")
for receipt in receipts:
    state = monitor.update(is_reject=(receipt.action == "reject"))
print(state.status)      # CERTIFIED | MONITORING | FLAGGED
print(state.confidence)  # 0.0–1.0
```

### Drift Detection (Jensen-Shannon Divergence)

Detects behavioral shifts in real-time — pure Python, no scipy required.

```python
from ai_audit.drift import DriftMonitor

monitor = DriftMonitor(window_size=100)
for receipt in receipts:
    state = monitor.update(receipt.action.value)
print(state.status)       # STABLE | DRIFTING | CRITICAL_DRIFT
print(state.drift_score)  # JSD 0.0–1.0
```

---

## Agentic AI Audit (World-First)

### Agent Behavioral Contracts

Formal (p, delta, k)-Satisfaction with Reliability Index Theta — transforms EU AI Act requirements into testable specifications.

```python
from ai_audit.contracts import BehavioralContract, Constraint, ContractMonitor

contract = BehavioralContract(
    contract_id="safety-v1",
    constraints=[
        Constraint(name="no_pii_leak", kind="hard", field="action", operator="!=", value="reject"),
        Constraint(name="quality", kind="soft", field="checks.safety.score", operator="<=", value=0.1, delta=0.5),
    ],
)
monitor = ContractMonitor(contract)
for receipt in receipts:
    state = monitor.evaluate(receipt)

print(state.p)                   # Hard constraint satisfaction probability
print(state.delta)               # Maximum soft deviation observed
print(state.k)                   # Recovery steps after last violation
print(state.reliability_index)   # Theta: single compliance metric (0.0–1.0)
print(state.status)              # COMPLIANT | DEGRADED | VIOLATED
```

### Cryptographic Tool-Call Receipts

Every agent API call Ed25519-signed — no existing framework provides this.

```python
from ai_audit.toolcall import seal_tool_call, verify_tool_call_chain

receipt = seal_tool_call(
    agent_id="researcher",
    tool_name="web_search",
    tool_args={"query": "EU AI Act compliance"},
    tool_result="Found 5 relevant documents...",
    private_key=signing_key,
    tenant_id="acme",
)
assert receipt.verify(signing_key.verify_key)
```

### Multi-Agent Trace-Graphs (DAG)

Audit delegation, handoff, and parallel orchestration — not just linear logs.

```python
from ai_audit.tracegraph import TraceGraph

graph = TraceGraph(trace_id="workflow-1", tenant_id="acme")
root = graph.add_node(agent_id="orchestrator", action="plan")
graph.add_node(agent_id="researcher", action="search", parent_id=root.node_id)
graph.add_node(agent_id="writer", action="draft", parent_id=root.node_id)

assert graph.verify_integrity()  # Hash-based tamper detection
assert not graph.has_cycles()    # DAG validation
lineage = graph.get_agent_lineage(leaf_node.node_id)  # Root-to-leaf trace
```

### Epistemische Integritat / Unforgeable Provenance

Track WHERE every piece of information came from — proves a decision was not influenced by prompt injection.

```python
from ai_audit.provenance import ProvenanceChain, ProvenanceRecord, SourceType

chain = ProvenanceChain(receipt_id="r1", tenant_id="acme")
chain.add(ProvenanceRecord(source_type=SourceType.SYSTEM, source_id="prompt", trust_level=1.0, content_hash="..."))
chain.add(ProvenanceRecord(source_type=SourceType.DOCUMENT, source_id="doc-123", trust_level=0.8, content_hash="..."))
chain.add(ProvenanceRecord(source_type=SourceType.UNKNOWN, source_id="???", trust_level=0.0, content_hash="..."))

summary = chain.trust_summary()
print(summary.system_grounded)       # True — has SYSTEM source
print(summary.potentially_injected)  # True — has UNKNOWN source
print(summary.min_trust)             # 0.0 — weakest link
```

---

## High-Throughput Architecture

### Merkle-Tree Batch Sealing (RFC 6962)

Chain-of-Roots instead of chain-of-receipts — O(log N) verification per batch.

```python
from ai_audit.batch import MerkleBatcher

batcher = MerkleBatcher(tenant_id="acme", private_key=key, max_batch_size=2048)
for receipt in receipts:
    seal = batcher.add(receipt.receipt_id, receipt.seal_payload())
    if seal:  # Auto-flushed at 2048 receipts
        print(f"Batch sealed: {seal.merkle_root[:16]}...")

assert batcher.verify_chain_of_roots(key.verify_key)
```

### Chain Epochs / Rollover

Prevent unbounded chain growth. Old epochs can be archived or deleted.

```python
from ai_audit.epochs import EpochManager

mgr = EpochManager(tenant_id="acme", private_key=key, max_epoch_size=10_000)
for receipt in receipts:
    seal = mgr.add_receipt(receipt)  # Auto-seals at 10k
mgr.seal_epoch()                     # Or explicit rollover
assert mgr.verify_epoch_chain(key.verify_key)
```

### Ring-Buffer with Backpressure

Bounded buffer for high-throughput ingestion — fail-closed, no silent data loss.

```python
from ai_audit.buffer import AuditBuffer, AuditBufferFullError

buffer = AuditBuffer(maxsize=50_000)  # ~5 seconds at 10k req/s
try:
    buffer.put(receipt)
except AuditBufferFullError:
    # Backpressure — reject the request rather than lose audit data
    pass
batch = buffer.drain(max_items=2048)
```

### Storage Backend ABCs

Pluggable persistence — bring your own database.

```python
from ai_audit.storage import StorageBackend, InMemoryBackend

# Use the reference implementation for dev/test
backend = InMemoryBackend(max_receipts=50_000)

# Or implement your own:
class PostgresBackend(StorageBackend):
    def write_receipt(self, receipt): ...
    def read_receipt(self, receipt_id): ...
    def query_by_tenant(self, tenant_id, limit=100): ...
    def healthcheck(self) -> bool: ...
```

### OpenTelemetry Instrumentation

Native metrics for SRE dashboards — graceful no-op without OTel SDK.

```python
# pip install "ai-audit-trail[otel]"
from ai_audit.telemetry import record_seal, record_append, record_drift

record_seal(duration_seconds=0.000045, tenant_id="acme")
record_append(tenant_id="acme", async_mode=True)
record_drift(score=0.03, tenant_id="acme")
```

**Metrics:** `ai_audit.seal_duration_seconds`, `ai_audit.append_total`, `ai_audit.redis_fallback_total`, `ai_audit.chain_break_total`, `ai_audit.drift_score`, `ai_audit.buffer_size`, `ai_audit.epoch_sealed_total`

---

## Production Setup

### Persistent Signing Key

```bash
python -c "import nacl.signing; print(nacl.signing.SigningKey.generate().encode().hex())"
```

```python
init_audit_config(AuditConfig(is_production=True, signing_key_hex="your-64-char-hex-key"))
```

### KMS Integration

```python
from ai_audit import KeyProvider, init_key_provider

class VaultKeyProvider(KeyProvider):
    def get_signing_key(self) -> nacl.signing.SigningKey:
        secret = vault_client.secrets.kv.read_secret("secret/ai-audit/key")
        return nacl.signing.SigningKey(bytes.fromhex(secret["data"]["key"]))
    def get_verify_key_hex(self) -> str:
        return self.get_signing_key().verify_key.encode().hex()

init_key_provider(VaultKeyProvider())
```

### Redis Persistence

```python
import redis
store = ReceiptStore(redis_client=redis.Redis(), use_lua=True)  # Lua mode: 10k+ req/s
```

---

## Shared Responsibility Model

| Responsibility | Library | Deployer |
|---|:---:|:---:|
| Ed25519 + SHA-256 signing and hashing | X | |
| Hash-chain integrity | X | |
| PII redaction (REDACT/HASH/MASK) | X | |
| Merkle-Tree batch sealing (RFC 6962) | X | |
| SPRT compliance certification | X | |
| ISO 42001 / NIST AI RMF mapping | X | |
| Evidence Package export + verification | X | |
| Crypto-Shredding (AES-256-GCM) | X | |
| Agent Behavioral Contracts | X | |
| OpenTelemetry metrics | X | |
| **Secure key storage (HSM/Vault)** | | X |
| **PII type configuration** | | X |
| **Durable storage backend** | | X |
| **Access controls / RBAC** | | X |
| **Human oversight (EU AI Act Art. 14)** | | X |
| **Clock synchronization (NTP)** | | X |
| **Incident response** | | X |
| **Regulatory compliance certification** | | X |

---

## Examples

See the [`examples/`](examples/) directory:

- **[end_to_end_audit.py](examples/end_to_end_audit.py)** — Full lifecycle: receipts, verification, crosswalk, evidence export
- **[fastapi_middleware.py](examples/fastapi_middleware.py)** — FastAPI audit middleware pattern
- **[langchain_callback.py](examples/langchain_callback.py)** — LangChain callback handler

---

## Performance

| Operation | Typical Latency | Notes |
|---|---|---|
| `seal()` (hash + sign) | < 100 us | Ed25519 via libsodium C |
| `verify_chain(1000)` | < 50 ms | Scales linearly |
| `merkle_root(2048)` | < 5 ms | RFC 6962 SHA-256 |
| Memory per receipt | ~1 KB | Pydantic V2 + orjson |

Run benchmarks: `pytest tests/test_benchmark.py -v -s`

---

## Project Stats

| Metric | Value |
|---|---|
| Tests | 196 |
| Source modules | 26 |
| `__all__` exports | 60 |
| Type checking | mypy --strict, 0 errors |
| Linting | ruff, 0 errors |
| Python versions | 3.11, 3.12, 3.13 |
| Security scans | 3 completed, 6 fixes applied |
| NB validators consulted | 5 (Architecture, Enterprise, Performance, Agentic, Branding) |

---

## Security

See [SECURITY.md](SECURITY.md) for the full threat model, vulnerability reporting process, and supported versions.

See [CONTRIBUTING.md](CONTRIBUTING.md) for architecture invariants, the shared responsibility model, and contribution guidelines.

---

## License

MIT — free for commercial use.

---

*Built by [S&S Connect](https://github.com/sundsoffice-tech)*
