# ai-audit

**Tamper-evident AI pipeline audit trail — EU AI Act Art. 12 compliant.**

Every AI pipeline decision gets a cryptographically signed, hash-chained receipt.
Drop-in for any Python AI application. No framework lock-in.

```python
from ai_audit import AuditConfig, init_audit_config, ReceiptCollector, ReceiptStore, verify_chain, get_verify_key_hex

# Configure once at startup
init_audit_config(AuditConfig.from_env())

# Wrap each request
store = ReceiptStore()
collector = ReceiptCollector(trace_id="req-1", tenant_id="acme")
collector.set_input("What is the capital of France?")
collector.add_check("safety", score=0.02, threshold=0.8, fired=False)
collector.set_output("The capital of France is Paris.")
collector.set_action("allow")
receipt_id = collector.emit(store)
collector.cleanup()

# Verify the chain (compliance audit)
result = verify_chain(store.get_by_tenant("acme"), get_verify_key_hex())
assert result.valid  # Ed25519 + SHA-256 + hash-chain all verified
```

## What it does

Each `DecisionReceipt` captures:
- **Input hash** — SHA-256 of NFKC-normalised input (semantic deduplication)
- **Output hash** — SHA-256 of generated response (bit-exact)
- **Check records** — scored gates (safety, routing, quality, etc.)
- **Terminal action** — `ALLOW / REJECT / ESCALATE / CACHE_HIT / FAIL_RETRY`
- **Model provenance** — which model was used
- **Ed25519 signature** — non-repudiation via libsodium (< 0.1ms)
- **SHA-256 hash-chain** — append-only, tamper-evident (like a blockchain)

Three-stage verification:
1. Ed25519 signature — detects forgery
2. SHA-256 self-hash — detects corruption
3. Hash-chain linkage — detects insertions/deletions

## Why

The **EU AI Act Art. 12** requires high-risk AI systems to maintain automatic
logs that demonstrate correct operation — and those logs must be tamper-evident.

`ai-audit` provides exactly that. There is no comparable standalone Python
package on PyPI.

## Installation

```bash
pip install ai-audit

# With Redis persistence
pip install "ai-audit[redis]"

# With Prometheus metrics
pip install "ai-audit[prometheus]"
```

## Configuration

```python
from ai_audit import AuditConfig, init_audit_config

# Option 1: Explicit
init_audit_config(AuditConfig(
    is_production=True,
    signing_key_hex="your-32-byte-hex-key",  # see below
))

# Option 2: From environment variables
# AI_AUDIT_ENV=production
# AI_AUDIT_SIGNING_KEY=<hex>
init_audit_config(AuditConfig.from_env())
```

Generate a persistent signing key:
```bash
python -c "import nacl.signing; print(nacl.signing.SigningKey.generate().encode().hex())"
```

## Redis persistence (optional)

```python
import redis
from ai_audit import ReceiptStore

r = redis.Redis(host="localhost", port=6379)
store = ReceiptStore(redis_client=r, ttl=2_592_000)  # 30-day TTL
```

## Prometheus monitoring (optional)

```python
from ai_audit import verify_chain, get_verify_key_hex
from prometheus_client import Counter

CHAIN_BREAKS = Counter("audit_chain_breaks_total", "Hash-chain breaks", ["tenant_id"])

result = verify_chain(
    receipts,
    get_verify_key_hex(),
    on_chain_break=lambda tenant_id: CHAIN_BREAKS.labels(tenant_id=tenant_id).inc(),
)
```

## Compliance summary (SPRT)

```python
from ai_audit import build_compliance_summary, verify_chain, get_verify_key_hex

receipts = store.get_by_tenant("acme", limit=1000)
chain_result = verify_chain(receipts, get_verify_key_hex())
summary = build_compliance_summary(receipts, chain_intact=chain_result.valid)

print(summary.sprt_status)           # CERTIFIED | MONITORING | FLAGGED
print(summary.compliance_confidence) # 0.0 - 1.0
print(summary.check_fire_rates)      # {"safety": 0.02, "routing": 0.0, ...}
```

SPRT (Sequential Probability Ratio Test) continuously monitors reject rates
with statistical confidence, flagging when reject rate exceeds 15%.

## Receipt schema

```python
@dataclass
class DecisionReceipt:
    receipt_id: str          # UUID hex
    timestamp: datetime      # UTC
    trace_id: str            # Request correlation ID
    session_id: str          # Chat session ID
    tenant_id: str           # Multi-tenant scope
    input_c14n: str          # SHA-256 of normalised input
    state_digest: str        # SHA-256 of context state
    output_hash: str         # SHA-256 of output
    checks: list[CheckRecord]
    action: ReceiptAction    # ALLOW | REJECT | ESCALATE | ...
    reason_codes: list[str]
    nist_tags: list[str]     # e.g. "AU-3", "AC-6"
    model_id: str
    prev_receipt_hash: str   # Hash-chain linkage
    receipt_hash: str        # SHA-256 self-hash
    signature: str           # Ed25519 signature (hex)
```

## License

MIT
