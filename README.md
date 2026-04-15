# ai-audit

[![PyPI version](https://img.shields.io/pypi/v/ai-audit.svg)](https://pypi.org/project/ai-audit/)
[![Python](https://img.shields.io/pypi/pyversions/ai-audit.svg)](https://pypi.org/project/ai-audit/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/sundsoffice-tech/ai-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/sundsoffice-tech/ai-audit/actions/workflows/ci.yml)
[![EU AI Act](https://img.shields.io/badge/EU%20AI%20Act-Art.%209%2C%2012%2C%2013%2C%2017%2C%2018-blue.svg)](https://artificialintelligenceact.eu/)

> **The only standalone Python library that makes your AI pipeline EU AI Act compliant — cryptographically provable, no blockchain, no SaaS, no lock-in.**

---

## The problem

The **EU AI Act** (mandatory from August 2026) requires high-risk AI systems to keep tamper-evident logs proving every decision was made correctly. Most teams are solving this with home-grown logging — which is neither tamper-evident nor legally defensible.

Existing alternatives either require a blockchain (complex, expensive, slow) or a SaaS subscription (your audit data leaves your infrastructure).

**ai-audit** solves this with 3 lines of code.

---

## Quickstart

```bash
pip install ai-audit
```

```python
from ai_audit import (
    AuditConfig, init_audit_config,
    ReceiptCollector, ReceiptStore, ReceiptAction,
    verify_chain, get_verify_key_hex,
    PiiConfig, PiiType,
)

# One-time setup
init_audit_config(AuditConfig.from_env())

# Wrap every AI request
store = ReceiptStore()
collector = ReceiptCollector(
    trace_id="req-abc123",
    tenant_id="acme",
    pii_config=PiiConfig(enabled_types=frozenset({PiiType.EMAIL, PiiType.IP})),
)
collector.set_input("What is our GDPR policy for alice@corp.com?")
collector.add_check("safety", score=0.02, threshold=0.8, fired=False)
collector.set_output("Our GDPR policy is available at...")
collector.set_action(ReceiptAction.ALLOW)
collector.emit(store)
collector.cleanup()

# Verify tamper-evidence at any time
result = verify_chain(store.get_by_tenant("acme"), get_verify_key_hex())
assert result.valid  # Ed25519 + SHA-256 + hash-chain — all three verified
```

---

## Why ai-audit wins

| Feature | ai-audit | aegis-ledger-sdk | cortex-persist | ai-audit-sdk |
|---------|:--------:|:----------------:|:--------------:|:------------:|
| Tamper-evident receipts | ✅ | ✅ | ❌ | ✅ |
| **No blockchain required** | ✅ | ❌ | ✅ | ❌ |
| **Fully offline / air-gap** | ✅ | ❌ | ✅ | ❌ |
| **PII stripped before hash** | ✅ | ❌ | ❌ | ❌ |
| **EU AI Act Art. 9–18 report** | ✅ | partial | ❌ | ❌ |
| **SPRT confidence per article** | ✅ | ❌ | ❌ | ❌ |
| Async-native | ✅ | ❌ | ❌ | ❌ |
| KMS / Vault / AWS KMS support | ✅ | ❌ | ❌ | partial |
| Redis Lua mode (1k+ req/s) | ✅ | ❌ | ❌ | ❌ |
| Standalone Python package | ✅ | ❌ | ✅ | ❌ |
| Zero external deps for PII | ✅ | ❌ | ❌ | ❌ |

---

## How it works

Every AI pipeline decision produces a **Decision Receipt** — a cryptographically sealed, hash-chained record that proves:

- **What** the model was asked (SHA-256 of normalised input)
- **What** it answered (SHA-256 of output)
- **Which** safety/quality checks ran and what they scored
- **What** action was taken (ALLOW / REJECT / ESCALATE / ...)
- **Which** model produced the answer
- **That nobody tampered** with the log (Ed25519 signature + hash-chain linkage)

### Three-stage verification (< 0.1 ms per receipt)

```
Ed25519 signature  →  detects forgery (who signed it)
SHA-256 self-hash  →  detects corruption (content integrity)
Hash-chain link    →  detects insertions and deletions (ordering)
```

This is the same principle as a blockchain — without the blockchain overhead.

---

## Installation

```bash
pip install ai-audit

# Redis persistence (recommended for production)
pip install "ai-audit[redis]"

# Prometheus metrics
pip install "ai-audit[prometheus]"

# Everything
pip install "ai-audit[all]"
```

**Requirements:** Python 3.11+, no external services, works air-gapped.

---

## PII-Redaction — GDPR Art. 17 compliant

Personal data is stripped **before** SHA-256 hashing. The stored hash is computed over the anonymised string — so even if your audit log is subpoenaed, it never contains raw PII.

```python
from ai_audit import PiiConfig, PiiMode, PiiType

config = PiiConfig(
    enabled_types=frozenset({
        PiiType.EMAIL, PiiType.PHONE, PiiType.IP,
        PiiType.IBAN, PiiType.CREDIT_CARD,
    }),
    mode=PiiMode.REDACT,  # or HASH (deterministic SHA-256) or MASK (a***m)
)

collector = ReceiptCollector(tenant_id="acme", pii_config=config)
collector.set_input("Call +49-89-123456 or email alice@corp.com")
# Stored hash = SHA-256("Call [PHONE] or email [EMAIL]")
# Raw PII never touches the audit log
```

| Mode | Input | Stored as |
|------|-------|-----------|
| `REDACT` | `alice@corp.com` | `[EMAIL]` |
| `HASH` | `alice@corp.com` | `3d4e5f8a…` (SHA-256) |
| `MASK` | `alice@corp.com` | `a***@c***.com` |

**Supported types:** `EMAIL` `PHONE` `IP` `IBAN` `CREDIT_CARD` `CUSTOM` (your regex)

Zero external dependencies — pure Python `re` + `hashlib`. Async via `aobfuscate_text()`.

---

## EU AI Act Compliance Reports

Generate legally-defensible audit reports in three formats — **100% offline**, no internet required.

```python
from ai_audit import build_compliance_summary, verify_chain, get_verify_key_hex
from ai_audit.report import ComplianceReportGenerator

receipts = store.get_by_tenant("acme")
chain = verify_chain(receipts, get_verify_key_hex())
summary = build_compliance_summary(receipts, chain_intact=chain.valid,
                                   verify_key_hex=get_verify_key_hex())

gen = ComplianceReportGenerator(summary, verify_key_hex=get_verify_key_hex())

gen.to_markdown()  # → Git, documentation portals
gen.to_json()      # → API consumers, automated pipelines
gen.to_html()      # → Self-contained HTML, works on air-gapped servers
```

Each report gives you:

| EU AI Act Article | What it measures | How we measure it |
|-------------------|-----------------|-------------------|
| **Art. 9** — Risk Management | Safety gate firing rates | SPRT + guardrail activation |
| **Art. 12** — Record-Keeping | Tamper-evident log integrity | Cryptographic hash-chain |
| **Art. 13** — Transparency | Ongoing compliance confidence | SPRT confidence score |
| **Art. 17** — Quality Management | System quality posture | SPRT certification status |
| **Art. 18** — Automatic Logging | Real-time logging proof | ReceiptStore chain |

Every report also includes the **Ed25519 signing-key fingerprint** — proving which system generated the receipts.

---

## Continuous Compliance Certification (SPRT)

ai-audit runs a **Sequential Probability Ratio Test** on every request batch, giving you a live compliance status:

```python
from ai_audit import build_compliance_summary

summary = build_compliance_summary(receipts, chain_intact=True)
print(summary.sprt_status)           # CERTIFIED | MONITORING | FLAGGED
print(summary.compliance_confidence) # 0.0 – 1.0
print(summary.check_fire_rates)      # {"safety": 0.02, "routing": 0.0}
```

| Status | Meaning |
|--------|---------|
| `CERTIFIED` | Reject rate statistically below 5% — you're compliant |
| `MONITORING` | Insufficient data or inconclusive — watch this |
| `FLAGGED` | Reject rate exceeds 15% — investigation required |

---

## Production setup

### Persistent signing key (mandatory in production)

```bash
python -c "import nacl.signing; print(nacl.signing.SigningKey.generate().encode().hex())"
```

```python
init_audit_config(AuditConfig(
    is_production=True,
    signing_key_hex="your-64-char-hex-key",
))
```

If the private key is lost, historical chains can no longer be verified. Store it in your KMS.

### KMS integration (Vault, AWS KMS, GCP KMS)

```python
from ai_audit import KeyProvider, init_key_provider
import nacl.signing

class VaultKeyProvider(KeyProvider):
    def get_signing_key(self) -> nacl.signing.SigningKey:
        secret = vault_client.secrets.kv.read_secret("secret/ai-audit/key")
        return nacl.signing.SigningKey(bytes.fromhex(secret["data"]["key"]))

    def get_verify_key_hex(self) -> str:
        return self.get_signing_key().verify_key.encode().hex()

init_key_provider(VaultKeyProvider())
```

### Redis persistence (high-throughput)

```python
import redis
from ai_audit import ReceiptStore

r = redis.Redis(host="localhost", port=6379)

# Standard mode
store = ReceiptStore(redis_client=r, ttl=2_592_000)  # 30-day TTL

# Lua mode — single roundtrip, no connection-pool exhaustion at 1k+ req/s
store = ReceiptStore(redis_client=r, use_lua=True)
```

### Prometheus monitoring

```python
from prometheus_client import Counter
from ai_audit import verify_chain, get_verify_key_hex

CHAIN_BREAKS = Counter("audit_chain_breaks_total", "Hash-chain breaks", ["tenant_id"])

verify_chain(
    receipts,
    get_verify_key_hex(),
    on_chain_break=lambda tid: CHAIN_BREAKS.labels(tenant_id=tid).inc(),
)
```

---

## Receipt schema

Every `DecisionReceipt` is a sealed, immutable record:

```python
DecisionReceipt(
    receipt_id      = "a3f2...",      # UUID hex
    timestamp       = datetime(...),  # UTC
    trace_id        = "req-abc123",   # Correlation ID
    tenant_id       = "acme",         # Multi-tenant scope
    input_c14n      = "sha256:...",   # Hash of (anonymised) input
    output_hash     = "sha256:...",   # Hash of output
    checks          = [CheckRecord(name="safety", score=0.02, fired=False)],
    action          = ReceiptAction.ALLOW,
    model_id        = "gpt-4o",
    prev_receipt_hash = "sha256:...", # Hash-chain linkage
    receipt_hash    = "sha256:...",   # Self-hash
    signature       = "ed25519:...",  # Ed25519 signature
)
```

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AI_AUDIT_ENV` | `development` | Set to `production` to enforce signing key |
| `AI_AUDIT_SIGNING_KEY` | — | Hex-encoded Ed25519 private key |
| `AI_AUDIT_RECEIPT_TTL` | `2592000` | Redis TTL in seconds (30 days) |

---

## License

MIT — free for commercial use.

---

*Built by [S&S Connect](https://github.com/sundsoffice-tech) · Feedback & issues welcome*
