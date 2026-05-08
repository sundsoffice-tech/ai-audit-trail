# Quickstart

## Install

```bash
pip install ai-audit-trail
```

Optional integrations are extras — install only what you use:

```bash
pip install "ai-audit-trail[fastapi]"     # FastAPI / Starlette middleware
pip install "ai-audit-trail[langchain]"   # LangChain callback handler
pip install "ai-audit-trail[openai]"      # AuditedOpenAI proxy client
pip install "ai-audit-trail[anthropic]"   # AuditedAnthropic proxy client
pip install "ai-audit-trail[postgres]"    # PostgresColdBackend
pip install "ai-audit-trail[s3]"          # S3ArchiveBackend
pip install "ai-audit-trail[vault]"       # HashiCorp Vault KeyProvider
pip install "ai-audit-trail[aws-kms]"     # AWS KMS / Secrets Manager
pip install "ai-audit-trail[all]"         # everything
```

## Generate a signing key

```bash
ai-audit gen-key
```

Stores nothing — prints the hex-encoded Ed25519 seed to stdout. Capture it in
your secret store (Vault, AWS Secrets Manager, an environment variable, …)
and pass it to the library at startup.

## Hello, audit trail

```python
from ai_audit import (
    AuditConfig, init_audit_config,
    ReceiptCollector, ReceiptStore,
    verify_chain, get_verify_key_hex,
)

# Configure once at startup
init_audit_config(AuditConfig.from_env())   # reads AI_AUDIT_SIGNING_KEY
store = ReceiptStore()

# Wrap each request / decision
collector = ReceiptCollector(trace_id="req-1", tenant_id="acme")
collector.set_input("What's the weather?")
collector.add_check("safety", score=0.05, threshold=0.5)
collector.set_output("I'm a chatbot, I can't check live weather.")
collector.set_action("allow")
collector.emit(store)
collector.cleanup()

# Verify the chain (e.g. before handing data to an auditor)
result = verify_chain(store.get_by_tenant("acme"), get_verify_key_hex())
assert result.valid
```

## FastAPI middleware

```python
from fastapi import FastAPI
from ai_audit import AuditConfig, init_audit_config, ReceiptStore
from ai_audit.integrations.fastapi import AuditMiddleware

init_audit_config(AuditConfig.from_env())
store = ReceiptStore()

app = FastAPI()
app.add_middleware(
    AuditMiddleware,
    store=store,
    tenant_id="acme",
    path_prefix="/v1/ai/",   # only audit AI endpoints
)
```

Every request to `/v1/ai/*` now produces one `DecisionReceipt`, sealed,
chained, and ready for offline verification.

## Verify a bundle offline

After exporting an evidence package via `export_evidence_package(bundle.zip)`,
auditors can verify it without any access to your systems:

```bash
ai-audit verify bundle.zip
```

Returns `PASS` (chain intact, signatures valid) or `FAIL` with the index of
the first inconsistent receipt.

## Production checklist

1. Set a persistent signing key:
   ```bash
   export AI_AUDIT_SIGNING_KEY="$(ai-audit gen-key --quiet)"
   export AI_AUDIT_ENV=production
   ```
2. Pick a [storage backend](https://github.com/sundsoffice-tech/ai-audit-trail#storage-backends)
   (Redis, Postgres, S3, …) — the in-memory default is dev-only.
3. Pick a [KMS provider](https://github.com/sundsoffice-tech/ai-audit-trail#kms-providers)
   if your security model requires it.
4. Decide on a [PII redaction policy](https://github.com/sundsoffice-tech/ai-audit-trail#pii)
   before sealing — once a receipt is sealed, the input/output is hashed.
