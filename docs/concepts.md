# Concepts

## Decision Receipt

A `DecisionReceipt` captures **one** security-relevant decision your AI system
made. The receipt is the unit of audit evidence.

Each receipt contains:

| Field | Purpose |
| --- | --- |
| `receipt_id` | Stable ID for cross-referencing across systems |
| `timestamp` | UTC ISO 8601, set at construction |
| `trace_id` / `session_id` | Correlate to your application's request IDs |
| `tenant_id` | Multi-tenant scope identifier (no semantics imposed) |
| `input_c14n` | SHA-256 of the canonicalised input (NFKC + lowercase) |
| `output_hash` | SHA-256 of the model's output |
| `state_digest` | Hash of security-relevant context |
| `checks` | Ordered list of `CheckRecord`s (safety, supervisor, routing, …) |
| `action` | `allow` / `reject` / `fail_retry` / `cache_hit` / `escalate` / `bypass` |
| `model_id` / `config_digest` | Model provenance |
| `prev_receipt_hash` | Chain linkage — points at the previous receipt in the same tenant |
| `receipt_hash` | SHA-256 self-hash over canonical JSON (excluding `receipt_hash` and `signature`) |
| `signature` | Ed25519 signature over the same canonical bytes |

## Hash chain

Every emitted receipt for a tenant carries `prev_receipt_hash` pointing at the
previous receipt's `receipt_hash`. The chain is **append-only**:

- Inserting a receipt **between** two existing ones changes downstream
  `prev_receipt_hash` values, which changes downstream `receipt_hash` values,
  which invalidates the Ed25519 signatures.
- Editing the content of an old receipt changes its `receipt_hash`, which
  invalidates the signature directly *and* breaks every chain link after it.
- Deleting an old receipt leaves a dangling `prev_receipt_hash` reference in
  the next receipt — `verify_chain` reports the gap.

Verification is O(N) by Ed25519 signature checks plus O(N) hash equalities.

## Merkle batch sealing

For high-throughput pipelines (10k+ receipts per second) per-receipt chaining
becomes a write hotspot. `MerkleBatcher` accumulates receipts and emits one
RFC-6962-style `BatchSeal` per batch — only the batch *roots* are chained.
Verification cost drops to O(log N) per batch via inclusion proofs.

## Ed25519 signatures

Each `seal()` computes a deterministic JSON canonicalisation of the receipt
(`orjson.OPT_SORT_KEYS`, RFC 8785-equivalent) and signs the resulting bytes
with libsodium's Ed25519 (via PyNaCl). The same canonical bytes are also
SHA-256-hashed for `receipt_hash`, so the signature and the chain linkage both
witness the exact same payload.

The signing key is loaded via the active `KeyProvider`. The default loads the
seed from `AuditConfig(signing_key_hex=...)`; production deployments inject
[`VaultKeyProvider`, `AWSKMSKeyProvider`, or `AWSSecretsManagerKeyProvider`](
https://github.com/sundsoffice-tech/ai-audit-trail#kms-providers).

## TOCTOU safety

`ReceiptCollector.emit()` calls `ReceiptStore.atomic_seal_and_append()` which
acquires a per-tenant `threading.Lock` for the *seal + chain-tip update*
critical section. Concurrent emits for the same tenant cannot interleave to
produce a forked chain.

## Evidence package

`export_evidence_package(receipts, "bundle.zip")` produces a self-contained ZIP
with:

- `receipts.jsonl` — one JSON object per receipt
- `chain_metadata.json` — first/last hashes, count, public key
- `public_key.hex` — the Ed25519 verify key
- `verify.py` — a standalone, dependency-light verifier script
- `manifest.json` — Ed25519-signed file manifest with SHA-256 of every other file

The auditor verifies offline:

```bash
ai-audit verify bundle.zip
```

No access to your production systems is required.
