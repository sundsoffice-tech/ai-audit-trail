# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in `ai-audit-trail`, please report it responsibly:

- **Email:** sunds.connect@gmail.com (subject: `[SECURITY] ai-audit-trail`)
- **GitHub:** Open a [security advisory](https://github.com/sundsoffice-tech/ai-audit-trail/security/advisories/new)

We aim to acknowledge reports within 48 hours and provide a fix within 7 days for critical issues.

---

## Threat Model

`ai-audit-trail` provides cryptographic building blocks for tamper-evident AI decision logging. The following threat analysis covers the library's scope.

### 1. Tampering (Integrity)

| Threat | Mitigation | Residual Risk |
|--------|-----------|---------------|
| Modify receipt content after creation | SHA-256 self-hash (`receipt_hash`) detects any payload change | None if hash is verified |
| Forge a receipt signature | Ed25519 signatures (libsodium/PyNaCl) — 128-bit security level | Key compromise (see below) |
| Insert/delete receipts in chain | Hash-chain linkage (`prev_receipt_hash`) detects insertions, deletions, and reordering | Tail truncation requires external anchor |
| Reorder receipts | `verify_chain()` sorts by timestamp and validates chain linkage | Clock manipulation on source system |

### 2. Confidentiality (PII)

| Threat | Mitigation | Residual Risk |
|--------|-----------|---------------|
| PII stored in audit chain | `PiiConfig` with REDACT/HASH/MASK modes applied before hashing | Deployer must configure PII types correctly |
| Custom regex fails silently | Invalid patterns logged via `logger.warning` (v0.1.1+) | Deployer must monitor logs |

### 3. Availability

| Threat | Mitigation | Residual Risk |
|--------|-----------|---------------|
| Redis unavailable | `fail_on_redis_error=True` (default) aborts the audited operation — no silent data loss | Deployer must handle the exception |
| In-memory store overflow | LRU eviction after `max_size` (default: 50,000) | Evicted receipts lost if not persisted to Redis |

### 4. Key Compromise

| Threat | Mitigation | Residual Risk |
|--------|-----------|---------------|
| Signing key exposed | `KeyProvider` ABC allows HSM/Vault integration | Deployer must implement secure key storage |
| No key rotation | Library supports custom `KeyProvider` — rotation logic is deployer responsibility | Receipts signed with old key remain verifiable with old public key |

**Key Rotation Process (Deployer Responsibility):**

1. Generate a new Ed25519 keypair
2. Update the `KeyProvider` to return the new signing key
3. Store the old public key for verification of historical receipts
4. New receipts are signed with the new key; old receipts remain valid
5. In case of compromise: revoke the old key, re-audit affected receipts

### 5. Repudiation

| Threat | Mitigation | Residual Risk |
|--------|-----------|---------------|
| Deny an AI decision was made | Ed25519 signature binds decision to signing key holder | Key must be attributable to operator |
| Claim receipt was created at different time | Timestamp in signed payload; hash-chain ordering | Deployer should use NTP-synced clocks |

---

## Compliance Scope

### What `ai-audit-trail` provides

- Cryptographically signed, hash-chained Decision Receipts (Ed25519 + SHA-256)
- PII redaction before hashing (GDPR Art. 17 compatibility)
- EU AI Act Art. 12 logging building blocks (traceability, integrity, auditability)
- Continuous certification via SPRT statistical testing
- Compliance report generation (Art. 9, 12, 13, 17, 18)

### What the deployer must provide

- **Secure key management** — HSM, Vault, or equivalent (not ephemeral keys in production)
- **PII configuration** — correct `PiiConfig` for the data being processed
- **Durable storage** — Redis with AOF or equivalent persistent backend
- **Access controls** — who can read/write audit data
- **Organizational oversight** — EU AI Act Art. 14 human oversight requirements
- **Monitoring** — alerting on `verify_chain()` failures and Redis errors
- **Clock synchronization** — NTP on all systems producing receipts
- **Incident response** — key rotation, breach notification per GDPR Art. 33/34

> **This library provides technical building blocks that support EU AI Act compliance.
> It does not, by itself, ensure or guarantee regulatory compliance.
> Compliance is an organizational obligation that extends beyond any single software component.**

---

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Dependencies

- **PyNaCl >= 1.5** — Ed25519 signatures via libsodium (C implementation)
- **Pydantic >= 2.0** — receipt schema validation
- **orjson >= 3.9** — deterministic JSON canonicalization
- **redis >= 5.0** (optional) — persistent storage backend
