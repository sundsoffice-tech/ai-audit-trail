# ai-audit-trail

**Prove what your AI did, why, and that nobody changed the record.**

`ai-audit-trail` is a Python library producing tamper-evident
[Decision Receipts](concepts.md) for every decision your AI system makes.

- **Ed25519** signatures over canonical JSON (RFC 8785 equivalent)
- **SHA-256 hash chain** per tenant — any retroactive edit is detected
- **ISO 42001 / NIST AI RMF / EU AI Act** [compliance crosswalks](compliance.md) built in
- **Drop-in adapters** for [FastAPI, LangChain, OpenAI, Anthropic](integrations.md)
- **KMS support** for HashiCorp Vault, AWS KMS, AWS Secrets Manager
- **Offline verification** — auditors verify a ZIP bundle without runtime access to your systems
- **Pure Python**, MIT, no native build steps, 234+ tests, mypy --strict, 0 errors

```bash
pip install ai-audit-trail
```

[Quickstart →](quickstart.md){ .md-button .md-button--primary }
[Compliance mappings →](compliance.md){ .md-button }
[GitHub →](https://github.com/sundsoffice-tech/ai-audit-trail){ .md-button }

---

## Why this exists

The **EU AI Act** becomes mandatory for high-risk AI systems in **August 2026**.
It requires tamper-evident logs proving every decision was made correctly
([Article 12](compliance.md)). Most teams are solving this
with normal application logging — which is neither tamper-evident nor legally
defensible in an audit.

`ai-audit-trail` closes this gap with **cryptographic receipts** that any
auditor can verify offline, without accessing your production systems. The same
principle as a blockchain — without the blockchain overhead, the SaaS
dependency, or the vendor lock-in.

## Who this is for

- **Regulated AI teams** (FinTech, HealthTech, LegalTech, InsurTech) who must
  prove compliance to internal or external auditors.
- **Enterprise platform teams** deploying LLM agents with tool access who need
  per-tool-call provenance.
- **Security and compliance officers** who need audit-ready evidence packages.
- **Developers** who want `pip install` and three lines of code, not a
  platform migration.

## Shared responsibility

`ai-audit-trail` provides the **technical building blocks** that *support*
ISO 42001, NIST AI RMF, and EU AI Act compliance. It does not, by itself,
guarantee regulatory compliance — compliance is an organisational obligation
that extends beyond any single software component. See the
[Shared Responsibility Model](https://github.com/sundsoffice-tech/ai-audit-trail#shared-responsibility-model)
in the repository for the boundary between what the library guarantees and
what your organisation must do.
