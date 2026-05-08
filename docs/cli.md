# Command-line interface

After install, the CLI is callable directly as `ai-audit`. The
`python -m ai_audit ...` form remains supported as an equivalent.

## `ai-audit gen-key`

Generate a fresh Ed25519 signing key (32-byte hex seed) plus the matching
public verify key. Stores nothing — you decide where to persist it.

```console
$ ai-audit gen-key
# Ed25519 signing key (KEEP SECRET)
AI_AUDIT_SIGNING_KEY=d58251819896733b749755e52a6ca32d3161c028ce71ae0faa941aabbcf1b70d

# Public verification key (safe to share / commit)
AI_AUDIT_VERIFY_KEY=445e2ee195915c1aa07e8516e9e6b62f6699ff873dcc9c29f82033a0db8a01f4

# Usage:
#   export AI_AUDIT_SIGNING_KEY=<seed>
#   export AI_AUDIT_ENV=production
#   from ai_audit import AuditConfig, init_audit_config
#   init_audit_config(AuditConfig.from_env())
```

For scripting / piping, use `--quiet` to print only the seed:

```console
$ ai-audit gen-key --quiet
d58251819896733b749755e52a6ca32d3161c028ce71ae0faa941aabbcf1b70d

$ export AI_AUDIT_SIGNING_KEY="$(ai-audit gen-key --quiet)"
```

## `ai-audit verify`

Verify an evidence-package ZIP **offline**, without any access to the
production system that produced it. Used by external auditors.

```console
$ ai-audit verify bundle.zip
PASS: bundle.zip - all checks passed
```

`PASS` means: the manifest is signed correctly, every file's SHA-256 matches
the manifest, every receipt's Ed25519 signature is valid against the embedded
public key, and the hash chain is intact end to end. `FAIL` reports the index
of the first failing receipt and the failure mode.

Add `-v` for verbose output:

```console
$ ai-audit verify bundle.zip -v
Verifying: bundle.zip
PASS: bundle.zip - all checks passed
```

## `ai-audit info`

Print the package version and a couple of runtime self-checks. Useful in bug
reports and CI.

```console
$ ai-audit info
ai-audit-trail 0.4.3
Python: 3.12.10
PyNaCl: available
```
