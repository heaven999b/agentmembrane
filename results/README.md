# Public results

This directory contains immutable, sanitized aggregate evidence. A new evidence
bundle should include:

- a README stating scope, evidence level, and claim boundary;
- machine-readable aggregate results;
- the frozen config/controller bindings needed to interpret the result;
- an artifact manifest with repository-relative paths and SHA-256 hashes;
- a documented audit command that fails closed on tampering.

Raw prompts/responses, per-case records, licensed dataset text, caches, and
machine-local runtime state are not public results. Stable cross-run
interpretation belongs in `reports/`; the construct mapping is in
[`studies/registry.json`](../studies/registry.json).
