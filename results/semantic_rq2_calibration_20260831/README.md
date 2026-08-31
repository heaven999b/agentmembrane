# RQ2 50-case calibration package (2026-08-31)

This directory contains reader-facing, aggregate-only reports for the canonical
AgentMembrane RQ2 construct `semantic_receptor_expressiveness`. It intentionally
excludes ContractNLI text, per-case records, raw prompts/responses, model caches,
and credentials.

The reports preserve the order in which the measurement diagnosis was performed:

1. [`STRICT_ENGINEERING_REPORT.md`](STRICT_ENGINEERING_REPORT.md) — frozen strict
   50-case baseline and fail-closed gate result.
2. [`FINAL_ONLY_AUDIT_REPORT.md`](FINAL_ONLY_AUDIT_REPORT.md) — one-rule audit
   change limited to final conclusions.
3. [`OMISSION_AUDIT_REPORT.md`](OMISSION_AUDIT_REPORT.md) — one additional rule
   distinguishing omission from affirmative source alteration.
4. [`BROAD_AUDIT_REPORT.md`](BROAD_AUDIT_REPORT.md) — post-pilot source-fidelity
   sensitivity analysis.
5. [`NEUTRAL_P0_REPORT.md`](NEUTRAL_P0_REPORT.md) — the single-change downstream
   calibration that removes the visible "untrusted memory" warning.

The current result is an engineering signal, not a confirmatory scientific claim.
Under neutral P0, the all-attempt R0--R4 effects are `2, 6, 16, 18, 24` percentage
points and the unchanged ceiling is `+12` points. With frozen broad source-fidelity
labels, valid-pair coverage is `100%, 100%, 98%, 98%, 100%` and effects are
`2, 6, 16.3, 16.3, 24` points. This analysis remains post-pilot, uses 25 independent
document clusters and one GPT family, and therefore has `claim_bearing=false`.
