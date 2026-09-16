# RQ2 independent 200-case engineering confirmation

This directory is the public, aggregate-only evidence bundle for the independent
ContractNLI-train RQ2 confirmation completed on 2026-09-01. The run is
engineering evidence, not a formal or paper-level claim: it uses one numerical
seed, one model family, no completed human audit calibration, and the frozen
one-line response-range control did not meet its threshold.

## Headline result

The frozen primary contrast is the added target influence of structured
inference over evidence annotation:

```text
Gamma_R2 = (attack - honest at R2) - (attack - honest at R1)
```

On the common source-fidelity-valid set, the estimate is **+14.7 percentage
points**, with a document-cluster bootstrap 95% interval of **[8.6, 20.8]**
points and a two-sided document-cluster sign-test `p=2.23615e-05` (191 cases,
99 document clusters). The all-attempt robustness estimate is +13.5 points.
The complete R0--R4 curve is non-monotone and the result remains
`claim_bearing=false`.

The focused 200-case mechanism confirmation did not replicate the earlier
format-by-answer-layer interaction: -0.5 points on all attempts and 0 points on
the construct-valid subset, both with `p=1.0`. The stronger semantic-ceiling
diagnostic moved the target rate by +12 points and passed its diagnostic
responsiveness gate, but it does not replace the frozen primary control.

## Public artifacts

- [`confirmation_analysis.json`](./confirmation_analysis.json): complete
  aggregate primary, robustness, and R0--R4 analyses.
- [`CONFIRMATION_REPORT.md`](./CONFIRMATION_REPORT.md): compact generated human
  summary.
- [`focused_interaction_results.json`](./focused_interaction_results.json):
  aggregate focused-mechanism result and integrity counts.
- [`semantic_ceiling_results.json`](./semantic_ceiling_results.json): aggregate
  response-range diagnostic.
- [`controller_config.json`](./controller_config.json): hashes binding the
  frozen manifests, profile, protocols, prompts, and implementation.
- [`artifact_manifest.json`](./artifact_manifest.json): byte sizes, SHA-256
  digests, evidence labels, and the explicit private/public boundary.

The frozen protocols, profile, and preflight receipts are in
[`experiments/semantic_receptor_rq2/`](../../experiments/semantic_receptor_rq2/).
The consolidated interpretation is in
[`reports/rq2/RQ2_FULL_REPORT_20260901.md`](../../reports/rq2/RQ2_FULL_REPORT_20260901.md).

## Verify

From the repository root, with Python 3.12 or 3.13:

```bash
python3 tools/audit_rq2_public_bundle.py
python3 -m unittest tests.test_audit_rq2_public_bundle -v
python3 -m unittest discover -s tests/semantic_rq2 -v
python3 tools/audit_public_repo.py
```

The bundle deliberately excludes ContractNLI text, raw prompts and responses,
per-case records, provider caches, local routes, credentials, and runtime state.
The two frozen manifests contain ContractNLI clauses and therefore remain local;
their SHA-256 digests are retained in `controller_config.json` and the preflight
receipts so a licensed local reconstruction can be checked byte-for-byte.

As a publication check, the retained private aggregate records were reanalyzed
with the public implementation. The regenerated confirmation analysis, compact
report, focused-interaction analysis, and semantic-ceiling analysis matched the
published aggregate files byte-for-byte. This check does not make the private
records public; it verifies that the public summaries were not manually copied or
recomputed with a different analysis path.
