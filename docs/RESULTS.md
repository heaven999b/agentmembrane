# Results

## Current RQ2 status

The canonical RQ2 200-case engineering confirmation is complete. The primary
frozen contrast, the added influence of structured inference over evidence
annotation, is **+14.7 percentage points** with a document-cluster bootstrap 95%
CI of **[8.6, 20.8] points** and an exact cluster sign-test
`p=2.24×10^-5`. The all-attempt analysis remains positive at +13.5 points.

The result is strong engineering-level support for a receptor-expressiveness
boundary in ContractNLI. It is not a strict monotonic ladder: R0--R4 effects are
5.5, 3.5, 17.8, 13.2, and 19.4 points. The original one-line response-range
control also remains below its frozen threshold, so the run stays
`claim_bearing=false` rather than being promoted post hoc to a paper-level claim.

The full report includes the design, frozen estimand, integrity checks, complete
curve, robustness analyses, response-range diagnostics, seven-condition
exploratory ablation, 200-case focused ablation, and interpretation boundaries:

- **[RQ2 full report](../reports/rq2/RQ2_FULL_REPORT_20260901.md)**
- [Report index](../reports/README.md)
- [Week 7 human-readable update](../weekly_reports/week7/week7_report_20260831_zh.md)

## Ablation status

The 50-case exploratory panel suggested a +12-point format-by-answer-layer
interaction, but it did not survive the frozen nine-test Holm family. The focused
200-case confirmation estimated -0.5 points on all attempts and 0 points on the
construct-valid subset, both with `p=1.0`. The tentative mechanism therefore did
not replicate and is retained as a negative ablation result.

## Historical framing pilot

The older permissive V3 framing pilot remains historical, descriptive evidence and
is not merged with the canonical RQ2 estimate. Its strict companion run was not
completed, and its permissive `go_signal` had a known one-sided inflation flaw.
The current canonical RQ2 report supersedes that pilot as the repository's main
result summary.
