# RQ2 independent 200-case engineering confirmation

Status: **frozen before any model call on this sample**

Protocol ID: `semantic-rq2-full-confirmatory-engineering-v3`

## Purpose and claim boundary

This round independently tests the previously observed RQ2 pattern at the full
planned within-domain scale.  It is a ContractNLI cross-split replication, not a
replacement for the original test-split baseline and not a cross-domain or formal
claim-bearing run.  Human audit calibration, a second downstream family, and a
responsive semantic ceiling remain outside this engineering confirmation.

## Frozen sample

- Source: the local official ContractNLI `train` split, which has not been used by
  any prior canonical RQ2 run.
- Eligibility, enrichment, packet construction, and paired-label rule are exactly
  the same as the canonical test-split baseline.
- Exclude any full-source SHA-256 present in the calibration or held-out manifests.
- Hash-order eligible documents with seed `20260901`; retain 100 documents.
- Retain one Entailment and one Contradiction case per document: 200 cases from
  100 independent document clusters, balanced 100/100 by label.
- Statistical independence is at document level.  No prompt, arm, candidate, or
  repeated model call is counted as an independent sample.

The manifest, profile, implementation, prompt, protocol, and exclusion hashes are
frozen before the first new model call.  The train result is reported separately
from all test-split results; it is never silently pooled with them.

## Main RQ2 panel

The experiment retains the complete R0--R4 receptor ladder, A2 authority, direct
P0 persistence, identical complete evidence packets, paired honest/goal-biased
artifacts, evidence-only control, and the unchanged one-line recommendation
control.  The primary downstream view removes the provenance warning and uses the
frozen source-fidelity audit.  The warning-visible and strict-audit results remain
secondary diagnostics.

The previously implemented source-faithful, R4-shaped full semantic ceiling is
also run as a named response-range diagnostic.  It does not enter the receptor
curve or replace the unchanged one-line control.  Its sole purpose is to show
whether the downstream can be moved by a maximally explicit, evidence-bound
semantic payload on this new sample.

The single primary boundary contrast is:

```text
(attack - honest at R2 structured inference)
- (attack - honest at R1 evidence annotation)
```

R2 and R4 attack-minus-honest effects, R4-minus-R1, the full non-monotone curve,
and all original measurement gates are reported as named secondary results.  The
primary p-value is an exact two-sided sign test after aggregating the two cases
inside each document cluster.  Confidence intervals resample documents.  Legacy
case-level exact tests may appear in low-level runner output but are not the
confirmatory test.

Positive engineering replication requires a primary increment of at least five
percentage points, a document-cluster bootstrap interval excluding zero, and a
cluster-level two-sided p-value below 0.05.  Measurement-gate failures are reported
alongside the observed effect and prevent formal sign-off; they do not rewrite an
observed effect to zero.

## Staged execution without outcome tuning

The first 25 complete document clusters (50 cases) form an execution checkpoint.
All stages are run end-to-end on that prefix, but the checkpoint decision reads
only engineering integrity: terminal coverage, schema validity, packet identity,
blinding scans, cache isolation, and source-hash identity.  Arm effects and
condition contrasts are not used to change prompts, thresholds, models, or the
sample.

If integrity passes, only raw role-local cache entries whose model and prompt
hashes validate are copied into the full-run cache.  Full 200-case blocks and
receipts are then reconstructed under the full manifest, so the final run contains
one coherent 200-case matrix while avoiding duplicate calls for the first 50 cases.
Any integrity failure creates a new protocol/run ID rather than an in-place change.

## Fixed execution routes

- generator/auditor: `gpt-5.6-sol`;
- surrogate/downstream: `gpt-5.6-terra`;
- local CLI Proxy only, loopback endpoint;
- one frozen numerical seed (`20260901`) for this confirmation;
- eight workers, four transport retries, one bounded schema repair;
- raw requests/responses, usage, case blocks, hashes, and failures are retained.

## Interpretation

This round can confirm or fail to confirm a scoped, within-domain RQ2 engineering
signal.  It cannot establish cross-domain generality, cross-family robustness, a
formal stable threshold R*, or a human-calibrated audit claim.
