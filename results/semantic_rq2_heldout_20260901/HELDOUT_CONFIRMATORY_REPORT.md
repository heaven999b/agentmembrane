# RQ2 held-out 50-case confirmatory engineering report

## Status

This run is a preregistered engineering confirmation of
`semantic_receptor_expressiveness`, not a formal claim-bearing experiment. The
sample contains 50 cases from 25 ContractNLI document clusters with zero cluster
overlap with the calibration round. The neutral-P0 view and source-fidelity audit
were frozen and published before the complete 50-case execution.

## What was held fixed

- A2 Proposal-Only authority and P0 Direct Commit promotion.
- Complete R0--R4 receptor ladder.
- Full evidence packet at downstream decision time.
- Evidence-only and unchanged one-line explicit-recommendation controls.
- Three attack candidates per receptor and the frozen surrogate selection rule.
- `gpt-5.6-sol` generator/auditor and `gpt-5.6-terra` surrogate/downstream.
- Source-fidelity validity as the primary audit; strict-v1 audit and the visible
  untrusted-memory warning are secondary panels.

## Integrity

- 50/50 generation blocks completed; no failed case.
- 600/600 neutral-P0 records completed, with 12 unique arms per case.
- Packet identity passed for 600/600 records; all cited evidence IDs were valid.
- The source-fidelity audit completed 500/500 artifacts and produced 495 valid
  honest/attack rows. Neutral P0 inherited all 500 validity decisions exactly,
  with zero key-level mismatch.
- Downstream request scans found zero gold-label, assigned-target, or arm-ID
  fields. Neutral-P0 requests also contained zero old provenance-warning strings.

## Held-out result

Evidence-only accuracy was 92%. Source-faithful pair coverage passed the frozen
80% gate at every receptor.

| Receptor | All-attempt effect | Source-faithful effect | Valid-pair coverage | Exact paired p | Cluster bootstrap 95% CI (valid) |
|---|---:|---:|---:|---:|---:|
| R0 evidence selection | +2 pp | +2.0 pp | 100% | 1.0000 | [-4.0, 8.0] pp |
| R1 evidence annotation | 0 pp | 0.0 pp | 100% | 1.0000 | [-6.0, 6.0] pp |
| R2 structured inference | +18 pp | +19.1 pp | 94% | 0.0039 | [8.5, 31.3] pp |
| R3 recommendation | +6 pp | +6.0 pp | 100% | 0.2500 | [0.0, 14.0] pp |
| R4 free form | +22 pp | +22.9 pp | 96% | 0.0010 | [12.2, 34.7] pp |

The held-out result independently reproduces low effects at R0/R1 and strong
positive effects at R2/R4. It does **not** reproduce a monotone R0--R4 curve:
R2 rises 18 points above R1, R3 then falls 12 points below R2, and R4 rises 16
points above R3. The R2-minus-R1 increment survives Holm correction (`p=0.0156`);
the other adjacent increments do not. The defensible interpretation is therefore
an observed onset at structured inference with strong R2 and R4 susceptibility,
not a proven monotone dose-response or a distinct boundary at every step.

## Failed ceiling gate

The unchanged one-line explicit-recommendation ceiling produced exactly zero
paired movement: 0 toward, 0 away, and a 0-point effect. It therefore failed both
frozen ceiling gates (+10 points and at least five toward-target pairs), even
though R2 and R4 artifacts produced large positive effects. This shows that the
old control is not a maximal semantic ceiling on this held-out sample; it does not
erase the directly observed positive engineering effects, but it blocks a bounded
null claim and prevents formal measurement sign-off.

For context only, pooling the earlier post-pilot calibration with this held-out
round gives 100 cases from 50 disjoint clusters and effects of `2, 3, 17, 12, 23`
points. That pooled curve retains the R3 dip and the combined ceiling remains only
6 points. Because the first half was post-pilot, this pooled analysis is descriptive
and is not substituted for the held-out primary result.

## Execution accounting

The main run contains 3,454 parsed model-call cache records and 6,077,314 tokens:

| Stage | Calls | Tokens |
|---|---:|---:|
| Source generation, strict audit, warning panel | 2,354 | 4,119,626 |
| Preregistered source-fidelity audit | 500 | 1,092,208 |
| Neutral-P0 primary downstream | 600 | 865,480 |

The source runner was safely resumed after a runtime hang at 40/50 generation
blocks. All frozen blocks and cache records were reused, and final receipts passed.
The legacy session counter in `results.json` counts only the resumed process for
generator/surrogate/strict-auditor usage; the table above is reconstructed from
the complete role-local cache inventory. The result records themselves are not
affected. A separate code fix adds persisted-cache totals for future resumptions.

## Decision

Do **not** launch the 100-cluster formal run with the current configuration. The
next calibration should change measurement, not the observed held-out result:

1. retain the failed one-line control and add a separate source-faithful,
   R4-shaped maximal semantic ceiling with comparable length and the same neutral
   wrapper;
2. add a content-equated nested receptor panel, because current R0--R4 artifacts
   are generated independently and R3 is not literally an extension of R2;
3. calibrate the source-fidelity audit on at least 100 human-labeled artifacts;
4. add a second downstream model family; and
5. obtain additional independent document clusters from another dataset. Only
   107 ContractNLI documents satisfy the current balanced-pair rule, and 50 have
   already been used, leaving 57 unseen—insufficient for a fresh 100-cluster run.

## Integrity anchors

- Frozen public code/protocol commit: `fe0e601`
- Held-out manifest SHA-256:
  `3b8a522d5ff6b62cf60129ee1f616cff26dbba756d4a6447da2feff8887d24e6`
- Generation receipt bundle:
  `27605368a18440c9e4e88380af81903e6a90e826d92e4516c8fec27e3f006f4a`
- Source-fidelity audit bundle:
  `5179edd426e83f2ac339d2eb1bfc72f8e74caff0b2ba37b135242c5db936efa4`
- Neutral-P0 results SHA-256:
  `6b686020c2aafc9528471dbb99a3f2de2e7c169117a00bd7a5d4872dd956fd65`
- Neutral-P0 records SHA-256:
  `0f378d8b6fb3cf032de36d0ae1e2b2d0b521f0d1948d5f165c2e99df3138692a`
