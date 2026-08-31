# AgentMembrane RQ2 50-case GPT engineering audit

## Verdict

- Canonical construct alignment: **PASS** for proposal RQ2
  `semantic_receptor_expressiveness`.
- Exact proposal Section 12 Boundary Pilot equivalence: **NO**. This run is the
  isolated receptor baseline at fixed A2/P0 with the complete R0--R4 ladder; it
  does not run P3/P5 or receptor-by-promotion interactions.
- Engineering execution integrity: **PASS**.
- Formal/claim-bearing interpretation: **FAIL-CLOSED (`not_estimable`)**.

## Design audited

- ContractNLI official test split, 50 cases in 25 complete document clusters.
- Balanced labels: 25 Entailment and 25 Contradiction.
- Fixed authority A2 Proposal-Only and promotion P0 Direct Commit.
- Evidence-only control, explicit wrong-target ceiling, and honest/attack pairs
  at every R0--R4 receptor: 12 arms per case.
- Best-of-3 attack candidate search with held-out surrogate ranking.
- Blind artifact audit before a hashed generation freeze; downstream evaluation
  only after the freeze.
- One engineering downstream (`gpt-5.6-terra`), with same-family GPT roles. This
  is calibration-only and cannot satisfy the cross-family formal profile.

## Code defects found and repaired before the run

1. A naive first-50 truncation would split document clusters. A dedicated
   50-case manifest now retains 25 complete two-case document clusters.
2. Generator artifacts were not bound to the runner-assigned opaque artifact ID.
   Schema validation now checks the expected artifact ID.
3. Blind-auditor output was not bound strongly enough to the exact opaque ID or
   packet evidence-ID universe. Both are now validated.
4. Finalization lacked a hard 12-arm record-matrix gate. The runner now rejects
   missing, duplicate, extra, seed-mismatched, or packet-mismatched cells.
5. Engineering preflight incorrectly required the formal 200-case shape. Formal
   remains exact/fail-closed; engineering calibration permits a validated smaller
   manifest.
6. Case-level concurrency and thread-safe usage counters were added without
   changing within-case arm ordering or the generation-freeze boundary.

## Execution integrity

- Offline preflight: PASS.
- Generation and blind-audit receipt: PASS, 50/50 cases, zero failed cases.
- Evaluation matrix: PASS, 600 expected and 600 observed unique cells.
- Terminal status: 600/600 completed.
- Packet identity: 600/600 matched.
- Cached raw calls: 2,354/2,354 parsed successfully.
- Generation block receipt hash mismatches after evaluation: zero.
- RQ2 unit tests: 19/19 PASS.
- RQ2 isolated mypy check: 7 modules, zero errors.

## Model usage

- Generator: 1,004 calls, 1,736,844 tokens.
- Surrogate: 250 calls, 480,121 tokens.
- Auditor: 500 calls, 993,592 tokens.
- Downstream: 600 calls, 878,856 tokens.
- Total: 2,354 calls, 4,089,413 tokens.

## Descriptive calibration result

All-attempt attack-minus-honest target-shift points were monotone in the observed
sample:

| Receptor | Effect | Cluster bootstrap 95% interval |
|---|---:|---:|
| R0 Evidence Selection | 0 pp | [-6, 6] pp |
| R1 Evidence Annotation | 0 pp | [-8, 8] pp |
| R2 Structured Inference | 8 pp | [0, 18] pp |
| R3 Recommendation | 12 pp | [4, 22] pp |
| R4 Free-form | 20 pp | [10, 32] pp |

These values are descriptive only. They must not be presented as the RQ2 result
because the measurement gates below failed.

## Why the result is `not_estimable`

- Only 25 independent document clusters were run; formal analysis requires 100.
- Construct-valid pair coverage was below 80% at R2 (72%), R3 (48%), and R4
  (50%). Audit failures were primarily fact-validity and qualifier-integrity
  failures, not schema or transport failures.
- The explicit wrong-target ceiling moved decisions by only 4 pp with two
  toward-target pairs; the frozen gate requires at least 10 pp and five pairs.
- The run uses a single GPT family and has no passed human-auditor calibration.

The evidence-only accuracy was 80%, terminal-failure imbalance was 0%, the full
receptor ladder was present, and packet identity passed. Those successes do not
override the failed gates.

## Artifact hashes

- `results.json`: `ccc38f4bddc6073a81c8e3aba3d65b624e919a64004b5900b572f537cec626a3`
- `records.jsonl`: `a7e1254923ea90846804ebb9aa59f0707e3f1984ce2f2d4d2496dc8f1fd831d4`
- `generation/receipt.json`: `b44498ddc5e498d3d9035612cfb224f04dddfad15eb8fdf7276393b41cd933d1`
- `evaluation/integrity.json`: `bc6724265f1bb5cb6252366fa2514f72d951ef12fdbf7f9d1dba852c6004e7da`
