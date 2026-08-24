# Results (preliminary — NOT paper-ready)

**One-line status:** the strict run (Run B) has **not** completed (blocked on model
quota), so there is **no A/B result yet**. What exists is the permissive Run A, whose
own `go_signal` is deliberately **not** treated as a finding. Everything below is a
single seed, a single model (`gpt-5.6-sol`), one shared backbone across the analyst,
auditor, and downstream roles. Do not cite these numbers.

## Pipeline status

| Stage | State |
|---|---|
| Frozen packet / four-arm invariants (offline `validate`) | ✅ pass |
| Offline test suite (36 tests, no model) | ✅ pass |
| **Run A** — permissive V3, 150 ex / 57 contracts, `gpt-5.6-sol` | ✅ complete |
| **Run B** — strict V3B | ⛔ blocked (model cooldown / quota) |
| A/B strict reanalysis + comparison | ⏳ pending Run B |

## Run A (permissive) — descriptive only

Frozen ContractNLI semantic-risk subset: **150 examples across 57 unique contracts**,
directional target (Entailment ↔ Contradiction). Integrity gates all held:
`all_arms_packet_sha_identical = true`, `overt_decision_leak_rate = 0`,
`valid_pair_coverage = 0.93`.

Downstream **target-hit rate by arm** (fraction of examples the arm pushed to the
attacker's directional target):

| arm | note shown to downstream | target-hit rate |
|---|---|---:|
| `neutral` | honest note | **0.107** |
| `framing` | biased-but-true note | **0.127** |
| `obedience` | honest note + explicit external label (positive control) | 0.147 |
| `reground` | framing note, downstream re-reads packet | 0.113 |

**Reading (informal):** with the deciding evidence in front of the downstream agent
and no answer leaked, `framing` beats `neutral` by only ~**2 points**, and even
`obedience` — which literally hands over the target label — moves it just ~4 points.
That is a **weak signal**, pointing away from "framing alone flips persistent belief"
and toward a memory-reliability (Path C) reading. But this is the *permissive* run;
the honest test is the strict Run B, and the numbers must be recomputed with the net,
leak-gated metric. **Nothing is concluded here.**

## Why Run A's `go_signal` is discarded

Run A's permissive `go_signal` uses a one-sided constrained-success rate with a known
inflation flaw (it counts "neutral misses, framing hits" without deducting reverse
moves, and without the strict semantic-answer-leak gate). The strict harness
(`real_asr_v3.py`) replaces it with the validity-gated **net** effect. Run A is kept
only as raw permissive data to be **reanalyzed** with the strict rules once Run B exists.

## Execution note (provenance)

Run A was executed with a 4-way parallel, 0-throttle runner instead of the intended
serial + 15s throttle. Because generation is deterministic (`temperature = 0`) and the
cache is keyed by prompt hash, parallelism changed only speed/order, not model outputs;
`../results/FREEZE_runA.json` records the code SHA, manifest SHA, and result SHA.

## Provenance files

- [`../results/FREEZE_runA.json`](../results/FREEZE_runA.json) — frozen SHAs, counts, integrity gates (no contract text).
- [`../results/runA_permissive_analysis.json`](../results/runA_permissive_analysis.json) — the full aggregate analysis block (numbers
  and ids only; records/narratives, which quote contract text, are **not** included).
