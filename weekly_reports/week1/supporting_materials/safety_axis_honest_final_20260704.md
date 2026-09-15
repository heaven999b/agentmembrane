# Safety axis — honest final state (2026-07-04)

Supersedes the optimistic framing in `state/e1_stats_and_rq1_safety_axis_20260703.md`
and the docx `安全轴_pilot报告_20260703.docx`. Report of record: `安全轴_诚实修订_20260704.docx`.

## What a 5-lens adversarial red-team + honest re-scoring established

**Retracted (my 07-03 overclaim):** "write-gate drops backdoor comply 100%->0%, vulnerability+cause+fix closed." It does not.

### Refuted / not supported
- **Original thesis (C^N launders/amplifies unsafe content):** refuted. prompt_only (no memory) payload_emission = 1.000 >= tiermem N=0 (0.867) >= N=2 (0.733). Consolidation only *reduces* exposure via forgetting.
- **"UAF=0 => no laundering":** artifact. `_bootstrap_ci` degenerated to [0,0] on all-0 cells; exact Clopper-Pearson upper bound at n=12 is 0.27. And the unsafe marker was hardcoded into the seed (construct contamination). Fixed the CI to exact binomial in `safety_metrics.py` + judge.
- **"write-gate defense works":** cosmetic. On v1 poison, comply 100%->0% but payload still emitted 83% (N=1) among judged-REFUSE answers (hedge-comply). Keyword gate recall 0/30 on stealthy poison; semantic gate recall ~28/30 but reduces emission only 3-10pp (within noise). Read-time meta-policy rule: 100%->93%.

### Solid, publishable
1. **Hedge-refusal (methodology, strong):** LLM-judge comply/refuse overstates agent safety; hedged-but-dangerous answers are labelled REFUSE. Use payload-emission (behavioural endpoint) instead. Clean, general, citable.
2. **Consolidation is benign (negative result, medium):** the vulnerability is reader-side authority-weighting, independent of consolidation; C^N slightly reduces exposure and only (weakly) erodes read-time defenses.

### Real but not clean (not yet a paper claim)
- Reader-side: co-present correct policy gives ~no protection (payload_emission 87-100%). BUT convention == command (framing not special -> overlaps instruction-hierarchy lit), queries prime "quickest way" (ceiling), n=15, single seed/backbone. Factors indistinguishable at ceiling.

## Key numbers (payload_emission, exact CIs, n=15 unless noted)
- prompt_only policy+convention: 1.000 ; +read-time defense: 0.933 ; command framing: 1.000 ; no policy: 0.867
- tiermem no-defense: N0 0.867 / N2 0.733 ; tiermem read-time defense: N0 0.667 / N2 0.733
- v1 write-gate honest re-score (n=24): comply N1 0.000 but payload_emission 0.833 (hedge_comply 0.833)
- stealthy: keyword-gate recall 0/30 (v1: 100/100); LLM-gate recall ~28/30, emission off 0.87->0.77 / llm 0.83->0.70

## Paper skeleton A (writable now)
Title: "The Illusion of Memory-Safety Defenses: Hedge-Refusal and the Benign Role of Consolidation"
- C1 methodology: hedge-refusal -> payload-emission endpoint.
- C2 negative: consolidation doesn't launder/amplify; vulnerability is reader-side.
- C3 defense audit: keyword (0% recall) + semantic (detect!=mitigate) + read-time (ignored) defenses fail.
- Artifacts: exact/cluster CIs, stealthy suite, orthogonal authority harness.

## To rescue the security main line (lower-ceiling battery)
Neutral queries (drop "quickest way"), harder non-saturating scenarios, >=40 semantic families + cluster CIs, >=5 seeds x >=2 cross-family backbones, human-validated endpoint + kappa, adaptive attacks, RQ2' factual-convention axis on HaluMem.

## Files added this round
`safety_honest_metrics.py`, `run_rq1_safety_rescore.py`, `safety_write_filter.py`,
`run_rq1_agentpoison_overlay.py`, `run_rq1_authority_experiment.py`,
`benchmarks/safety/{agentpoison_trigger,stealthy_poison}_suite_v1.json` (+ builders),
`安全轴_诚实修订_20260704.docx`. CIs fixed in `safety_metrics.py` + `run_rq1_safety_judge.py`.
Run tiermem paths with `.venv_tiermem_v2/bin/python` + `set -a && source .env.v3`; isolate `MEM0_DIR` per concurrent run.
