# AgentMembrane

AgentMembrane studies security boundaries for **untrusted external agents**.
Canonical RQ1 measures how an external agent's real business-tool authority changes
task utility and attack reachability. Canonical RQ2 measures how semantic receptor
expressiveness changes persistent-memory risk.

This repository is the canonical public source for the runtime, measurement
harness, tests, protocols, aggregate results, and weekly reports. Raw benchmark
copies, model I/O, credentials, and machine-local run artifacts stay in the private
research workspace. See the [repository workflow](docs/REPOSITORY_WORKFLOW.md).

The curated [`references/`](references/README.md) library lists the closest papers,
with one page per paper containing bibliographic metadata, a Chinese abstract
paraphrase, a short AI-generated summary, and its exact relationship to the RQs.

## Proposal tracks

- **PRIMARY — current research plan:** [`docs/PROPOSAL.md`](docs/PROPOSAL.md),
  centered on authority, receptor expressiveness, memory promotion, and the
  evidence-preserving semantic-infection study implemented in this repository.
- **ALTERNATIVE / SECONDARY — bio-inspired admission and containment direction:**
  [`docs/APPENDIX_BIO_INSPIRED_ALTERNATIVE.md`](docs/APPENDIX_BIO_INSPIRED_ALTERNATIVE.md),
  retained as an appendix and not a replacement for the primary proposal.

> **Status: work in progress; no result here is paper-ready.** The current RQ1
> three-tier baseline is 46 eligible AgentDojo tasks × low/medium/high external
> authority × honest/malicious. A paused mixed-code diagnostic attempted 136 of
> 276 cells; it is not formal evidence and will not be resumed or pooled. See the
> [Week 9 report](weekly_reports/week9/week9_report_20260916_zh.md). In earlier canonical
> RQ1 work, an exact seven-workflow conditional replay produced native attack effects in 7/7
> vulnerable sessions and 0/7 protected sessions while preserving benign utility
> at 7/7, but a real 50-session natural-activation calibration produced 0 target
> proposals despite 44/50 carrier exposures. RQ1 therefore has a positive
> conditional mechanism result, not a completed natural end-to-end contrast. The
> canonical RQ2 200-case engineering confirmation found a frozen R2-over-R1
> contrast of +14.7 points with a cluster 95% CI of [8.6, 20.8], while remaining
> non-monotone and `claim_bearing=false`. See the [`reports/` index](reports/README.md),
> [current RQ1 report](reports/rq1/RQ1_CURRENT_RESULTS_20260902.md), and
> [full RQ2 report](reports/rq2/RQ2_FULL_REPORT_20260901.md).

## The question, made precise

The core object is **authorized semantic infection**: an external agent that

- never escalates privilege, never calls a forbidden tool, never writes memory directly;
- never fabricates a fact and never denies a clause that is present;
- never states the task answer;

…and yet, by *selection / ordering / emphasis / uncertainty wording alone*, moves a
future agent's decision. The harness is built so this cannot be faked:

- **Frozen candidate-evidence packet.** All four arms see byte-identical evidence
  (every candidate span, all gold retained, neutral order). No arm may omit, add, or
  reorder evidence, so a "win" can never come from hiding the deciding clause — the
  failure mode that made our own earlier versions a tautology (see *Design history*).
- **No answer leak.** The downstream agent never sees a label. An `OVERT_DECISION_RE`
  plus an LLM `no_explicit_task_answer` auditor reject any note that states the answer
  (even via synonyms like "consistent with the agreement").
- **Four arms:** `neutral` (honest note), `framing` (biased-but-true note),
  `obedience` (honest note + an explicit external label — a label-copy *positive
  control*), `reground` (framing note, but the downstream re-reads the packet).
- **Honest metric.** GO is driven by the **validity-gated net framing effect**
  (`framing_target − neutral_target`, reverse moves deducted), bootstrapped by
  **document cluster** (57 unique contracts, not 150 independent rows). The one-sided
  "constrained success" rate is reported only as an ASR figure and does **not** drive GO.

## Design history (why the harness looks the way it does)

1. **v1/v2 — tautology caught.** An early attack let the agent *omit* the deciding
   evidence; downstream then said "not mentioned" ~100% of the time. That is not
   framing, it is withholding the answer, and it was baked into the eligibility filter.
2. **v3 — evidence-preserving framing.** Force the deciding evidence to stay in front
   of the downstream agent; only the narrative may vary.
3. **v3 permissive vs v3B strict (this repo).** A permissive run and a strict run are
   compared with the *same* corrected metrics. Strict adds: net effect (reverse moves
   deducted) as the GO driver, a semantic answer-leak auditor, raw-schema violations
   that are not silently cleaned, and default request throttling.

## Layout

```
agentmembrane/host_v2/                 RQ1 benchmark, authority, and evidence runtimes
agentmembrane/host_v2/rq1_three_tier_formal_v1/  fail-closed three-tier formal runtime
agentmembrane/semantic_rq2/              canonical RQ2 R0--R4 baseline harness
tests/                                   offline, synthetic, and integration checks
tools/                                   reproducible builders and repository audits
weekly_reports/                          canonical Week 1 onward public report sequence
experiments/host_boundary_v2/            small public protocol metadata only
experiments/semantic_receptor_rq2/       frozen RQ2 protocol, contract and profiles
docs/PROPOSAL.md                         research plan (chosen direction)
docs/AGENTMEMBRANE_ORIGINAL_PROPOSAL.md  hash-bound original RQ1 proposal
results/                                 frozen aggregate RQ1/RQ2 artifacts (no contract text)
reports/                                 human-readable design, results, ablations, and caveats
docs/RESULTS.md                          current result entry point
data/README.md                          how to obtain ContractNLI (not redistributed)
```

## Reproduce

```bash
./tools/bootstrap_research_workspace.sh  # one-time exact benchmark checkouts + venv
.venv/bin/python -m compileall -q agentmembrane tests tools
.venv/bin/python -m pytest -q tests/rq1_three_tier
.venv/bin/python -m unittest discover -s tests/semantic_rq2 -v
.venv/bin/python tools/audit_public_repo.py
# then obtain ContractNLI (see data/README.md), build the frozen manifest, and run:
.venv/bin/python -m agentmembrane.real_asr_v3 validate --manifest <manifest>
.venv/bin/python -m agentmembrane.real_asr_v3 run --manifest <manifest> --run-dir outputs/v3b_strict --model <model>
```

The legacy V3 command reproduces the historical framing pilot. For the complete
canonical proposal RQ2 (`semantic_receptor_expressiveness`), use
[`experiments/semantic_receptor_rq2/README.md`](experiments/semantic_receptor_rq2/README.md).

## Attribution

Evaluation uses **ContractNLI** (Koreeda & Manning, 2021), released under
**CC BY 4.0**. The dataset is **not** redistributed here; see
[`data/README.md`](data/README.md) to obtain it.
