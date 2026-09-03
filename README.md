# AgentMembrane

Characterizing security boundaries for **untrusted external agents in persistent
multi-agent memory**: when an agent is fully authorized and never lies, can its
*framing* of true evidence still push a downstream agent's persistent belief toward
an attacker-chosen conclusion?

This repo is a **lightweight reference runtime + a falsifiable measurement harness**,
not a claim that a particular defense wins. See [`docs/PROPOSAL.md`](docs/PROPOSAL.md)
for the research plan (boundary-first design with a pre-registered outcome tree).

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

> **Status: work in progress; no result here is paper-ready.** For canonical RQ1,
> an exact seven-workflow conditional replay produced native attack effects in 7/7
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
agentmembrane/real_asr_v3.py            strict V3B harness (four arms, net-effect GO)
agentmembrane/real_asr_v3a_permissive.py  frozen permissive harness (Run A)
agentmembrane/compare_real_asr_v3_ab.py   strict reanalysis of Run A + A/B comparison
agentmembrane/{kernel,memory,proxy,...}.py  minimal capability/quarantine runtime
agentmembrane/semantic_rq2/              canonical RQ2 R0--R4 baseline harness
experiments/semantic_receptor_rq2/       frozen RQ2 protocol, contract and profiles
tests/                                   38 RQ2 offline tests (no model calls)
docs/PROPOSAL.md                         research plan (chosen direction)
results/                                 frozen aggregate RQ1/RQ2 artifacts (no contract text)
reports/                                 human-readable design, results, ablations, and caveats
docs/RESULTS.md                          current result entry point
data/README.md                          how to obtain ContractNLI (not redistributed)
```

## Reproduce

```bash
python3 -m compileall -q agentmembrane tests
python3 -m unittest discover -s tests/semantic_rq2 -v  # 38 RQ2 tests, no model
# then obtain ContractNLI (see data/README.md), build the frozen manifest, and run:
python3 -m agentmembrane.real_asr_v3 validate --manifest <manifest>
python3 -m agentmembrane.real_asr_v3 run --manifest <manifest> --run-dir outputs/v3b_strict --model <model>
```

The legacy V3 command reproduces the historical framing pilot. For the complete
canonical proposal RQ2 (`semantic_receptor_expressiveness`), use
[`experiments/semantic_receptor_rq2/README.md`](experiments/semantic_receptor_rq2/README.md).

## Attribution

Evaluation uses **ContractNLI** (Koreeda & Manning, 2021), released under
**CC BY 4.0**. The dataset is **not** redistributed here; see
[`data/README.md`](data/README.md) to obtain it.
