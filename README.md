# AgentMembrane

Characterizing security boundaries for **untrusted external agents in persistent
multi-agent memory**: when an agent is fully authorized and never lies, can its
*framing* of true evidence still push a downstream agent's persistent belief toward
an attacker-chosen conclusion?

This repo is a **lightweight reference runtime + a falsifiable measurement harness**,
not a claim that a particular defense wins. See [`docs/PROPOSAL.md`](docs/PROPOSAL.md)
for the research plan (boundary-first design with a pre-registered outcome tree).

> **Status: work in progress. The results here are a preliminary pilot and are NOT
> paper-ready.** A single seed, a single model, one shared backbone across roles, and
> the strict run (Run B) has not completed yet. Do not cite any number here as a
> validated finding.

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

## Repository structure

Code, prose, result data, and dataset are kept in separate top-level areas so each can
be read, cited, or replaced on its own:

```
agentmembrane/     CODE — source package (harnesses, comparison tool, runtime)
tests/             CODE — 36 offline tests (no model calls)
tools/             CODE — dev utilities (live monitor dashboard)
docs/              REPORTS — PROPOSAL.md (research plan) + RESULTS.md (write-up + caveats)
results/           RESULT DATA — aggregate metrics only, no contract text (JSON)
data/              DATASET — how to obtain ContractNLI (raw data is NOT redistributed)
README.md          this file · pyproject.toml · .gitignore
```

Key modules:

```
agentmembrane/real_asr_v3.py              strict V3B harness (four arms, net-effect GO)
agentmembrane/real_asr_v3a_permissive.py  frozen permissive harness (Run A)
agentmembrane/compare_real_asr_v3_ab.py   strict reanalysis of Run A + A/B comparison
agentmembrane/{kernel,memory,proxy,...}.py  minimal capability/quarantine runtime
```

See [`docs/RESULTS.md`](docs/RESULTS.md) for the current (preliminary) results and
[`docs/PROPOSAL.md`](docs/PROPOSAL.md) for the plan.

## Reproduce

```bash
python3 -m compileall -q agentmembrane tests
python3 -m unittest discover -s tests -v          # no model calls; the manifest-
                                                  # dependent tests need the built
                                                  # manifest (see data/README.md)
# obtain ContractNLI (data/README.md), build the frozen manifest, then run:
python3 -m agentmembrane.real_asr_v3 validate --manifest <manifest>
python3 -m agentmembrane.real_asr_v3 run --manifest <manifest> --run-dir outputs/v3b_strict --model <model>
```

## Attribution

Evaluation uses **ContractNLI** (Koreeda & Manning, 2021), released under
**CC BY 4.0**. The dataset is **not** redistributed here; see
[`data/README.md`](data/README.md) to obtain it.
