# Week 6 Package

This folder is a self-contained report for **another independent research line** —
*AgentMembrane: security boundaries for untrusted external agents in persistent
multi-agent memory* — distinct from the reproduction project (Weeks 1–4) and the
self-model-miscalibration line (Week 5). It covers a self-caught artifact, a
confound-free harness rebuild, and the first permissive pilot (Run A) on real
ContractNLI data.

**Public code + results:** https://github.com/heaven999b/agentmembrane

## Reading order

| File | Purpose |
| --- | --- |
| [week6_report_20260825_zh.md](./week6_report_20260825_zh.md) | Plain-language Chinese report: the new idea (authorized semantic infection), the confound-free minimal experiment (evidence-preserving four arms), the permissive minimal positive signal (Run A: 4/150 = 2.7%, doc-clustered CI [0.6%, 5.4%]), and the **completed strict A/B** showing it does NOT survive the no-answer-leak control — net framing effect 0 in both runs, GO=False, `A_negative_B_negative` (Path C) |

For the full research plan and the runnable harness, see the
[chosen boundary-first proposal](../../docs/PROPOSAL.md), the
[current results entry point](../../docs/RESULTS.md), and the four-arm harness
under `agentmembrane/`.

## Evidence vocabulary

- **Self-caught artifact**: an early "100% attack success" that was a definitional
  tautology — success required deleting the deciding evidence, and that requirement
  was baked into the eligibility denominator. Retired before it reached any conclusion.
- **Permissive minimal positive signal (Run A)**: biased framing flipped 4/150
  downstream decisions that neutral did not (2.7%, doc-clustered CI [0.6%, 5.4%]) — real
  but small, and a permissive-stage figure (the run's own `go_signal` is not used).
- **Completed strict A/B (Run B + reanalysis of A)**: under the strict
  `no_explicit_task_answer` control, ~90–96% of *all* notes are judged to convey the
  answer, valid coverage collapses to 1–3%, and the net framing effect is **0** in both
  runs. Verdict `A_negative_B_negative`: the permissive signal was answer-leakage, not
  pure framing → a negative (Path-C) result. Single seed / single model — not
  paper-ready.

The public aggregate artifacts are
[`runB_strict_analysis.json`](../../results/runB_strict_analysis.json) and
[`v3_ab_comparison_seed1.md`](../../results/v3_ab_comparison_seed1.md), with the
machine-readable comparison beside it.

Single seed, single model, one shared backbone across analyst/auditor/downstream —
nothing here is a validated finding.

No API credential, private prompt/response body, or paid-provider secret is included
in the public package. ContractNLI (CC BY 4.0) is attributed but **not** redistributed.
