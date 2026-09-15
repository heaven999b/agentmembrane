# Week 5 Package

This folder is a self-contained report for an **independent research line** — *self-model miscalibration from selective memory* — distinct from the reproduction project in Weeks 1–4. It covers a proposal upgrade (v3) and the first landed validation (a stage-0 manipulation-check pilot).

## Reading order

| File | Purpose |
| --- | --- |
| [proposal_self_model_miscalibration_v6_20260805.md](./proposal_self_model_miscalibration_v6_20260805.md) | **Full latest proposal (v6)**: motivation → all 5 RQs with full baselines (main + fallback + data sourcing / no-AI-synthesis, main indicators, falsification) → related work (20+ neighbors) and per-RQ differentiation placed last. Fire-concentrated (RQ1/RQ5 core, RQ2/3/4 supporting); nine-way differentiation moat |
| [week5_report_20260805_zh.md](./week5_report_20260805_zh.md) | Plain-language Chinese report: what the research line asks, how the proposal was upgraded into a 5-RQ system, the stage-0 pilot result, the two problems it exposed, and the next-step fork |
| [stage0_pilot_results_20260805.md](./stage0_pilot_results_20260805.md) | Full pilot method, per-topic numbers, read-base-rate signal, saturation check, verdict, and evidence-class labeling |

## Evidence vocabulary

- **Measurement-flow validation (synthetic cards)**: synthetic memory cards used *only* to check whether the measurement pipeline works (can the model read a visible success rate; are pre-answer probabilities non-saturated). This is **not** a main experiment and does **not** enter main-experiment conclusions.
- **Live pilot call**: real model calls via a local proxy (fast model), serial + hard-capped + fully cached, ban-safe; used to probe feasibility, not to establish a headline.

The main experiment's data contract requires **zero AI-synthesized data** (public contest problems, official tests/exact-match scoring, model-true pass-rate difficulty, real run logs). The synthetic cards here are the one explicitly declared, purpose-limited exception (flow validation only).

No API credential, private prompt/response body, or paid-provider secret is included in this public package.
