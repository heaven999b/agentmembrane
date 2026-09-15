# Week 4 Research Report: From Reproducing Papers to Identifying Experiments That Actually Need to Be Done

This week did not produce a new paper, but it was also not limited to reading or summarizing prior work. We **recomputed released results, ran official baselines, added controlled experiments to test the boundaries of published claims, and identified two questions that may support new methods and one concrete evaluation problem.**

The most important correction is that experimental workload is not the same as research novelty. This report therefore separates what previous work has already established from what we added.

## 1. What Did We Actually Do This Week?

### 1.1 First layer: checking whether published results and released code can be reproduced

| Project | Work completed this week | Result | Can this be claimed as a new finding? |
| --- | --- | --- | --- |
| Lethe | Ran the official deterministic forgetting pipeline and official scorer | 244/385, or 63.38%, exactly matching the paper's 244/385 | No. This is an exact reproduction. |
| Engram | Recomputed metrics from the authors' 500 released outputs | lean 83.6%, full 73.2%, matching the released results | No. This is a recomputation of released outputs. |
| TokenPilot | Recomputed the authors' released quality and cost ledger | Quality 79.2%→81.3%; primary-model cost approximately $7.24→$2.79 | No. Auxiliary-module costs are missing, so full TCO is not identifiable. |
| GateMem | Used the official data, Long-Context baseline, native memory injection, prompts, judge, and scorer, replacing only the unavailable model | 30 checkpoints, 60 successful calls, 211,223 tokens, and zero scorer mismatches on recomputation | No paper-table reproduction claim. This is a model-substituted baseline with the paper's method preserved. |

In the corrected GateMem run, utility was 8/12 (66.67%), access-control answer leakage was 3/9 (33.33%), active-forgetting answer leakage was 0/9, and the answer-only Memory Governance Score was 44.44%. Because both the model and the 30-item slice differ from the paper's complete matrix, the strict label is **MODEL-SUBSTITUTE / PAPER-BASELINE-METHOD-EXACT**.

For MemSyco, we verified the official OFJ data; the official paired `NoMemory` and `RawDialogue` protocol; and the official task prompt, judge, and scorer. The first gate sample completed all four calls successfully. The formal 50-sample run was not yet complete, so this report does not claim an effect estimate.

### 1.2 Second layer: adding new interventions, controls, and failure audits rather than simply rerunning papers

| Incremental activity | Main focus of the original paper | What we added | Current evidence level |
| --- | --- | --- | --- |
| MemPrivacy linkability attack | Typed placeholders plus local recovery to preserve task semantics while hiding sensitive values | Four identity representations—raw, stable, rotating, and opaque; separate attacks on value recovery, attribute inference, and cross-session linkage; multi-level confidence intervals and paired tests | Empirical increment; method not yet complete |
| MemTrace replay controls | Error tracing, operation attribution, and attribution-guided prompt optimization | Five arms—baseline, byte-identical placebo, correct replacement, length-matched deletion, and length-matched irrelevant replacement—using multiple seeds and common random numbers | Causal signal, but only four cases |
| TRAJECT metric-validity audit | Trajectory structure and trajectory-aware metrics | 28,350 structural perturbations over 5,670 released trajectories to test whether the metric detects edge, type, and ordering errors | Concrete benchmark audit, not a new memory method |
| Lethe candidate-stage failure localization | The effect of placing an LLM at different forgetting control-plane locations | Newly generated, zero-overlap English/Chinese/Japanese data; separate candidate, router, and hook stages; call/quality Pareto accounting | Finer-grained diagnosis; the high-level issue was already studied in the paper |
| Supersede full-lifecycle cost | The accuracy gap of bounded memory on fact-update tasks | 108 budget/span/maintenance-frequency conditions, adding write-side maintenance cost, latency, and utility crossover | Reproduction extension; the high-level result was already studied |
| MemoryAgentBench marginal value | Retrieval, learning, long-horizon understanding, and forgetting in memory systems | Paired no-memory/BM25 comparison; benefit concentration by history; token cost per additional correct answer | Small diagnostic, not a research contribution |

### 1.3 Third layer: stopping directions that did not justify further resource use

- Lethe's original selective router saved only 11.46% of calls on new held-out data, below the 30% gate, so we stopped tuning the same threshold.
- The current oracle-gated MemPrivacy method lost 5.21 percentage points of utility and recovered only 66.7% of the lost utility, missing the ≤3-point and ≥80% gates; the method is therefore NO-GO in its current form.
- On MemoryAgentBench, BM25 produced only two additional correct answers while adding 1,026,651 tokens, failing the preregistered improvement gate.
- TRAJECT's old observable had far below 10% sensitivity to the targeted structural perturbations, so we did not launch the planned 200-item model experiment.
- In the current 108-condition matrix, fixed-character summaries were dominated by full context, so we stopped sweeping 100/150/200/300/400-character budgets.
- The earlier custom LongMemEval, Agent-Native, and MemSyco runs, together with the GateMem shadow adapter, are no longer counted as paper-reproduction evidence.

## 2. The Empirical Evidence We Actually Added

### 2.1 Increment 1: typed placeholders can hide values while strengthening cross-session tracking

The MemPrivacy paper uses semantically typed placeholders. For example, a real email address may be replaced with a stable `<EMAIL_1>` token, and the original value is later recovered locally. The paper primarily evaluates sensitive-information detection and task utility.

We asked a different question: **even if the cloud cannot see the underlying value, can it use a stable placeholder to determine that two sessions belong to the same person?**

The experiment used 48 source blocks, 9 users, and 24 questions from the public MemPrivacy data, with 685 attempts and approximately 1.306 million tokens. The four representations produced the following results:

| Identity representation | Exact value recovery | Attribute inference | Cross-session link balanced accuracy |
| --- | ---: | ---: | ---: |
| Raw identity | 77.08% | 79.17% | 93.75% |
| Stable typed placeholder | 0% | 81.25% | 100% |
| Per-session rotating placeholder | 0% | 89.58% | 50% |
| Opaque session identity | 0% | 62.50% | 54.17% |

The stable-to-rotating linkability difference was 50 percentage points, with McNemar `p=1.19e-7`; the direction was consistent under source-block, question, and user clustering.

The new result is not the generic claim that metadata may leak privacy. It is the more specific observation that:

> **The same de-identification mechanism can reduce exact value recovery to 0% while increasing cross-session linkage to 100%. Value privacy, attribute privacy, and link privacy therefore cannot be collapsed into a single privacy score.**

This is not yet a complete method. The rotating arm's 50% performance mostly came from an attacker that always predicted “different user.” We still need adaptive lexical attacks, multiple independent LLM attackers, and user-disjoint external confirmation.

### 2.2 Increment 2: using five-arm real replay to test whether erroneous evidence has a causal effect

MemTrace can locate erroneous operations, but the paper also explains that its idealized repair is mainly used to define decisive errors. It does not fully roll back and replay every candidate operation, because reconstructing persistent long-horizon state is expensive and downstream modules may still fail.

We froze four mechanically reconstructable retrieval-error cases from the official MemTraceBench release. Each case used five outcome-blind seeds and five experimental arms:

1. retain the original erroneous evidence;
2. use a byte-identical placebo input;
3. replace the error with the correct evidence;
4. delete length-matched content;
5. replace it with length-matched irrelevant content.

Across 100 calls and 500,371 tokens:

- correct replacement versus baseline: F1 `+0.1864`, case-cluster 95% CI `[0.0463, 0.3880]`;
- correct replacement versus length-matched deletion: `+0.1955`;
- correct replacement versus irrelevant replacement: `+0.1882`;
- placebo variation was close to zero;
- all four cases had the same directional effect.

These results suggest that the gain cannot be explained only by shorter context or random generation. However, strict exact match remained zero in every arm. The current result therefore establishes only a small-sample causal signal; it does not show that an automatic repair system has succeeded.

### 2.3 Increment 3: TRAJECT's original observable is almost insensitive to within-structure errors

TRAJECT-Bench presents trajectory-aware metrics. Rather than trusting that label, we tested a basic validity requirement: does the metric change when a necessary dependency edge, type annotation, or execution order is corrupted?

Across 28,350 reproducible perturbations applied to 5,670 released trajectories:

- deleting or inserting dependency edges changed the old routing decision in only 15/1,670 cases, or approximately 0.90%;
- deleting type information changed only 5/5,670 cases, or approximately 0.09%;
- swapping execution order changed no cases;
- yet 29.45% of clean examples were redirected to the conservative strategy.

This is not a vague statement that a benchmark may contain a bug. It is evidence about the construct validity of a specific observable: the observable behaves more like a classifier of broad parallel-versus-sequential structure than a measure of whether dependencies within that structure are correct.

## 3. Which Results Must Not Be Presented as Our Innovations?

### 3.1 Lethe's control-plane placement is not our idea

The title of the [Lethe paper](https://arxiv.org/abs/2606.15903) is *Control-Plane Placement Shapes Forgetting*. It already compares 13 system configurations, different LLM placements, and cross-lingual failure. Our narrower addition is the `candidate-empty` code-path diagnosis and call-cost analysis—not the discovery that control-plane placement matters.

### 3.2 Supersede already identifies the bounded-memory maintenance gap

The [Supersede paper](https://arxiv.org/abs/2606.27472) reports 92% for full context and 77% for bounded memory, attributing the bottleneck to memory maintenance. Our 108-condition matrix adds full-lifecycle cost and Pareto evidence, but we cannot claim to be the first to discover that fixed summaries fail.

The [Agent Memory systems analysis](https://arxiv.org/abs/2606.06448) also separately measures construction, retrieval, and generation cost, and discusses write-side and read-side cost amortization over query volume.

### 3.3 Selective memory invocation is already a crowded direction

[BudgetMem](https://arxiv.org/abs/2602.06025) already performs query-aware budget routing and optimizes the accuracy–cost frontier. AdaMem, TraceRetain, and related work also study conditional retrieval and selective retention. “Some queries do not need memory” is therefore not a new direction. Our 2-of-12 concentration result is only a diagnostic signal about whether further work is justified.

### 3.4 GateMem explicitly does not certify physical deletion

The [GateMem paper](https://arxiv.org/abs/2606.18829) defines irrecoverability at the agent interface; it does not certify physical deletion from databases, vector indexes, caches, summaries, or model parameters. [Deployment-Time Memorization](https://arxiv.org/abs/2606.10062) also studies deletion residue in derived memory tiers.

Our observation of 9/9 context exposures but 0/9 final-answer leaks is a concrete characterization of the official Long-Context baseline, not the first distinction between “not disclosed in the answer” and “actually deleted.”

### 3.5 Counterfactual repair is not an empty field

[MemTrace](https://arxiv.org/abs/2605.28732) studies long-term memory error attribution, while [CausalFlow](https://arxiv.org/abs/2605.25338) applies counterfactual interventions and minimal repair to agent traces. Our potential contribution must therefore focus on the narrower problem they do not complete: **real rollback and replay of persistent long-horizon state, together with matched negative controls that form an auditable causal certificate.**

### 3.6 Benchmark auditing is already an established research area

[Automated Benchmark Auditing](https://arxiv.org/abs/2605.26079) audits 168 benchmarks. Our possible novelty is therefore a reproducible failure analysis of this specific [TRAJECT-Bench](https://github.com/PengfeiHePower/TRAJECT-Bench) observable, not the invention of benchmark auditing.

## 4. The Most Honest Accounting of This Week's Contributions

| Type | Count | Deliverable this week |
| --- | ---: | --- |
| Released-result recomputations | 3 | Lethe, Engram, TokenPilot |
| Method-preserving, model-substituted baseline | 1 | GateMem Long-Context, 30 checkpoints |
| Narrow empirical increments with research potential | 2 | MemPrivacy linkability attack; MemTrace five-arm real replay |
| Concrete benchmark audit | 1 | TRAJECT structural-perturbation sensitivity |
| Engineering/failure-localization increments | 2 | Lethe `candidate-empty`; Supersede full-lifecycle cost matrix |
| Complete new methods | 0 | Not yet completed |
| Complete, submission-ready conclusions | 0 | Multi-dataset validation, strong baselines, and external confirmation are still missing |

It would therefore be inaccurate to claim that we produced seven new findings, but it would also be inaccurate to say that nothing was done. The precise statement is:

> **We completed a reproduction-and-evidence-screening stage, producing two research gaps that may support new methods and one concrete evaluation gap; duplicated or crowded directions were downgraded or stopped.**

## 5. Incremental Experiments Now Underway

### 5.1 Task-Scoped Unlinkable Memory

The research question is not how to mask more information. It is:

> How can cross-session records remain unlinkable by default, while restoring only the minimum identity continuity that an authorized task actually requires?

First-round design:

- public MemPrivacy/PersonaMem or other public cross-session data;
- user-disjoint calibration and confirmation sets;
- four arms: raw, stable typed, rotating session alias, and task-scoped non-oracle reveal;
- a lexical attacker plus at least two independent LLM attackers;
- joint Pareto analysis of value leakage, attribute inference, linkability, task utility, and tokens;
- no oracle use of the correct evidence to decide when identity continuity should be restored.

GO criterion: the linkability reduction must survive adaptive attackers; utility loss must be no more than 3 percentage points; and task recovery must be at least 80%.

### 5.2 Stateful Counterfactual Replay Certification

The research question is not whether an error can be located. It is:

> Can a system perform minimal rollback and real replay over persistent long-horizon memory, and use negative controls to show that the repair caused downstream task recovery?

First-round design:

- freeze 20–30 official MemTraceBench retrieval-error cases;
- use an automatic detector/editor rather than manually supplying the correct answer;
- use at least three outcome-blind seeds and common random numbers;
- use strict task success as the primary metric, with F1, repair precision, and replay cost as secondary metrics.

GO criterion: the lower confidence bound for strict accuracy improvement must be above zero, and repair must significantly outperform length-matched deletion and irrelevant replacement.

### 5.3 TRAJECT Observable Validity Confirmation

The research question is not whether we can produce another scorer. It is:

> Can a change in a trajectory metric predict an actual tool-execution failure?

The first round uses only an offline gate over public data. It holds the broad parallel/sequential class constant while changing necessary dependencies, parameter dataflow, and tool-order executability. It then compares the original observable with at least two new candidates for monotonic sensitivity, before testing whether metric changes correspond to real execution failures on a public executable subset. If the validity gate fails, the direction stops without a model call.

## 6. Resource Ledger for the Week

The original five-line confirmation experiments completed 1,178 real calls through the authorized local proxy and used 3,126,042 tokens. The corrected GateMem run added 60 calls and 211,223 tokens; the MemSyco gate added 4 calls and 4,364 tokens. The independently auditable ledgers therefore total at least 1,242 calls and approximately 3.342 million tokens.

All formal experiments:

- use only public benchmarks or public research data;
- make zero calls to official metered APIs;
- make zero `gpt-5.6` calls;
- retain sample IDs, actual models, calls/tokens, persistent outputs, and reproducible scorers;
- do not compare a result directly with a paper table when the model, data, method, slice, or scorer differs.

## 8. Technical Attachments

- [Complete data from the first-round five-line confirmation experiments](./round1_followup_results_20260728.md)
- [Per-paper baseline comparison matrix](./baseline_replication_matrix_20260728.md)
- [Research proposal roadmap](./research_proposal_roadmap_20260728.md)
- [Next-stage investment and stopping criteria](./investment_decision_20260728.md)
