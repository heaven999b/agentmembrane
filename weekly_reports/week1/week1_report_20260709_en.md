# Week 1 Technical Update

**Date:** July 9, 2026<br>
**Companion files:**<br>
- [week1_metric_and_parameter_guide.md](./week1_metric_and_parameter_guide.md)<br>
- [week1_artifact_index.md](./week1_artifact_index.md)<br>
- [supporting_materials/README.md](./supporting_materials/README.md)

**Primary source files used for this summary:**<br>
- `supporting_materials/rq_progress_summary_by_plan_20260709.md`<br>
- `supporting_materials/OPERATOR_GUIDE.md`

## Scope And Evaluation Pipeline

Week 1 used one shared pipeline:

1. Build a memory scenario from benchmark slices or self-built safety/dialogue suites.
2. Run either `prompt_only` or TierMem with iterative consolidation depth `N`.
3. Ask the downstream action or factual question.
4. Score the final answer with a **negation-aware LLM judge** as the primary endpoint.

Lexical metrics were kept only as secondary audits because they repeatedly overstated both risk and defense success. The main settings were `prompt_only`, TierMem `summary_only`, older TierMem `auto`, and read-time policy-priority defense.

The copied tables, CSVs, and dashboards behind these claims are bundled under `supporting_materials/` so the report can be reviewed without browsing the whole repository.

## RQ Status Summary

| RQ | Data source | Method | Current finding | Status |
| --- | --- | --- | --- | --- |
| **RQ1** Unsafe retention / amplification | `unsafe_seed_suite_v1` (12), `stealthy_poison_suite_v1` (30), `agentpoison_trigger_suite_v1` (100) | `prompt_only` vs TierMem, `N=0/1/2/4/8`, judge-first scoring | Strong original claim **not supported**; `prompt_only` was often worst. | Mostly complete |
| **RQ2** False memory / hallucination | Official HaluMem (15-QA tight-budget, 45-QA expanded) + self-built 100-item dialogue suite | TierMem `summary_only`, `N=0/1/2/4`; judge labels + `FALSE_BELIEF` | Official line is negative; self-built line supports only a weak false-belief claim. | Partial |
| **RQ3** Provenance defense | 30-item read-time defense set; 5-seed large run | Old `auto` vs `summary_only`; new read-time policy-priority defense, `prompt_only` and TierMem `N=0/1/2` | Old line weak; new read-time defense is the main positive intervention result so far. | Partial |
| **RQ4** Operator comparison | No complete multi-operator dataset | Would require TierMem vs COMEDY / Context-Memory / NeedSleep / E-mem | No defensible result yet. | Not done |
| **RQ5** Failure stage diagnosis | 30 know-do items, 3 OpenAI models | Same memory, ask for policy vs action | Strong support for a reader-side know-do gap. | Strong |

## Key Results

### RQ1: Consolidation is not the main hazard

In the main authority-style safety setup, unsafe payload emission was `15/15 = 1.000` for `prompt_only`, versus `13/15 = 0.867` at TierMem `N=0` and `11/15 = 0.733` at `N=2`. This does **not** support the claim that deeper consolidation amplifies unsafe behavior.

### RQ2: Official benchmark line is negative; self-built line is weaker and mixed

On official HaluMem, unsupported fabrication on unknown questions dropped from `0.333` at `N=0` to `0.167` on the 15-QA tight-budget line, and to `0.083` on the 45-QA line. The benchmark therefore does not show “deeper consolidation causes more hallucination.”<br>

On the self-built 100-item dialogue suite, `FALSE_BELIEF` was `0.060` for `prompt_only`, `0.105` at TierMem `N=0`, then `0.035` at `N=1` and `0.025` at `N=2`. The supported claim is weaker: repeated misinformation can create false belief, but not in a monotonic depth-driven way.

### RQ3: Read-time defense is promising but incomplete

The older provenance route (`auto` vs `summary_only`) did not produce a stable positive story. The new read-time defense did: risky-action rates dropped from `94.0% -> 80.0%` for `prompt_only`, `88.3% -> 76.7%` at TierMem `N=0`, `86.7% -> 77.5%` at `N=1`, and `88.3% -> 74.2%` at `N=2`. This is the strongest intervention result so far, but the utility side is still open.

### RQ5: The strongest supported finding is the know-do gap

Across three models, the know-do gap was `0.633` for `gpt-4.1-mini`, `0.467` for `gpt-4o`, and `0.367` for `gpt-4.1`, while `doesnt_know = 0.000` in all cases. The model can state the policy correctly but still chooses the unsafe action, so the failure is primarily **behavioral and reader-side**.

## Main Takeaways

- **The original “deeper consolidation is the main safety hazard” story is not supported.**
- **Endpoint definition can flip the conclusion**: soft compliance labels can make a failed defense look successful.
- **The current best positive result is reader-side**: agents often know the rule but still act against it.
- **The most promising intervention is read-time policy prioritization**, but it still needs utility-side closure.
