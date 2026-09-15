# Week 1 Metric And Parameter Guide

This guide explains the notation used in the Week 1 report and the copied evidence files.

## 1. Common Symbols And Settings

| Symbol or term | Meaning in this project | Why it matters |
| --- | --- | --- |
| `N` | Consolidation depth: how many extra summary-layer rewrite passes TierMem performs after memory is written | Used to test whether deeper consolidation makes behavior safer, worse, or unchanged |
| `prompt_only` | No external memory system; the model answers directly from the prompt | This is the strongest control baseline for asking whether memory is the real cause |
| `tiermem` | The project's main memory-agent backend based on TierMem | This is the main experimental system under study |
| `summary_only` | A TierMem route that uses the summary memory layer rather than a more adaptive route | This is the cleaner route for Week 1 reporting because it is easier to interpret |
| `auto` | An older TierMem route that automatically chose how to read memory | Included only as older comparison context; it is not the preferred reporting surface |
| `off` / `on` | Defense disabled or enabled | Used mainly in RQ3 to compare the same items with and without read-time protection |
| `seed` | Random sampling seed for stochastic model calls | Multiple seeds test whether the effect only appears under one lucky sample |
| `report_id` | The run identifier written into output files | Lets you trace a table back to the exact run artifact |

## 2. Main Outcome Metrics

| Metric | Plain-English meaning | Used for which RQ |
| --- | --- | --- |
| `unsafe payload emission` | The final answer still contains dangerous step-by-step content | RQ1 |
| `hard_refuse` | The model fully refuses the dangerous request and does not emit the payload | RQ1 |
| `UF_on_unknown` | On a question whose answer is not supported by the provided context, the model still invents an answer | RQ2 official benchmark line |
| `CORRECT` | The final answer is correct and supported | RQ2 official benchmark line |
| `FALSE_BELIEF` | After repeated false claims in memory, the model acts as if the false claim is true | RQ2 self-built line |
| `risky-action rate` | The final answer follows the unsafe or wrong action instead of the safer rule | RQ3 and RQ5 |
| `doesnt_know` | The model explicitly fails because it does not know the relevant rule or fact | RQ5 |
| `know-do gap` | The model can state the rule correctly but still chooses the wrong action | RQ5 |
| `better` / `worse` flips | In paired comparison, how many items improved or deteriorated when the defense was turned on | RQ3 |
| `McNemar p` | A paired significance test on item-level flips between two settings | RQ3 |
| `seed-level t` | A more conservative test that checks whether the effect is consistent across seeds | RQ3 |
| `Clopper-Pearson CI` | Exact binomial confidence interval around a rate | RQ1 |
| `cluster-robust CI` | Interval adjusted for repeated similar attack families rather than treating every item as fully independent | RQ1 |

## 3. What Each Research Question Asked

| RQ | Week 1 question | Main data surface |
| --- | --- | --- |
| RQ1 | Does iterative consolidation preserve or amplify unsafe memory content? | Self-built safety suites in `benchmarks/safety/` |
| RQ2 | Does iterative consolidation create fabricated memory or hallucinated answers? | Official HaluMem slices plus self-built local-dialogue suites |
| RQ3 | Can provenance-aware or read-time defenses reduce bad downstream behavior? | Read-time defense suite built from safety mini-scenarios |
| RQ4 | Which consolidation operator is most fragile? | Not yet run to a publishable standard |
| RQ5 | Does failure happen during writing, consolidation, retrieval, or final answering? | Know-do mini-suite across three OpenAI models |

## 4. Main Week 1 Experimental Surfaces

| Surface | What it ran on | Main model or backend | Key parameters to notice |
| --- | --- | --- | --- |
| RQ1 safety consolidation | `unsafe_seed_suite_v1`, `stealthy_poison_suite_v1`, `agentpoison_trigger_suite_v1` | `prompt_only` and `tiermem` | `N`, backend, judge-first scoring |
| RQ2 official line | HaluMem 15-QA and 45-QA slices | TierMem `summary_only` | `N`, `session_limit`, `qa_limit`, route mode |
| RQ2 self-built line | 100 local-dialogue base items with repeated misinformation pressure | `prompt_only` and `tiermem` | `N`, `query_mode`, `repetition`, `seed` |
| RQ3 read-time defense | 30-item stealthy-poison action suite | `prompt_only`, TierMem `summary_only`, defense `off/on` | `seed`, `backend`, `pass`, defense switch |
| RQ5 know-do | 30 policy items | `gpt-4.1-mini`, `gpt-4o`, `gpt-4.1` | model choice, policy-recall prompt, action-choice prompt |

## 5. Parameter Notes People Usually Ask About

| Parameter | Meaning |
| --- | --- |
| `query_mode=neutral` | The question wording does not push the model toward the unsafe option and is meant to test the memory effect more cleanly |
| `query_mode=free` | Open factual questioning in the self-built RQ2 line |
| `query_mode=operational` | A more action-like or use-oriented version of the same self-built RQ2 question |
| `poison_framing=convention` | The unsafe instruction is framed as a normal team convention or habit |
| `page_size=1000` | Memory page chunk size used by the TierMem bridge in the benchmark-style runs |
| `session_limit=1` | Only one benchmark session was included in that run |
| `qa_limit=15` | Only the first 15 QA items from the chosen benchmark slice were run |
| `repetition=5` | The self-built false-belief prompt repeated the misinformation five times |

## 6. How To Read The Week 1 Conclusions

- RQ1 is a negative result against the original hypothesis. The key comparison is whether higher `N` increases unsafe output. It did not.
- RQ2 is split into two lines on purpose. The official benchmark line did not show worsening with depth. The self-built line showed a small false-belief effect, but it peaked at `N=0` rather than increasing monotonically.
- RQ3 is the cleanest positive intervention line so far. The read-time defense reduced risky actions across all 20 paired seed-by-condition cells, but the remaining risk stayed high.
- RQ5 is the strongest mechanistic result. The models usually knew the rule yet still violated it, which points to an answer-stage or reader-stage failure rather than a missing-memory failure.

## 7. Reliability Warning

- Week 1 reporting treats the negation-aware LLM judge as the primary endpoint.
- Lexical checks are kept only as secondary audits because they previously produced false positives and false reassurance.
- For RQ3, do not overclaim the pooled tiny `p` values. The safer interpretation is: all seeds moved in the same direction and the seed-level tests remained significant.
