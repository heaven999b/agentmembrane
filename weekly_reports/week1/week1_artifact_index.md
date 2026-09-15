# Week 1 Artifact Index

This file maps each copied supporting artifact to the research question it supports, the data or benchmark it was run on, and what the reader should look for inside it.

## RQ1: Unsafe Retention Or Amplification

| Artifact | Supports | What it ran on | What to look for |
| --- | --- | --- | --- |
| [supporting_materials/rq_progress_summary_by_plan_20260709.md](./supporting_materials/rq_progress_summary_by_plan_20260709.md) | Overall RQ1 status | Self-built safety suites | The RQ1 section explains the intended metrics, the current conclusion, and the remaining gap at deep `N` |
| [supporting_materials/safety_axis_honest_final_20260704.md](./supporting_materials/safety_axis_honest_final_20260704.md) | Historical RQ1 audit | Self-built safety axis | Earlier RQ1 adjudication notes and why later judge-based scoring mattered |
| [supporting_materials/rq1_agentpoison_full100_judged_honest.md](./supporting_materials/rq1_agentpoison_full100_judged_honest.md) | Honest endpoint table | 100-item AgentPoison-style trigger suite | Compare `payload_emission` across `N=0/1/2`; this is the cleanest table for whether deeper consolidation worsened danger |

## RQ2: False Memory Or Hallucination

| Artifact | Supports | What it ran on | What to look for |
| --- | --- | --- | --- |
| [supporting_materials/rq2_dual_track_refresh_20260708.md](./supporting_materials/rq2_dual_track_refresh_20260708.md) | Dual-track RQ2 summary | Official HaluMem slices plus self-built local-dialogue suite | This is the best single comparison between the official and self-built RQ2 lines |
| [supporting_materials/e1_halumem_tightbudget_rerun_20260708.md](./supporting_materials/e1_halumem_tightbudget_rerun_20260708.md) | Official benchmark rerun notes | HaluMem tight-budget slice | Look for the `UF_on_unknown` and `CORRECT` trend across `N` |
| [supporting_materials/fidelity_reliability_audit_20260709.md](./supporting_materials/fidelity_reliability_audit_20260709.md) | Reliability caveats | Mixed RQ2 evaluation surfaces | Use this when explaining why judge-based endpoints were kept primary |

## RQ3: Read-Time Defense And Provenance

| Artifact | Supports | What it ran on | What to look for |
| --- | --- | --- | --- |
| [supporting_materials/rq3_readtime_defense_large_run_spec_20260708.md](./supporting_materials/rq3_readtime_defense_large_run_spec_20260708.md) | Pre-registered run setup | 30-item stealthy-poison defense suite | The exact condition grid, seeds, and decision rule for the large run |
| [supporting_materials/rq3_readtime_large_20260708_interpretation.md](./supporting_materials/rq3_readtime_large_20260708_interpretation.md) | Main RQ3 interpretation | Same 30-item suite, 5 seeds, defense off vs on | This is the clearest plain-language adjudication of whether the defense worked |
| [supporting_materials/rq3_readtime_large_20260708_summary.md](./supporting_materials/rq3_readtime_large_20260708_summary.md) | Human-readable result table | Same large run | Contains the compact summary table cited in the report |
| [supporting_materials/rq3_readtime_large_20260708_condition_summary.csv](./supporting_materials/rq3_readtime_large_20260708_condition_summary.csv) | Per-condition numeric table | Same large run | Use when you need exact off/on means by backend and pass |
| [supporting_materials/rq3_readtime_large_20260708_paired_summary.csv](./supporting_materials/rq3_readtime_large_20260708_paired_summary.csv) | Paired flip statistics | Same large run | Use for `better`, `worse`, and the paired significance columns |
| [supporting_materials/rq3_readtime_large_20260708_dashboard.html](./supporting_materials/rq3_readtime_large_20260708_dashboard.html) | Visual dashboard | Same large run | Open in a browser to inspect condition-level plots interactively |
| [supporting_materials/rq3_readtime_large_20260708_dashboard_data.json](./supporting_materials/rq3_readtime_large_20260708_dashboard_data.json) | Dashboard source data | Same large run | Machine-readable input behind the HTML dashboard |

## RQ5: Failure Stage And Know-Do Gap

| Artifact | Supports | What it ran on | What to look for |
| --- | --- | --- | --- |
| [supporting_materials/rq_progress_summary_by_plan_20260709.md](./supporting_materials/rq_progress_summary_by_plan_20260709.md) | Overall RQ5 status | 30-item know-do suite across three OpenAI models | The RQ5 section states the core result: the models knew the policy but still violated it |
| [supporting_materials/OPERATOR_GUIDE.md](./supporting_materials/OPERATOR_GUIDE.md) | Reproduction instructions | The same know-do and safety pipelines | The `run_rq_know_vs_do.py` section explains how the main know-do outputs were produced |

## Cross-RQ Orientation Files

| Artifact | Role | Why it is here |
| --- | --- | --- |
| [supporting_materials/OPERATOR_GUIDE.md](./supporting_materials/OPERATOR_GUIDE.md) | Project-wide runbook | Best single file for a technical reader who wants to reproduce the runs |
| [supporting_materials/rq_progress_summary_by_plan_20260709.md](./supporting_materials/rq_progress_summary_by_plan_20260709.md) | Master internal progress note | Best single file for understanding what is complete, partial, or still missing |

## Raw Repository Outputs Still Live Outside This Folder

- The full machine outputs remain in `outputs/` because duplicating every JSON file into `weekly_reports/` would make the handoff package noisy.
- The copied files here are the curated Week 1 evidence surface: human-readable summaries, CSV tables, and the main dashboard source.
