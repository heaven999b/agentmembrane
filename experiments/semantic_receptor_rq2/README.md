# Canonical RQ2 semantic-receptor baseline

This directory is the executable baseline for the canonical proposal construct
`semantic_receptor_expressiveness`. It is intentionally outside
`experiments/host_boundary_v2`: the six Host-action mechanisms are RQ1b and must
not be pooled with this experiment.

Read `PROTOCOL.md` before changing code, prompts, thresholds, models, or data.
Post-pilot measurement revisions are specified separately in
`CALIBRATION_V2_PLAN.md`; they do not retroactively alter protocol v1 or its run.
Aggregate-only public reports for the strict run, staged audits, and neutral-P0
calibration are collected in
[`results/semantic_rq2_calibration_20260831/`](../../results/semantic_rq2_calibration_20260831/README.md).
Per-case records, ContractNLI text, raw model calls, and caches stay local.

The next unseen-sample engineering round is frozen in
[`HELDOUT_50_CONFIRMATORY_PROTOCOL.md`](HELDOUT_50_CONFIRMATORY_PROTOCOL.md). It
uses 25 document clusters with zero overlap with calibration, seed `20260901`,
the preregistered source-fidelity audit, and neutral P0 as the primary downstream
view. This held-out round remains `claim_bearing=false` because it is one seed,
one model family, and only 25 independent clusters.
The completed result and the next-round design are in
[`results/semantic_rq2_heldout_20260901/`](../../results/semantic_rq2_heldout_20260901/HELDOUT_CONFIRMATORY_REPORT.md).

## Zero-token setup and checks

```bash
python3 -m agentmembrane.semantic_rq2 build-manifest \
  --split data/official/contract-nli/test.json \
  --license data/official/contract-nli/LICENSE \
  --output experiments/semantic_receptor_rq2/manifests/contractnli_test_200_seed20260831.json

python3 -m agentmembrane.semantic_rq2 validate-manifest \
  --manifest experiments/semantic_receptor_rq2/manifests/contractnli_test_200_seed20260831.json \
  --split data/official/contract-nli/test.json

python3 -m agentmembrane.semantic_rq2 preflight \
  --manifest experiments/semantic_receptor_rq2/manifests/contractnli_test_200_seed20260831.json \
  --profile experiments/semantic_receptor_rq2/profiles/engineering_baseline.json

python3 -m unittest discover -s tests/semantic_rq2 -v
```

The included profile is engineering-only. It does not authorize a model run and
cannot pass `--formal`; formal execution additionally requires two downstream
model families, a cross-family generator, a third-family auditor, and passed human
audit calibration.

Build and preflight the held-out engineering manifest without a model call:

```bash
python3 -m agentmembrane.semantic_rq2 build-heldout-manifest \
  --parent-manifest experiments/semantic_receptor_rq2/manifests/contractnli_test_200_seed20260831.json \
  --exclude-manifest experiments/semantic_receptor_rq2/manifests/contractnli_test_50_seed20260831_calibration.json \
  --output experiments/semantic_receptor_rq2/manifests/contractnli_test_50_seed20260901_heldout.json \
  --documents 25 \
  --seed 20260901

python3 -m agentmembrane.semantic_rq2 preflight \
  --manifest experiments/semantic_receptor_rq2/manifests/contractnli_test_50_seed20260901_heldout.json \
  --profile experiments/semantic_receptor_rq2/profiles/engineering_confirmatory_v2.json
```

## Execution shape

One run uses one frozen seed. Three run directories are required for the three
pre-registered seeds. The runner globally finishes and freezes generation plus
blind audit before starting downstream evaluation. Every case is a complete paired
block containing evidence-only, ceiling, and honest/attack R0--R4 arms.

```bash
python3 -m agentmembrane.semantic_rq2 run \
  --manifest experiments/semantic_receptor_rq2/manifests/contractnli_test_200_seed20260831.json \
  --profile experiments/semantic_receptor_rq2/profiles/engineering_baseline.json \
  --seed 20260831 \
  --run-dir outputs/semantic_rq2_engineering_seed20260831
```

Do not run that command merely to test plumbing: it makes real model calls. Unit
tests use scripted roles and make zero network/model calls.

To reproduce the post-pilot broad-rubric sensitivity analysis without changing
the frozen artifacts or downstream decisions:

```bash
python3 -m agentmembrane.semantic_rq2 reaudit-sensitivity \
  --manifest experiments/semantic_receptor_rq2/manifests/contractnli_test_50_seed20260831_calibration.json \
  --profile experiments/semantic_receptor_rq2/profiles/engineering_baseline.json \
  --source-run-dir outputs/semantic_rq2_gpt_50case_20260831_r1 \
  --output-dir outputs/semantic_rq2_relaxed_reaudit_50case_20260831_r1 \
  --seed 20260831
```

This command makes real auditor calls on a cache miss. Its output is explicitly
post-pilot and non-claim-bearing; it never relabels the strict result in place.

The intermediate audit retains all strict-valid rows and focuses only on eligible
R3/R4 strict failures:

```bash
python3 -m agentmembrane.semantic_rq2 reaudit-intermediate \
  --manifest experiments/semantic_receptor_rq2/manifests/contractnli_test_50_seed20260831_calibration.json \
  --profile experiments/semantic_receptor_rq2/profiles/engineering_baseline.json \
  --source-run-dir outputs/semantic_rq2_gpt_50case_20260831_r1 \
  --output-dir outputs/semantic_rq2_intermediate_reaudit_50case_20260831_r2 \
  --seed 20260831
```

The neutral-P0 calibration reuses frozen artifacts and changes only the visible
provenance warning. Run the 20-case canary before the 50-case extension:

```bash
python3 -m agentmembrane.semantic_rq2 calibrate-neutral-p0 \
  --manifest experiments/semantic_receptor_rq2/manifests/contractnli_test_50_seed20260831_calibration.json \
  --profile experiments/semantic_receptor_rq2/profiles/engineering_baseline.json \
  --source-run-dir outputs/semantic_rq2_gpt_50case_20260831_r1 \
  --validity-stage-dir outputs/semantic_rq2_omission_reaudit_50case_20260831_r1 \
  --output-dir outputs/semantic_rq2_neutral_p0_20case_20260831_r1 \
  --seed 20260831 \
  --max-cases 20
```

After all three frozen seed runs finish, aggregate them without treating seeds as
independent documents:

```bash
python3 -m agentmembrane.semantic_rq2 aggregate-seeds \
  --records outputs/semantic_rq2_seed20260831/records.jsonl \
            outputs/semantic_rq2_seed20260901/records.jsonl \
            outputs/semantic_rq2_seed20260902/records.jsonl \
  --output outputs/semantic_rq2_three_seed_analysis.json
```
