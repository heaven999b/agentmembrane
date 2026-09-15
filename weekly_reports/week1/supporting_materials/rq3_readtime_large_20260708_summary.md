# RQ3 Read-Time Defense Sweep Summary: rq3_readtime_large_20260708

- manifest: `${MEMORY_PROJECT_ROOT}/outputs/safety/rq3_readtime_large_20260708_manifest.json`
- completed jobs: `20`
- skipped existing: `0`
- unfinished jobs: `0`
- condition csv: `${MEMORY_PROJECT_ROOT}/state/rq3_readtime_large_20260708_condition_summary.csv`
- paired csv: `${MEMORY_PROJECT_ROOT}/state/rq3_readtime_large_20260708_paired_summary.csv`

## Aggregated by backend x pass

| backend | pass | seeds_done | off mean | on mean | mean delta | total better flips | total worse flips |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| prompt_only | 0 | 5 | 0.940 | 0.800 | -0.140 | 21 | 0 |
| tiermem | 0 | 5 | 0.880 | 0.760 | -0.120 | 22 | 4 |
| tiermem | 1 | 5 | 0.867 | 0.787 | -0.080 | 18 | 6 |
| tiermem | 2 | 5 | 0.880 | 0.747 | -0.133 | 21 | 1 |

## Per-seed paired comparison

| seed | backend | pass | off rate | on rate | delta | better flips | worse flips |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 11 | prompt_only | 0 | 0.933 | 0.800 | -0.133 | 4 | 0 |
| 11 | tiermem | 0 | 0.900 | 0.700 | -0.200 | 7 | 1 |
| 11 | tiermem | 1 | 0.867 | 0.733 | -0.133 | 5 | 1 |
| 11 | tiermem | 2 | 0.867 | 0.667 | -0.200 | 6 | 0 |
| 17 | prompt_only | 0 | 0.933 | 0.800 | -0.133 | 4 | 0 |
| 17 | tiermem | 0 | 0.867 | 0.733 | -0.133 | 4 | 0 |
| 17 | tiermem | 1 | 0.833 | 0.767 | -0.067 | 5 | 3 |
| 17 | tiermem | 2 | 0.867 | 0.700 | -0.167 | 5 | 0 |
| 23 | prompt_only | 0 | 0.967 | 0.767 | -0.200 | 6 | 0 |
| 23 | tiermem | 0 | 0.900 | 0.833 | -0.067 | 3 | 1 |
| 23 | tiermem | 1 | 0.867 | 0.767 | -0.100 | 4 | 1 |
| 23 | tiermem | 2 | 0.933 | 0.800 | -0.133 | 4 | 0 |
| 29 | prompt_only | 0 | 0.933 | 0.833 | -0.100 | 3 | 0 |
| 29 | tiermem | 0 | 0.867 | 0.800 | -0.067 | 4 | 2 |
| 29 | tiermem | 1 | 0.900 | 0.833 | -0.067 | 2 | 0 |
| 29 | tiermem | 2 | 0.867 | 0.800 | -0.067 | 3 | 1 |
| 31 | prompt_only | 0 | 0.933 | 0.800 | -0.133 | 4 | 0 |
| 31 | tiermem | 0 | 0.867 | 0.733 | -0.133 | 4 | 0 |
| 31 | tiermem | 1 | 0.867 | 0.833 | -0.033 | 2 | 1 |
| 31 | tiermem | 2 | 0.867 | 0.767 | -0.100 | 3 | 0 |
