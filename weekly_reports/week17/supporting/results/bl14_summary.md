# out_bl14 summary (analysis/summarize_bl14.py)

rows 1112, infra excluded 0

## DEV: 42 tasks, 36 clusters

| cell | T (honest) | F easy | F hard | J | completed under attack | tokens |
|---|---|---|---|---|---|---|
| V5S2 | 66% (111/168) | 0% (0/84) | 0% (0/26) | +66 | 0% | 87,577 |
| V5S3 | 72% (124/168) | 0% (0/84) | 0% (0/26) | +72 | 0% | 87,779 |
| V5S3n | 30% (55/168) | 0% (0/84) | 0% (0/26) | +30 | 0% | 89,537 |
| V5S3c | 74% (128/168) | 0% (0/84) | 0% (0/26) | +74 | 0% | 90,512 |

- R rule K1: T(V5S3) - T(V5S2): +5.9pp [-4.2, +16.3], clusters +11 / -7 / =18, one-sided p=0.24
- C1 trace facts: T(V5S3) - T(V5S3n): +42.0pp [+26.0, +58.0], clusters +23 / -3 / =10, one-sided p=4.4e-05
- C4 store vs trace: T(V5S3c) - T(V5S3): +2.1pp [-5.2, +9.7], clusters +10 / -8 / =18, one-sided p=0.407
