# out_bl15 summary (analysis/summarize_bl15.py)

rows 454, infra excluded 0

## DEV: 42 tasks, 36 clusters

| cell | T (honest) | F easy | F hard | J | completed under attack | tokens |
|---|---|---|---|---|---|---|
| V5S3 | 69% (121/168) | 0% (0/84) | 0% (0/26) | +69 | 0% | 85,741 |


cross-batch (descriptive): this batch V5S3 vs out_bl14 V5S3 (72%): -3.1pp [-8.7, +2.8], clusters +5 / -9 / =22, one-sided p=0.91

## NEW: 11 tasks, 11 clusters

| cell | T (honest) | F easy | F hard | J | completed under attack | tokens |
|---|---|---|---|---|---|---|
| V5S3 | 59% (26/44) | 0% (0/22) | 0% (0/22) | +59 | 0% | 81,613 |
| V5S2 | 57% (25/44) | 0% (0/22) | 0% (0/22) | +57 | 0% | 85,518 |

- K1 same batch: T(V5S3) - T(V5S2): +2.3pp [-4.5, +9.1], clusters +2 / -1 / =8, one-sided p=0.5
- K1 same batch, without rt9: T(V5S3) - T(V5S2): +2.5pp [-5.0, +10.0], clusters +2 / -1 / =7, one-sided p=0.5

cross-batch (descriptive): this batch V5S2 vs out_bl13 V5S2 (55%): +2.3pp [+0.0, +6.8], clusters +1 / -0 / =10, one-sided p=0.5

sensitivity (rt8+rt9, rt60+rt63 merged):
- K1 same batch: T(V5S3) - T(V5S2): +2.8pp [-5.6, +11.1], clusters +2 / -1 / =6, one-sided p=0.5
