# out_bl13 summary (analysis/summarize_bl13.py)

rows 2196, infra excluded 0

## DEV: 42 tasks, 36 clusters

| cell | T (honest) | F easy | F hard | J | completed under attack | tokens |
|---|---|---|---|---|---|---|
| V5S2 | 67% (114/168) | 0% (0/84) | 0% (0/26) | +67 | 0% | 86,115 |
| V5S2P | 68% (116/168) | 0% (0/84) | 0% (0/26) | +68 | 0% | 94,813 |
| NEW5S | 92% (155/168) | 0% (0/84) | 0% (0/26) | +92 | 78% | 86,409 |
| V5b | 47% (82/168) | 1% (1/84) | 0% (0/26) | +45 | 0% | 85,106 |
| Ecode | 62% (105/168) | 0% (0/84) | 0% (0/26) | +62 | 0% | 92,566 |
| MRp | 75% (126/168) | 1% (1/84) | 8% (2/26) | +73 | 0% | 76,913 |

- C1 trace: T(V5S2) - T(V5b): +20.8pp [+8.7, +33.7], clusters +16 / -4 / =16, one-sided p=0.00591
- C2 J(V5S2) - J(MRp): -5.9pp [-18.1, +5.2], clusters +11 / -9 / =16, one-sided p=0.412
- C2 T(V5S2) - T(MRp): -7.3pp [-19.4, +3.8], clusters +10 / -10 / =16, one-sided p=0.588
- C2 F hard(V5S2) - F hard(MRp): -8.3pp [-20.8, +0.0], clusters +0 / -2 / =10, one-sided p=1
- C2 J(V5S2) - J(Ecode): +5.2pp [-6.9, +17.4], clusters +15 / -9 / =12, one-sided p=0.154
- C2 T(V5S2) - T(Ecode): +5.2pp [-6.9, +17.4], clusters +15 / -9 / =12, one-sided p=0.154
- C2 F hard(V5S2) - F hard(Ecode): +0.0pp [+0.0, +0.0], clusters +0 / -0 / =12, one-sided p=1
- C3 T(V5S2P) - T(V5S2): +0.7pp [-5.6, +7.3], clusters +8 / -8 / =20, one-sided p=0.598
- ref T(NEW5S) - T(V5S2): +24.7pp [+13.5, +36.8], clusters +16 / -2 / =18, one-sided p=0.000656
- C3 non-inferior at -5pp: False

## NEW: 11 tasks, 11 clusters

| cell | T (honest) | F easy | F hard | J | completed under attack | tokens |
|---|---|---|---|---|---|---|
| V5S2 | 55% (24/44) | 0% (0/22) | 0% (0/22) | +55 | 0% | 84,389 |
| V5S2P | 59% (26/44) | 0% (0/22) | 0% (0/22) | +59 | 0% | 92,292 |
| NEW5S | 77% (34/44) | 0% (0/22) | 0% (0/22) | +77 | 82% | 78,572 |
| V5b | 9% (4/44) | 0% (0/22) | 0% (0/22) | +9 | 0% | 92,362 |
| Ecode | 50% (22/44) | 5% (1/22) | 5% (1/22) | +45 | 0% | 91,942 |
| MRp | 64% (28/44) | 9% (2/22) | 9% (2/22) | +55 | 0% | 73,078 |

- C1 trace: T(V5S2) - T(V5b): +45.5pp [+18.2, +72.7], clusters +6 / -0 / =5, one-sided p=0.0156
- C2 J(V5S2) - J(MRp): +0.0pp [-27.3, +25.0], clusters +3 / -3 / =5, one-sided p=0.656
- C2 T(V5S2) - T(MRp): -9.1pp [-31.8, +11.4], clusters +2 / -3 / =6, one-sided p=0.812
- C2 F hard(V5S2) - F hard(MRp): -9.1pp [-22.7, +0.0], clusters +0 / -2 / =9, one-sided p=1
- C2 J(V5S2) - J(Ecode): +9.1pp [-27.3, +43.2], clusters +5 / -3 / =3, one-sided p=0.363
- C2 T(V5S2) - T(Ecode): +4.5pp [-27.3, +34.1], clusters +5 / -3 / =3, one-sided p=0.363
- C2 F hard(V5S2) - F hard(Ecode): -4.5pp [-13.6, +0.0], clusters +0 / -1 / =10, one-sided p=1
- C3 T(V5S2P) - T(V5S2): +4.5pp [+0.0, +11.4], clusters +2 / -0 / =9, one-sided p=0.25
- ref T(NEW5S) - T(V5S2): +22.7pp [-6.8, +54.5], clusters +4 / -3 / =4, one-sided p=0.5
- C3 non-inferior at -5pp: True

sensitivity (rt8+rt9, rt60+rt63 merged):
- C1 trace: T(V5S2) - T(V5b): +44.4pp [+19.4, +69.4], clusters +6 / -0 / =3, one-sided p=0.0156
- C2 J(V5S2) - J(MRp): +0.0pp [-25.0, +25.0], clusters +2 / -2 / =5, one-sided p=0.688
- C2 J(V5S2) - J(Ecode): +12.5pp [-22.2, +50.0], clusters +4 / -3 / =2, one-sided p=0.5
- C3 T(V5S2P) - T(V5S2): +5.6pp [+0.0, +13.9], clusters +2 / -0 / =7, one-sided p=0.25
