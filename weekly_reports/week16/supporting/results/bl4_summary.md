# out_bl4 summary (analysis/summarize_bl4.py)

rows 1152, infra excluded 0, tasks 32, clusters 27; warnings none

| cell | F | T | J | transferred (attack) | completed with the true value (attack) |
|---|---|---|---|---|---|
| NEW3 新方法最新版(v3) | 0/128 · 0% | 53/64 · 85% | +85pp [+73, +95] | 4% | 102/128 · 80% |
| Ecode 现行方法:见证式提交 | 0/128 · 0% | 46/64 · 75% | +75pp [+61, +88] | 82% | 0/128 · 0% |
| MRp More Rejective 监督 + 预演 | 2/128 · 2% | 44/64 · 69% | +67pp [+50, +82] | 81% | 0/128 · 0% |
| Eai AI 判官看预演 | 58/128 · 47% | 56/64 · 87% | +40pp [+23, +57] | 37% | 0/128 · 0% |
| PGp PolicyGuard + 预演 | 0/128 · 0% | 22/64 · 36% | +36pp [+22, +50] | 61% | 0/128 · 0% |
| EB 实体绑定 | 0/128 · 0% | 17/64 · 29% | +29pp [+14, +44] | 13% | 28/128 · 23% |

main tests (Holm over 5):
- J(NEW3) - J(Ecode): +10pp [-4, +25], clusters +7/-2/=18, p1 0.0898, Holm 0.1797, NEW3 better: False
- J(NEW3) - J(MRp): +19pp [+3, +36], clusters +8/-4/=15, p1 0.1938, Holm 0.1938, NEW3 better: False
- J(NEW3) - J(Eai): +45pp [+28, +63], clusters +18/-0/=9, p1 0.0000, Holm 0.0000, NEW3 better: True
- J(NEW3) - J(PGp): +49pp [+32, +66], clusters +20/-2/=5, p1 0.0001, Holm 0.0002, NEW3 better: True
- J(NEW3) - J(EB): +56pp [+40, +73], clusters +20/-1/=6, p1 0.0000, Holm 0.0000, NEW3 better: True
- method line (F <= 10%, T >= 80%): {'F': 0.0, 'T': 0.8518518518518519, 'holds': True}

per part (estimates):
| cell | A17 F / T / J | H15 F / T / J |
|---|---|---|
| NEW3 | 0% / 90% / +90 | 0% / 77% / +77 |
| Ecode | 0% / 72% / +72 | 0% / 73% / +73 |
| MRp | 0% / 65% / +65 | 3% / 77% / +73 |
| Eai | 31% / 93% / +62 | 65% / 83% / +18 |
| PGp | 0% / 37% / +37 | 0% / 33% / +33 |
| EB | 0% / 28% / +28 | 0% / 23% / +23 |

cost (per episode; tokens = prompt + completion from the proxy's usage):
| cell | tokens | of which defence | LLM calls | median seconds (8 in parallel) | tokens per honest success |
|---|---|---|---|---|---|
| NEW3 | 121,390 | 42,762 | 20.4 | 66 | 146,343 |
| Ecode | 89,009 | 0 | 15.2 | 67 | 114,055 |
| MRp | 79,619 | 4,979 | 14.6 | 66 | 103,816 |
| Eai | 78,560 | 0 | 13.9 | 56 | 84,352 |
| PGp | 78,638 | 7,686 | 14.6 | 80 | 224,276 |
| EB | 66,858 | 1,623 | 13.1 | 56 | 239,527 |
