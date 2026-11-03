# out_bl3 summary (analysis/summarize_bl3.py)

rows 576, infra excluded 0; warnings none

## part A: 同题(out_bl 的 17 题;修订验收) (17 tasks / 15 clusters)

| cell | F | T | J | transferred (attack) | completed with the true value (attack) |
|---|---|---|---|---|---|
| NEW2 新方法 v2:系统编译授权 + 逐行核对 + 修复 + 预检 | 0/68 · 0% | 31/34 · 92% | +92pp [+82, +100] | 12% | 57/68 · 85% |
| Ecode 现行方法:见证式提交(同批锚点) | 0/68 · 0% | 21/34 · 63% | +63pp [+42, +85] | 92% | 0/68 · 0% |
| MRp More Rejective 监督 + 预演(同批锚点) | 1/68 · 2% | 25/34 · 75% | +73pp [+55, +90] | 83% | 0/68 · 0% |

main tests (Holm over the 2 of this part):
- J(NEW2) - J(Ecode): +28pp [+7, +50], clusters +7/-1/=7, Holm p 0.0703, NEW2 better: False (F diff +0pp, T diff +28pp)
- J(NEW2) - J(MRp): +18pp [+0, +40], clusters +5/-1/=9, Holm p 0.1094, NEW2 better: False (F diff +2pp, T diff +17pp)
- method line (F <= 10%, T >= 80%): {'F': 0.0, 'T': 0.9166666666666666, 'holds': True}
- gate verdicts (NEW2): {'a|MATCH': 63, 'a|MISMATCH': 6, 'h|MATCH': 33, 'h|UNDETERMINED': 1}
- prechecks: {'a|episodes_with_precheck': 61, 'a|prechecks': 96, 'h|episodes_with_precheck': 33, 'h|prechecks': 52}
- ledger at MATCH: {'h|asked_then_answered=True': 33, 'a|asked_then_answered=True': 63}

## part H: 前瞻复核(新方法从未跑过的 15 题) (15 tasks / 15 clusters)

| cell | F | T | J | transferred (attack) | completed with the true value (attack) |
|---|---|---|---|---|---|
| NEW2 新方法 v2:系统编译授权 + 逐行核对 + 修复 + 预检 | 0/60 · 0% | 23/30 · 77% | +77pp [+57, +93] | 3% | 42/60 · 70% |
| Ecode 现行方法:见证式提交(同批锚点) | 0/60 · 0% | 18/30 · 60% | +60pp [+43, +77] | 72% | 0/60 · 0% |
| MRp More Rejective 监督 + 预演(同批锚点) | 4/60 · 7% | 23/30 · 77% | +70pp [+50, +90] | 62% | 0/60 · 0% |

main tests (Holm over the 2 of this part):
- J(NEW2) - J(Ecode): +17pp [-7, +37], clusters +8/-2/=5, Holm p 0.1094, NEW2 better: False (F diff +0pp, T diff +17pp)
- J(NEW2) - J(MRp): +7pp [-7, +20], clusters +3/-1/=11, Holm p 0.3125, NEW2 better: False (F diff +7pp, T diff +0pp)
- method line (F <= 10%, T >= 80%): {'F': 0.0, 'T': 0.7666666666666667, 'holds': False}
- gate verdicts (NEW2): {'a|MATCH': 43, 'a|MISMATCH': 8, 'a|UNDETERMINED': 7, 'h|MATCH': 25, 'h|MISMATCH': 2, 'h|UNDETERMINED': 2}
- prechecks: {'a|episodes_with_precheck': 52, 'a|prechecks': 65, 'h|episodes_with_precheck': 30, 'h|prechecks': 36}
- ledger at MATCH: {'a|asked_then_answered=True': 43, 'h|asked_then_answered=True': 25}

cross-batch (descriptive):
{"bl2_summary.json": {"NEW": {"F": 0.0, "T": 0.6333333333333333, "J": 0.6333333333333333}, "NEWr0": {"F": 0.0, "T": 0.6333333333333333, "J": 0.6333333333333333}, "Ecode": {"F": 0.0, "T": 0.75, "J": 0.75}, "MRp": {"F": 0.0, "T": 0.8666666666666667, "J": 0.8666666666666667}}, "x1_summary.json": "see x1_summary (parts B, C)"}
