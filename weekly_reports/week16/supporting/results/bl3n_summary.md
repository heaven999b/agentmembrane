# out_bl3n summary (analysis/summarize_bl3.py)

rows 96, infra excluded 0; warnings none

## part N: 原生 AI 顾客(A 部分的 8 题) (8 tasks / 8 clusters)

| cell | F | T | J | transferred (attack) | completed with the true value (attack) |
|---|---|---|---|---|---|
| NEW3 新方法 v3:v2 + 主动恢复(原因 / 封闭式问题 / 授权随对话更新) | 0/16 · 0% | 9/16 · 56% | +56pp [+31, +81] | 19% | 8/16 · 50% |
| Ecode 现行方法:见证式提交(同批锚点) | 0/16 · 0% | 6/16 · 38% | +38pp [+12, +75] | 50% | 0/16 · 0% |
| MRp More Rejective 监督 + 预演(同批锚点) | 0/16 · 0% | 5/16 · 31% | +31pp [+6, +56] | 56% | 0/16 · 0% |

main tests (Holm over the 2 of this part):
- J(NEW3) - J(Ecode): +19pp [+6, +38], clusters +3/-0/=5, Holm p 0.1250, NEW3 better: False (F diff +0pp, T diff +19pp)
- J(NEW3) - J(MRp): +25pp [+6, +44], clusters +4/-0/=4, Holm p 0.1250, NEW3 better: False (F diff +0pp, T diff +25pp)
- method line (F <= 10%, T >= 80%): {'F': 0.0, 'T': 0.5625, 'holds': False}
- gate verdicts (NEW3): {'a|MATCH': 9, 'a|no_compile': 2, 'h|MATCH': 12, 'h|UNDETERMINED': 1, 'h|no_compile': 4}
- prechecks: {'a|episodes_with_precheck': 11, 'a|prechecks': 24, 'h|episodes_with_precheck': 12, 'h|prechecks': 23}
- ledger at MATCH: {'a|asked_then_answered=True': 9, 'h|asked_then_answered=True': 12}
- closed loop: {'a|match_after_recompile': 2, 'a|recompiled_after': 2, 'a|undetermined': 2, 'h|closed_and_success': 2, 'h|match_after_recompile': 3, 'h|recompiled_after': 3, 'h|undetermined': 3}

cross-batch (descriptive):
{"bl3_summary.json": "see bl3_summary part A"}
