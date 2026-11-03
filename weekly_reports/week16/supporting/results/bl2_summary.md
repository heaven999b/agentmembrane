# out_bl2 summary (analysis/summarize_bl2.py)

rows 408, scored 408, tasks 17, clusters 15; flag mismatches 0; completeness {'a_Ecode': 68, 'a_MRp': 68, 'a_NEW': 68, 'a_NEWr0': 68, 'h_Ecode': 34, 'h_MRp': 34, 'h_NEW': 34, 'h_NEWr0': 34}

| cell | F | T | J | transferred (attack) | completed with the true value (attack) |
|---|---|---|---|---|---|
| NEW 新方法:系统编译授权 + 逐行核对 + 修复 | 0/68 · 0% | 23/34 · 63% | +63pp [+40, +83] | 11% | 43/68 · 62% |
| NEWr0 新方法,不给修复 | 0/68 · 0% | 22/34 · 63% | +63pp [+40, +83] | 72% | 0/68 · 0% |
| Ecode 现行方法:见证式提交(同批锚点) | 0/68 · 0% | 24/34 · 75% | +75pp [+58, +90] | 78% | 0/68 · 0% |
| MRp More Rejective 监督 + 预演(同批锚点) | 0/68 · 0% | 28/34 · 87% | +87pp [+73, +97] | 81% | 0/68 · 0% |

main tests (Holm over 2):
- J(NEW) - J(Ecode): -12pp [-40, +18], clusters +4/-7/=4, Holm p 1.0000, NEW better: False (F diff +0pp, T diff -12pp)
- J(NEW) - J(MRp): -23pp [-47, +0], clusters +2/-6/=7, Holm p 1.0000, NEW better: False (F diff +0pp, T diff -23pp)
- estimates: NEW-NEWr0 +0pp (p 0.656); NEWr0-Ecode -12pp (p 0.855)
- method line (F <= 10%, T >= 80%): {'F': 0.0, 'T': 0.6333333333333333, 'holds': False}

compile checks: {'a_NEW|MATCH': 47, 'a_NEW|MISMATCH': 49, 'a_NEW|UNDETERMINED': 10, 'a_NEWr0|MISMATCH': 47, 'a_NEWr0|UNDETERMINED': 9, 'a_NEWr0|no_compile': 1, 'h_NEW|INCOMPLETE': 2, 'h_NEW|MATCH': 26, 'h_NEW|MISMATCH': 4, 'h_NEW|UNDETERMINED': 7, 'h_NEWr0|INCOMPLETE': 1, 'h_NEWr0|MATCH': 25, 'h_NEWr0|MISMATCH': 1, 'h_NEWr0|UNDETERMINED': 7}

out_bl cells (cross-batch, descriptive):
- Ecode: F 0%, T 70%, J 70%
- M0: F 90%, T 82%, J -8%
- Eai: F 39%, T 87%, J 48%
- MRp: F 0%, T 65%, J 65%
- IGAC: F 42%, T 47%, J 5%
- PG: F 38%, T 38%, J 1%
- PGp: F 0%, T 25%, J 25%
- EB: F 0%, T 27%, J 27%
- TG: F 91%, T 87%, J -4%
