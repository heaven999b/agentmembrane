# E1 HaluMem Tight-Budget Rerun (2026-07-08)

## 为什么重跑

这是在补 `v2` 计划里一直没补齐的那条排查:

> 如果 pilot 没看到清晰正信号，先把压缩预算收紧再重跑，不要直接改假设。

之前官方 `HaluMem` 线已经做过:

- `summary_only`
- 1 session / 15 QA
- `qa_retrieved_pages`
- warmup `top-k=10`

但没有做过一轮明确的 **tight-budget** 版本。

## 这次怎么收紧

- benchmark: `HaluMem-Medium` 官方数据
- route: `summary_only`
- sessions: `1`
- QA: `15`
- N: `0 / 1 / 2`
- page size: `1000` 以前默认常见是 `4000`
- consolidation scope: `qa_retrieved_pages`
- consolidation warmup top-k: `10`
- consolidation target max pages: `1`

关键点:

- `N=1/2` 时，warmup 检到的 QA 相关页并集是 `38` 页
- 真正允许进入压缩的只有 `1` 页
- 也就是这次不是“稍微收一点”，而是 **非常狠地收**

对应产物:

- sweep:
  `outputs/v2_tiermem_micro/sweep_reports/e1_halumem_tightbudget_s1_q15_p1000_m1_20260708.json`
- judge:
  `outputs/v2_tiermem_micro/judge_reports/e1_halumem_tightbudget_s1_q15_p1000_m1_20260708_judge_net.json`
- stats:
  `outputs/v2_tiermem_micro/stats/e1_hallucination_stats_20260708_223913.md`

## 和旧单 session 官方线正面对比

旧基线:

- report:
  `outputs/v2_tiermem_micro/judge_reports/e1_halumem_targeted_cov10_depth_20260701_judge_relaxed_net.json`

| 设置 | N | correct | UF_on_unknown | AF_on_factual | FD_on_factual | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 旧官方线 | 0 | 0.600 | 0.333 | 0.333 | 0.111 | 0.205 |
| 旧官方线 | 1 | 0.667 | 0.167 | 0.333 | 0.111 | 0.205 |
| 旧官方线 | 2 | 0.533 | 0.167 | 0.444 | 0.222 | 0.189 |
| 新 tight-budget | 0 | 0.800 | 0.333 | 0.111 | 0.000 | 0.220 |
| 新 tight-budget | 1 | 0.867 | 0.167 | 0.000 | 0.111 | 0.207 |
| 新 tight-budget | 2 | 0.867 | 0.167 | 0.111 | 0.000 | 0.201 |

## 人话结论

1. **收紧压缩预算以后，RQ2 还是没有被“救正”。**
   - `UF_on_unknown` 还是老样子:
     - `0.333 -> 0.167 -> 0.167`
   - 也就是:
     - `N=0` 最会乱编
     - 一旦开始压缩，乱编下降
     - 到 `N=2` 也没有再反弹

2. **这次甚至比旧线更不像“越压越坏”。**
   - 旧线里 `AF_on_factual` 是:
     - `0.333 -> 0.333 -> 0.444`
   - 新线里变成:
     - `0.111 -> 0.000 -> 0.111`
   - 旧线里 `FD_on_factual` 是:
     - `0.111 -> 0.111 -> 0.222`
   - 新线里变成:
     - `0.000 -> 0.111 -> 0.000`

3. **所以“之前没看到 RQ2，只是因为压得不够狠”这个解释，现在不太站得住。**
   - 我们已经把相关页从 `38` 页砍到 `1` 页了
   - 结果没有出现“更深压缩把幻觉重新放大”
   - 相反，这个 slice 里答案整体更干净

## 统计口径

bootstrap + paired McNemar 结果:

- `N=1 vs N=0` correct: `p=1.0`
- `N=1 vs N=0` UF_on_unknown: `p=1.0`
- `N=2 vs N=0` correct: `p=1.0`
- `N=2 vs N=0` UF_on_unknown: `p=1.0`

不要误读:

- 这不是“证明完全没效应”
- 而是 `n=15` 太小，配对翻转数太少，统计功效不足

但就 **方向** 而言，这轮已经足够说明:

> 收紧压缩预算并没有把官方版 `RQ2` 从负面/不支持，翻成正面支持。

## 现在这条排查的状态

| 排查项 | 状态 | 备注 |
| --- | --- | --- |
| 官方 HaluMem summary-only 是否因为压缩不够狠才没出正信号 | `已补` | 结论偏否: 更狠压缩也没把 RQ2 救正 |

## 下一步如果还要继续补

优先顺序建议:

1. 把这条 tight-budget 版扩到 `3 sessions / 45 QA`
2. 再做 multi-seed，而不是继续在 `n=15` 上反复看单点
3. 如果要补 RQ3，就在这个 tight-budget 基线上再加 `auto / research_only`
