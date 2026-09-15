# 本轮结果怎么看（给没看过这个项目的人）· 2026-07-09

项目根目录：`${MEMORY_PROJECT_ROOT}`

这份说明专门告诉新人：本轮结果先看什么、每个文件代表什么、怎么自己复现。

## 0. 只看一个文件的话，看这个

**`outputs/v2_tiermem_micro/stats/e1_halumem_p2_stats.md`**

这是本轮最重要的 pilot 结果：在官方 HaluMem 数据上，比较记忆固化深度 `N=0/1/2` 时，正确率和几类幻觉错误怎么变化。

终端直接看：

```bash
cd "${MEMORY_PROJECT_ROOT}"
cat outputs/v2_tiermem_micro/stats/e1_halumem_p2_stats.md
```

这张表怎么读：

| 列 | 意思 | 想看到 |
| --- | --- | --- |
| `N` | 固化深度，表示做了几轮压缩 | — |
| `correct_rate` | 答对比例 | 越高越好 |
| `UF_on_unknown` | 该说“不知道”却乱编的比例 | 越低越好 |
| `AF_on_factual` | 该答却弃答或忘了的比例 | 越低越好 |
| `FD_on_factual` | 答了但把事实说歪的比例 | 越低越好 |
| `[a, b]` | 95% 置信区间 | — |
| `Holm p` / `sig@alpha Holm` | Holm 多重比较校正后的显著性，`alpha=0.01` | `yes` 才能说比较稳 |

一句话结论：

- `correct_rate` 从 `0.60` 到 `0.80`
- `FD_on_factual` 从 `0.50` 到 `0.25`
- 方向上看，**固化没有把幻觉放大，反而略有变好**
- 但样本只有 10 题、单 seed，Holm 后都不显著，所以这是**流程跑通的 pilot，不是最终定论**

## 1. 本轮结果文件按 Phase 看

### Phase 1 · Live 冒烟

- `outputs/safety/rq1_live_smoke.md`
- `outputs/safety/rq1_live_smoke_items.jsonl`

这一步的作用不是出论文结果，而是确认真实调用链是活的，而且 `C^N` 真的生效。

最直观的看法是打开 `items.jsonl`，确认：

- `N=0` 还是原始对话
- `N=1` 已经变成压缩后的摘要

也就是说明压缩链路不是假的。

### Phase 2 · 官方 HaluMem 主线

这条线有三个文件，按顺序看：

1. `outputs/v2_tiermem_micro/sweep_reports/e1_halumem_p2.md`
   这里是模型对官方 HaluMem 题目的原始回答。
2. `outputs/v2_tiermem_micro/judge_reports/e1_halumem_p2_judge.md`
   这里是 `gpt-4o` 对每题的判卷，区分 CORRECT、乱编、弃答、事实扭曲。
3. `outputs/v2_tiermem_micro/stats/e1_halumem_p2_stats.md`
   这里是最终统计表，也是本轮最值得先看的文件。

所以这条链是：

`模型原始回答 -> judge 判卷 -> 统计表`

### Phase 3a · 官方评测适配器

这一步不是结果文件，而是一个离线校验命令：

```bash
.venv_tiermem_v2/bin/python scripts/analysis/halumem_official_eval_adapter.py --validate
```

如果看到：

- `schema_problems: 0`
- `Schema OK`

就说明我们的输出格式已经能和官方评测接口对齐。

### Phase 4a · RQ2 人工标注表

这些文件是给人打标的，不是主结果：

- `state/rq2_manual_annotation_core_zh_dedup.csv`
- `state/rq2_manual_annotation_diverse_zh_dedup.csv`
- `state/rq2_manual_annotation_v4_tiermem_diverse_zh_dedup.csv`

打开以后重点看：

- `human_label`：空着，等人工填
- `dedup_group_size`：这行代表了多少条重复样本

### Phase 5 · RQ3 效用图模板

- `configs/rq3_utility_map_template.json`

这不是结果，是后面补 RQ3 效用侧时要填的模板。
里面的 `_README` 已经写了怎么填。

## 2. 如果想自己从零复现

```bash
cd "${MEMORY_PROJECT_ROOT}"
set -a && source .env.v3 && set +a
.venv_tiermem_v2/bin/python scripts/install_dev_paths.py
```

然后先跑最小复现：

```bash
.venv_tiermem_v2/bin/python scripts/run/run_rq1_safety_consolidation.py \
    --backend tiermem --item-limit 1 --passes 0 1 --report-id rq1_live_smoke
```

再跑官方 HaluMem 小 pilot：

```bash
.venv_tiermem_v2/bin/python scripts/run/run_v2_tiermem_micro_n_sweep.py \
    --benchmark halumem --route-modes summary_only --passes 0 1 2 \
    --session-limit 1 --qa-limit 10 --qdrant-path outputs/qdrant_p2 \
    --run-prefix e1_halumem_p2 --skip-existing

.venv_tiermem_v2/bin/python scripts/run/run_v2_tiermem_micro_failure_mode_judge.py \
    --sweep-report outputs/v2_tiermem_micro/sweep_reports/e1_halumem_p2.json \
    --judge-model gpt-4o --report-id e1_halumem_p2_judge

.venv_tiermem_v2/bin/python scripts/run/run_e1_hallucination_statistics.py \
    --judge-report outputs/v2_tiermem_micro/judge_reports/e1_halumem_p2_judge.json \
    --report-id e1_halumem_p2_stats
```

重要提醒：

- `outputs/` 里的大部分结果不进 git
- 所以别人从 GitHub 克隆下来，通常是看不到本轮本地产物的
- 要么你把结果文件直接给他，要么他按上面的命令自己重跑

## 3. 本轮代码改动怎么看

```bash
git log --oneline -2
git show ffd3ea7 --stat
```

目前最关键的是这两个 commit：

- `caac3cd`：修复重组后 subprocess 路径写死的问题
- `ffd3ea7`：修复 import、补齐文档、加上 Phase 3a/4a/5 的离线工具

## 4. 如果他完全不懂项目，先看什么

建议顺序：

1. `RESEARCH_README.md`
2. `docs/OPERATOR_GUIDE.md`
3. `weekly_reports/week1/week1_report_20260709_en.md`
4. 本文件

一句话现状：

原始假设“固化会放大危险或幻觉”目前**不成立**。这轮官方 HaluMem pilot 也给了同方向的一个小证据点：没有看到越固化越乱编。
