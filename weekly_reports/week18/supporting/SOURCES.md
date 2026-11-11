# Week 18 · 数字来源与代码位置

本周报告里的数字都来自前几周已发布的汇总,下表逐批列出。原始轨迹、运行环境和模型调用记录不进 Git;实验工作区里的路径都相对于实验工作区根目录。

## §6 各批结果的出处

| 报告里的表 | 出处(本仓库) |
|---|---|
| Week 15 · 17 道题、9 种做法 | [week15 汇总](../../week15/supporting/results/bl_summary.md) |
| Week 16 · out_bl4,32 道题、6 种方法 | [out_bl4 汇总](../../week16/supporting/results/bl4_summary.md)(表里的“核对 + 代填”是当时的 v3,汇总里叫 NEW3) |
| Week 16 · out_bl5,10 道新题 | [out_bl5 汇总](../../week16/supporting/results/bl5_summary.md)(冻结版 v4,汇总里叫 NEW4) |
| Week 17 · out_bl13,老题 + 新题、6 格 | [out_bl13 汇总](../../week17/supporting/results/bl13_summary.md) |
| Week 17 · out_bl14,干净对比 | [out_bl14 汇总](../../week17/supporting/results/bl14_summary.md) |

- 被骗写入的局数(如 7/154)= 易攻击 + 难攻击两列的局数相加,老题和新题合计。
- 各方法小节里“结果”一栏的数字,出自同一批汇总。

## 外部方法原文

| 方法 | 原文 |
|---|---|
| More Rejective 监督 | Han、Yan、Zhang,[arXiv 2608.23941](https://arxiv.org/abs/2608.23941) |
| PolicyGuard | Kang、Yu、Hwang,[arXiv 2606.29225](https://arxiv.org/abs/2606.29225) |
| IGAC | Zhu、Wang,[arXiv 2606.22916](https://arxiv.org/abs/2606.22916) |
| 实体绑定闸门 | Suresh Babu、Indukuri,[arXiv 2606.30531](https://arxiv.org/abs/2606.30531) |
| ToolGuard | Zwerdling 等(IBM,EMNLP 2025 Industry),[arXiv 2507.16459](https://arxiv.org/abs/2507.16459) |

外部方法在我们这里的实现和适配,见 [Week 15 报告](../../week15/week15_report_20261028_zh.md)。

## 进行中的批次 out_bl15

| 内容 | 位置(实验工作区) |
|---|---|
| 预注册 | `out_bl15/PREREG.md`(副本:[out_bl15_PREREG.md](./out_bl15_PREREG.md)) |
| 作业清单 | `out_bl15/make_jobs.py`(从 out_bl13 的 V5S2 作业行生成,V5S3 只替换 `--compile-mode`)、`out_bl15/jobs.txt`(454 行) |
| 开跑前的哈希 | `out_bl15/HASHES.txt` |
| 汇总脚本 | `analysis/summarize_bl15.py`(规则同 `summarize_bl14.py`) |
| 小试跑 | `out_bl15_smoke/`(4 局,不计入) |

## 图

`figures/` 里的 SVG 由方法讲解页的同一份数据生成,自带浅色和深色两套配色。
