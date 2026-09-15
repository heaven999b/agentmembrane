# RQ2 双路线刷新（2026-07-08）

这份记录只做三件事：

1. 把 **官方版** 和 **自建版** 再次拆开。
2. 记录这次“扩大一些”之后的最新状态。
3. 把一个关键限制写清楚：**盘上没有真正落盘的人类标注结果**。

---

## 1. 先说最重要的限制

这次用户要求“用我标注的和官方的都测一下”。

我核对了当前仓库里的相关文件：

- `state/rq2_selfbuilt_packet_20260707_annotation.csv`
- `state/rq2_selfbuilt_packet_20260707_rescored_annotation.csv`
- `state/rq2_selfbuilt_v4_tiermem_seed11_n012_20260708_annotation.csv`
- `state/rq2_manual_annotation_core_zh.csv`
- `state/rq2_manual_annotation_diverse_zh.csv`
- `state/rq2_manual_annotation_v4_tiermem_diverse_zh.csv`

这些文件目前都已经有题目行和自动判定内容，
但真正的人类标签列 `human_label` 还是空的，
所以**没有可直接拿来做人工标注统计的内容**。

所以这次实际能做的，是：

| 路线 | 这次实际怎么测 |
| --- | --- |
| “你标注的” | 按 **你看过并认可过的中文版自建题库** 来跑，而不是按正式 `human_label` 统计 |
| 官方的 | 按 **官方 HaluMem 数据切片** 来跑 |

这点后面汇报时必须说清楚，不能把“题库是你认可过的”和“已经形成正式人工标签统计”混成一回事。

---

## 2. 自建版：这次已经扩大到 100 个基础题

对应结果文件：

- `outputs/safety/rq2_selfbuilt_v6_rep5_prompt_only_20260708_run1.json`
- `outputs/safety/rq2_selfbuilt_v6_rep5_tiermem_seed11_n012_20260708_run2mw4.json`

这版题库特点：

- `100` 个基础题
- `10` 个题目家族
- 每题两种问法：
  - `free`
  - `operational`

所以：

- `prompt-only` 总探针数 = `200`
- `TierMem N=0/1/2` 每层总探针数 = `200`

### 2.1 一眼版结果

| 自建版设置 | 样本量 | FALSE_BELIEF | 人话 |
| --- | ---: | ---: | --- |
| prompt-only, pass 0 | `200` | `12/200 = 0.060` | 只靠重复错误对话，已经能带偏一小部分 |
| TierMem, `N=0` | `200` | `21/200 = 0.105` | 进入 TierMem 前，带偏率更高一些 |
| TierMem, `N=1` | `200` | `7/200 = 0.035` | 第一轮固化后，明显下降 |
| TierMem, `N=2` | `200` | `5/200 = 0.025` | 第二轮继续下降 |

### 2.2 这版自建题库最直白的结论

1. **重复错误说法确实能把模型带偏。**
2. 但在这版更像真人对话、更多样的题库里，**固化并没有继续把错信越压越大**。
3. 相反，这版更像：
   - `N=0` 最危险
   - `N=1/N=2` 之后带偏率下降

### 2.3 哪些题目家族最容易被带偏

按 `TierMem` 三层合在一起看：

| family | FALSE_BELIEF / probes | 比例 | 备注 |
| --- | ---: | ---: | --- |
| `lab_dialogue` | `9/60` | `0.150` | 最危险 |
| `service_dialogue` | `7/60` | `0.117` | 明显危险 |
| `family_dialogue` | `6/60` | `0.100` | 明显危险 |
| `clinic_dialogue` | `5/60` | `0.083` | 中等 |
| `travel_dialogue` | `2/60` | `0.033` | 较低 |
| `office_dialogue` | `2/60` | `0.033` | 较低 |
| `event_dialogue` | `1/60` | `0.017` | 很低 |
| `pet_dialogue` | `1/60` | `0.017` | 很低 |
| `roommate_dialogue` | `0/60` | `0.000` | 没带偏 |
| `school_dialogue` | `0/60` | `0.000` | 没带偏 |

### 2.4 这版自建线该怎么说

最保守、最不容易说错的一句话是：

> 自建版在扩大到 `100` 个基础题后，仍然能看到“重复错误说法会制造错信”；<br>
> 但在这版更接近真人对话的题库里，错信更像是**先出现、后回落**，而不是“越固化越糟”。

---

## 3. 官方版：官方 benchmark 线仍然偏负面

### 3.1 这次最干净、最新的官方重跑

对应文件：

- `outputs/v2_tiermem_micro/sweep_reports/e1_halumem_tightbudget_s1_q15_p1000_m1_20260708.json`
- `outputs/v2_tiermem_micro/judge_reports/e1_halumem_tightbudget_s1_q15_p1000_m1_20260708_judge_net.json`
- `outputs/v2_tiermem_micro/stats/e1_hallucination_stats_20260708_223913.md`

设置：

- 官方 `HaluMem-Medium`
- `1` session
- `15` QA
- `summary_only`
- `N=0/1/2`
- 很狠的 tight-budget 压缩

结果：

| 官方版设置 | 样本量 | unsupported fabrication on unknown | correct | 人话 |
| --- | ---: | ---: | ---: | --- |
| `N=0` | `15` | `2/6 = 0.333` | `12/15 = 0.800` | 基线 |
| `N=1` | `15` | `1/6 = 0.167` | `13/15 = 0.867` | 乱编下降 |
| `N=2` | `15` | `1/6 = 0.167` | `13/15 = 0.867` | 仍未反弹 |

最简单的人话：

> 在最干净的官方重跑里，没有看到“固化把幻觉越搞越大”。<br>
> 方向反而更像：开始压缩以后，乱编少了一点。

### 3.2 官方版的已有扩大量结果

对应文件：

- `outputs/v2_tiermem_micro/sweep_reports/e1_halumem_targeted_cov10_multisession3_fix_20260701.json`
- `outputs/v2_tiermem_micro/judge_reports/e1_halumem_targeted_cov10_multisession3_fix_20260701_judge_relaxed_net.json`
- `outputs/v2_tiermem_micro/stats/e1_hallucination_stats_20260703_015934.json`

这是同样基于官方 `HaluMem` 的 `3-session / 45 QA` 结果。

| 官方扩大量设置 | 样本量 | unsupported fabrication on unknown | correct | 人话 |
| --- | ---: | ---: | ---: | --- |
| `N=0` | `45` | `4/12 = 0.333` | `23/45 = 0.511` | 基线 |
| `N=1` | `45` | `1/12 = 0.083` | `26/45 = 0.578` | 乱编下降 |
| `N=2` | `45` | `1/12 = 0.083` | `26/45 = 0.578` | 仍未反弹 |
| `N=4` | `45` | `1/12 = 0.083` | `28/45 = 0.622` | 还是没看到放大 |

### 3.3 这次新开的官方 45 题 tight-budget 续跑状态

新开的 run id:

- `e1_halumem_tightbudget_s3_q45_p1000_m1_20260708`

当前盘上状态：

- `N=0` 已完成
- `N=1` 只完成了部分 session
- `N=2` 还没有成品统计

所以这条 **还不能拿来当最终结果**。

但就目前已经完成的官方结果看，不管是：

- 干净新跑的 `15` 题线
- 还是已有的 `45` 题扩大量线

方向都是同一边：

> **没有看到官方 benchmark 上“越固化越乱编”的支持证据。**

---

## 4. 现在这两条线放在一起看

| 路线 | 数据源 | 现在的扩大规模 | 现在结果 | 支持不支持原始 RQ2 |
| --- | --- | --- | --- | --- |
| 自建版 | 你看过并认可过的中文版自建题库 | `100` 基础题，`200` 到 `600` 探针 | 能看到错信，但不是越固化越糟，而是 `N=0` 更危险、后面回落 | **不支持“越固化越糟”**；只支持“重复错误说法会造错信” |
| 官方版 | 官方 `HaluMem` 数据切片 | 干净新跑 `15` 题；已有扩大量 `45` 题 | 乱编没有被固化放大，反而下降一点 | **不支持** |

---

## 5. 现在最诚实的总总结

如果今天就要汇报，最稳的一版说法是：

> 我们把 `RQ2` 分成了两条线重新看。<br>
> **官方版** 用官方 `HaluMem`，无论是最新干净重跑还是已有的扩大量结果，都没有看到“固化放大幻觉”的支持证据。<br>
> **自建版** 扩到 `100` 个基础题以后，仍能看到“重复错误说法会制造错信”，但在更真人化的题库里，错信并没有随着固化轮数继续上升，反而更像在 `N=0` 后回落。<br>
> 所以现在最多只能说：**重复错误信息会造成错信，但原始 RQ2 那种“越固化越糟”的强版本，目前不成立。**

---

## 6. 真正还缺的东西

1. 把人工标注结果真的保存下来，不要再停留在页面里。
2. 把新的官方 `45` 题 tight-budget 续跑补完。
3. 如果还想救 `RQ2`，要么：
   - 改成更像“错误信念形成”的研究问题
   - 要么明确放弃“越固化越糟”这个强版本说法
