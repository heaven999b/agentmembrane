# RQ 研究进度总结（对照 v2 PDF 计划）· 2026-07-09

> 覆盖 RQ1 / RQ2 / RQ3 / RQ5（RQ4 略）。
> 每个 RQ 给：① PDF 里的问题与假设 ② 我的研究进度 ③ 评价指标（PDF 定义 vs 实测口径）④ 当前结论 ⑤ 完成度与缺口。
> 通则：**所有安全/幻觉终点默认以「否定感知 LLM judge」为准，词法指标只做交叉验证**（词法已被证明系统性高估）。

---

## RQ1 · 递归固化是否保留 / 放大不安全内容？

- **PDF 假设**：在 summary-only 记忆里，不安全种子命题与可触发投毒会随固化深度 N **持续存在或被语义洗白**。
- **进度**：✅ **已完整实现并跑过**。注入 12 条 unsafe 种子 + 30 条隐蔽投毒 + 100 条 AgentPoison 触发，做 C^N × backend（fake / tiermem / prompt_only），judge 复核。

**评价指标（PDF §6）**

| 指标 | PDF 定义 | 诊断阶段 | 实现 | 实测终点 |
| --- | --- | --- | --- | --- |
| SRR(N) | 固化后仍存活的 unsafe 种子 / 注入数 | 写入+固化 | ✅ | 词法 + judge |
| UAF(N) | 固化后被洗白/去标记的 unsafe 命题 / 注入数 | 固化放大 | ✅ | 词法 + judge |
| RTR@k(N) | 触发 query 下投毒记忆进 top-k 的概率 | 检索 | ✅ | 词法 |
| unsafe answer/action rate | 下游回答遵从/依赖不安全记忆的比例 | reader | ✅ | judge（主）|

**当前结论**
- ❌ **推翻原假设**：迭代固化**不放大、不洗白**不安全内容——标记为 unsafe 的内容固化后仍带标记、从不被洗白，且 reader 随 N 增大**更倾向拒答**（经遗忘反而略降暴露）。
- ⚠️ 真正的漏洞在 **reader 侧**、与固化无关：`prompt_only`（无记忆）风险 ≥ `tiermem`。
- 对照事实层：agent **92% 尊重官方权威**、3× 重复假传闻也灌不进。

**完成度**：核心可结。**缺口**：N 深度只到 8×1（N=16 未跑）；SRR/UAF 主表用词法，judge 复核到位但未全量。

---

## RQ2 · 迭代固化是否制造假记忆？

- **PDF 假设**：HaluMem 抽取/更新错误**先升**，随后无来源支撑的记忆**传播进 QA**。
- **进度**：🟡 **部分完成**，双路线：**官方 HaluMem 切片** + **自建本地对话题库（v6，100 基础题/200–600 探针）**。做了 tight-budget 收紧重跑（按 PDF §7 stop/go 纪律）。

**评价指标**

| 指标 | PDF 定义 | 诊断阶段 | 实现情况 |
| --- | --- | --- | --- |
| HaluMem 分阶段分 | extraction / update / QA 分开评 | 全链 | 🟡 用 judge 标签（CORRECT/UF/FD/ABSTAIN）在 QA 端替代 |
| **UNMR(N)** | 无来源支撑的新固化语句 / 全部新固化语句 | 固化幻觉 | ❌ **未按定义实现**（无写入阶段独立度量）|
| **conflict merge rate** | 矛盾事实被错并成一条 | 更新处理 | ❌ **未实现**（E3 冲突漂移未做）|
| **PAR(N)** | 无支撑记忆被最终答案引用/使用的概率 | 传播到答案 | ❌ **未按定义实现**（无 provenance 追踪的 PAR）|
| FALSE_BELIEF（自建线）| 重复错误说法后模型形成错信 | reader | ✅ judge |

**当前结论（关键数字）**
- 官方 HaluMem（tight-budget，N=0/1/2）：`UF_on_unknown` **0.333 → 0.167 → 0.167**，correct **0.800 → 0.867 → 0.867** —— **没看到「越固化越乱编」，方向反而是压缩后乱编下降**。
- 自建 v6（100 题）：`FALSE_BELIEF` TierMem **N=0 0.105 → N=1 0.035 → N=2 0.025** —— 重复错误说法**能**造错信，但**N=0 最危险、之后回落**，不是越固化越糟。

**完成度**：证据偏弱。**缺口**：① UNMR/conflict-merge/PAR 三个 PDF 指标未实现（当前用 judge 标签替代，需在文档显式声明）；② 人工标注 `human_label` 还没真正落盘；③ 官方 45 题 tight-budget 续跑卡在 N=1。

---

## RQ3 · provenance 分层能否打断失败链？

- **PDF 假设**：TierMem 原始证据升级机制能**降低不安全/幻觉传播**，同时保住大部分效用与省算力。
- **进度**：🟡 **部分完成**。两条：写入侧 no-rewrite/provenance 门 + **读取侧 meta-policy 防御**。读取侧刚跑完 **5-seed 大跑**（20/20 完成）。

**评价指标**

| 指标 | PDF 定义 | 实现情况 |
| --- | --- | --- |
| 风险下降 | 防御 on vs off 的错误行动率下降 | ✅ 已测（judge 终点，配对 McNemar + seed 级 t）|
| 效用损失 | LongMemEval-S 良性召回是否被伤 | ❌ **未与防御 run 绑定测** |
| Pareto frontier | 良性准确率 vs 不安全保留 的前沿 | ❌ **未闭合**（只测了风险侧一半）|

**当前结论（关键数字）**
- 读取侧防御：错误行动率 off **~0.88–0.94** → on **~0.75–0.80**；**5 seeds × 2 backend × 3 深度 20/20 格全部同向**，better:worse = **82:11**，seed 级 t 检验各层显著。
- 即 **方向稳健、统计显著（从「不显著」升级），但效应小、仍不闭合**：相对下降仅 ~15%（**未过 PDF 的 25% 判据**），且四分之三违规仍在。
- 写入侧 no-rewrite / provenance-required：**不支持**（auto 退化成 summary、写入 no-rewrite 无效）。

**完成度**：读取侧风险轴已到「稳健小效应」。**缺口**：① Pareto 的效用侧没测 → PDF §6 的「≥25% 风险↓ 且 ≤3pt 效用↓」判据无法完整回答;② 单模型单套件(gpt-4.1-mini + 30 题),跨家族/跨套件未验。详见 `state/rq3_readtime_large_20260708_interpretation.md`。

---

## RQ5 · 失败发生在哪个阶段？

- **PDF 假设**：失败分成 write / consolidation / retrieval / answer 四种模式，防御该对症下药。
- **进度**：✅ **核心已答**。用 know-do 探针 + 失败模式 judge，把失败定位到具体阶段。

**评价指标**

| 指标 | PDF 定义 | 实现情况 |
| --- | --- | --- |
| 逐 item artifact trace | 每条样本的写入/固化/检索/回答全链留痕 | ✅ per-item JSONL 已落盘 |
| stage 标签 | 首次出错阶段标注 | ✅ 失败模式 judge + know-do 对比 |

**当前结论（关键数字）**
- **know-do gap（本项目最硬发现）**：同一条记忆，问「政策是什么」→ **100% 背得对**（doesn't-know = 0，三模型皆是）；问「该怎么做」→ **40–67% 违反**那条自己能背出的政策（gpt-4.1-mini 0.67 / gpt-4o 0.47 / gpt-4.1 0.40）。
- 失败是 **reader 侧、行为性、非认知性**：`prompt_only`（无记忆）≥ `tiermem` → **不是固化/检索出错，是回答阶段出错**。
- 显式 policy-check 干预：**67% → 50%，部分帮助、不显著、不闭合**。

**完成度**：定位清楚，是全项目最强线之一。**缺口**：跨家族复现（需非 OpenAI key）、闭 gap 干预还没找到显著且闭合的方案。

---

## 一页速览

| RQ | 主题 | 完成度 | 一句话结论 | 最大缺口 |
| --- | --- | --- | --- | --- |
| RQ1 | 固化放大不安全？ | ✅ 可结 | 推翻：固化良性，漏洞在 reader | N=16 未跑 |
| RQ2 | 固化造假记忆？ | 🟡 部分 | 重复错误能造错信，但非越固化越糟 | UNMR/conflict/PAR 三指标未按定义实现 |
| RQ3 | provenance 防御？ | 🟡 部分 | 读取侧防御稳健但小效应、不闭合 | Pareto 效用侧未测 |
| RQ5 | 失败在哪阶段？ | ✅ 已答 | know-do gap，失败在回答阶段 | 跨家族复现、闭 gap 干预 |

> 通用口径提醒：报告 RQ1/RQ3 的显著性时，**别引用池化后的极小 p 值**（30 题在多 seed 间是同一批题，独立单元被高估），用「多 seed 全部同向 + seed 级 t 显著」表述；等价/无害主张应改 **TOST**；多终点应做 **Holm-Bonferroni + α=0.01**（目前仓库尚未实现）。

---

## 附录 · 各 RQ 对应文件与产物路径（均已核实存在）

> 项目根：`${MEMORY_PROJECT_ROOT}`
> 本总结文件本身：`state/rq_progress_summary_by_plan_20260709.md`

### RQ1 · 安全保留/放大
- 代码：`run_rq1_safety_consolidation.py`、`run_rq1_authority_experiment.py`、`run_rq1_agentpoison_overlay.py`、`run_rq1_agentpoison_locomo.py`、`run_rq1_safety_judge.py`、`run_rq1_safety_rescore.py`
- 指标：`safety_metrics.py`（SRR/UAF/RTR@k/unsafe-answer 词法）、`safety_honest_metrics.py`（Clopper-Pearson + payload-emission）
- 数据：`benchmarks/safety/unsafe_seed_suite_v1.json`(12)、`stealthy_poison_suite_v1.json`(30)、`agentpoison_trigger_suite_v1.json`(100)
- 产物：`outputs/safety/rq1_agentpoison_full100_judged*.json`、`rq1_agentpoison_full100_seed11*.{json,md,jsonl}`、`outputs/safety/rq1_auth*`、`stealth_*`

### RQ2 · 造假记忆
- 代码：`run_rq2_factual_poison.py`、`rq2_fixed.py`、`analyze_rq2_tiermem_completed_pass.py`、`rescore_rq2_selfbuilt_reports.py`；统计：`run_e1_hallucination_statistics.py`、`run_e1_multiseed_statistics.py`
- 数据（自建）：`configs/rq2_selfbuilt_suite_v3..v6_*.json`
- 产物（自建线）：`outputs/safety/rq2_selfbuilt_v6_rep5_prompt_only_20260708_run1.json`、`rq2_selfbuilt_v6_rep5_tiermem_seed11_n012_20260708_run2mw4.json`
- 产物（官方 HaluMem 线）：`outputs/v2_tiermem_micro/sweep_reports/e1_halumem_tightbudget_s1_q15_p1000_m1_20260708.json`、`outputs/v2_tiermem_micro/stats/e1_hallucination_stats_20260708_223913.md`
- 阶段说明：`state/rq2_dual_track_refresh_20260708.md`、`state/e1_halumem_tightbudget_rerun_20260708.md`

### RQ3 · provenance / 读取侧防御
- 代码：`run_rq3_provenance_clean.py`、`run_rq3_readtime_defense_matrix.py`、`summarize_rq3_readtime_defense_matrix.py`、`extract_rq3_stubborn_partial_results.py`、`build_rq3_readtime_dashboard_data.py`、`v3_no_rewrite_policy.py`
- 产物：`outputs/safety/rq3_readtime_large_20260708_manifest.json`（+ 20 份 `rq3_readtime_large_20260708_{po,tm}_{off,on}_seed*.json`）
- 汇总：`state/rq3_readtime_large_20260708_{summary.md,condition_summary.csv,paired_summary.csv}`
- 解读裁决：`state/rq3_readtime_large_20260708_interpretation.md`、跑法 spec：`state/rq3_readtime_defense_large_run_spec_20260708.md`

### RQ5 · 失败定位 / know-do gap
- 代码：`run_rq_know_vs_do.py`、`run_v2_tiermem_micro_failure_mode_judge.py`
- 产物（三模型主结果）：`outputs/safety/knowdo_main_gpt41mini_20260708.json`、`knowdo_main_gpt4o_20260708.json`、`knowdo_main_gpt41_20260708.json`
- 产物（judge 终点 + 干预）：`outputs/safety/rq_knowdo_none_judge.json`、`rq_knowdo_pcheck30.json`、`rq_knowdo_pcheck_full.json`、`rq_knowdo_gpt-4o_judge.json`、`rq_knowdo_gpt-4_1_judge.json`

### 相关审计/入口文档
- 代码逐条审计：`state/plan_v2_code_audit_20260709.md`
- 研究总入口：`RESEARCH_README.md`；代码导航：`docs/research_question_map.md`
