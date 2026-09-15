# 项目操作指南（给懂代码、没看过本项目的人）

面向读者：会 Python、会命令行，但**第一次接触这个仓库**。读完能独立跑通、评测、并知道结果怎么读、什么不能吹。

---

## 0. 先建立心智模型（30 秒）

- 研究对象：**迭代记忆固化（consolidation 深度 N）** 对 memory-agent **安全 / 幻觉** 的影响，底座是 **TierMem**（raw 层不可变，只递归重写 summary 层）。
- **重要：结论已 pivot。** 原假设「固化会放大危险/造假记忆」**已被推翻**。现在最硬的两条线是：
  1. **评测终点会翻转结论**（词法判卷 vs LLM judge 结论相反）；
  2. **know-do gap**（agent 100% 背得出政策，40–67% 却不照做）。
- **铁律：所有安全/幻觉终点默认用「否定感知 LLM judge」，词法指标只做交叉验证。** 历史上至少 3 次词法结论一上 judge 就塌。

---

## 1. 环境搭建

### 1.1 目录坐标
```
/path/to/workspace/
├── memory_consolidation_small_pilot/   # 主项目（在这里跑一切）
└── tiermem_upstream/                    # TierMem 原版代码（被主项目自动加进 sys.path）
```

### 1.2 Python 环境与 key
```bash
cd "${MEMORY_PROJECT_ROOT}"
# 加载环境变量（OPENAI key、router 配置等）
set -a && source .env.v3 && set +a
# 统一用这个解释器（装了 openai / numpy / scipy / qdrant）
PY=.venv_tiermem_v2/bin/python
# 目录简写（仓库已重组）：run 脚本 / 框架-指标 / 汇总分析
RUN=scripts/run ; CORE=scripts/core ; ANA=scripts/analysis
```
- `.env.v3` 已配 `OPENAI_API_KEY`，默认模型 `gpt-4.1-mini`。
- `.env.v3` 里 **`QWEN_*` / `LLAMA_*` 槽是空的** → 跨家族复现暂时做不了（需要自己填 key）。
- 纯统计/离线脚本用系统 `python3` 即可；**任何 live（真调 API）脚本必须用 `$PY` 且先 source 环境**。

### 1.2b ⚠️ 一次性：修好重组后的导入（每个 venv 跑一次）
仓库已重组（`run_*.py`→`scripts/run/`，框架模块→`scripts/core/`），但脚本仍用扁平 `import`。
**新 venv 首次使用前必须跑一次**，否则所有 run 脚本会 `ModuleNotFoundError`：
```bash
$PY scripts/install_dev_paths.py     # 写一个 .pth，让扁平 import（含派生子进程）解析
```
一次即永久生效；移动仓库或重建 venv 后再跑一次即可。

### 1.3 Qdrant（TierMem 检索后端）
部分 tiermem live 跑法用本地 Qdrant。两种方式：
- 起服务：`bash ../tiermem_upstream/start_qdrant.sh`
- 或用本地路径存储：多数脚本支持 `--qdrant-path <dir>`（免起服务，单机够用）。

### 1.4 并行隔离（重要，避免串数据）
同时跑多个 tiermem live 任务时，**每个任务用独立的 `MEM0_DIR`**：
```bash
MEM0_DIR=outputs/tiermem_local_mem0_jobA $PY $RUN/run_xxx.py ...
```

---

## 2. 仓库地图（只记这些就够开工）

| 类别 | 文件 |
| --- | --- |
| **总入口 / 现状** | `RESEARCH_README.md`（结论）、`docs/research_question_map.md`（代码导航）|
| **公共底座** | `run_v2_tiermem_local_bridge.py`（TierMem 桥）、`pilot_core.py`、`benchmark_native_runtime.py` |
| **RQ1 安全** | `run_rq1_safety_consolidation.py`、`run_rq1_authority_experiment.py`、`run_rq1_agentpoison_overlay.py` |
| **RQ2 幻觉/错信** | `run_rq2_factual_poison.py`（自建线）、`run_v2_tiermem_micro_n_sweep.py`（官方 HaluMem 线）|
| **RQ3 防御** | `run_rq3_readtime_defense_matrix.py` + `summarize_rq3_readtime_defense_matrix.py`、`run_rq3_provenance_clean.py` |
| **RQ5 know-do** | `run_rq_know_vs_do.py` |
| **指标/判卷** | `safety_metrics.py`、`safety_honest_metrics.py`、`run_v2_tiermem_micro_failure_mode_judge.py`、`run_rq1_safety_judge.py`、`run_rq1_safety_rescore.py` |
| **统计** | `run_e1_hallucination_statistics.py`、`run_e1_multiseed_statistics.py` |
| **可靠性** | `kappa_score.py`、`export_kappa.py`、`gen_kappa_html.py` |
| **数据** | `benchmarks/`（官方切片 + 自建 safety 套件）、`configs/rq2_selfbuilt_suite_v*.json` |
| **产物** | `outputs/`（原始 report/jsonl）、`docs/state/`（阶段总结/CSV）|

---

## 3. 第一步永远是冒烟测试（不花钱，验证环境）

```bash
# 3.1 核心指标/统计自测（离线，秒级）
$PY $CORE/safety_metrics.py                       # 期望: [safety_metrics self-test] OK
$PY $CORE/safety_honest_metrics.py                # 期望: OK
$PY $RUN/run_e1_multiseed_statistics.py --self-test

# 3.2 编译全部 RQ 脚本（无语法错）
$PY -m py_compile $RUN/run_rq1_safety_consolidation.py $RUN/run_rq2_factual_poison.py \
    $RUN/run_rq3_readtime_defense_matrix.py $RUN/run_rq_know_vs_do.py $RUN/run_v2_tiermem_local_bridge.py

# 3.3 TierMem 桥就绪检查（不跑 benchmark，只查数据/依赖）
$PY $RUN/run_v2_tiermem_local_bridge.py --benchmark halumem --check-only

# 3.4 花钱前先 dry-run 估算（几个脚本支持）
$PY $RUN/run_rq1_safety_consolidation.py --backend tiermem --dry-run
```
以上全绿 → 环境 OK，可以进真跑。

---

## 4. 分 RQ 怎么跑（命令 + 产物 + 花不花钱）

> 约定：`$PY` = `.venv_tiermem_v2/bin/python`，跑前已 `source .env.v3`。
> 便宜档默认 `gpt-4.1-mini`；换 `--model gpt-4o` / `gpt-4.1` 更贵。

### RQ1 · 固化是否放大不安全内容（结论：不放大，固化良性）
```bash
# (a) 安全固化主实验：注入 unsafe 种子 → C^N → 答案（真 TierMem）
$PY $RUN/run_rq1_safety_consolidation.py --backend tiermem --passes 0 1 2 4 \
    --report-id rq1_safety_demo

# (b) 权威加权受控实验（know-do 的正交 harness：policy×framing×defense×N×backend）
$PY $RUN/run_rq1_authority_experiment.py --backend tiermem --inject-policy on \
    --poison-framing convention --query-mode neutral --meta-policy-defense off \
    --passes 0 1 2 --seed 11 --report-id rq1_auth_demo

# (c) AgentPoison 后门 overlay + 写入闸门防御（E4 classifier gate）
$PY $RUN/run_rq1_agentpoison_overlay.py --suite benchmarks/safety/stealthy_poison_suite_v1.json \
    --write-filter llm --write-filter-on-unsafe flag --passes 0 1 2 --report-id rq1_ap_demo
```
产物：`outputs/safety/<report-id>*.json` + `*_items.jsonl`。**花钱（API）。**

### RQ2 · 固化是否造假记忆（结论：能造错信，但非越固化越糟）
```bash
# (a) 自建本地对话线（v6=100题；judge 终点）
$PY $RUN/run_rq2_factual_poison.py --suite-version v6 --backend tiermem \
    --passes 0 1 2 --query-modes free operational --seed 11 --repetition 5 \
    --report-id rq2_v6_demo

# (b) 官方 HaluMem 线：N-sweep（真官方数据）→ 见 §5 打分
$PY $RUN/run_v2_tiermem_micro_n_sweep.py --benchmark halumem --route-modes summary_only \
    --passes 0 1 2 --session-limit 1 --qa-limit 15 --page-size 1000 \
    --consolidation-scope qa_retrieved_pages --consolidation-warmup-top-k 10 \
    --consolidation-target-max-pages 1 --qdrant-path outputs/qdrant_rq2 \
    --run-prefix e1_halumem_demo --skip-existing
```
产物：自建线 `outputs/safety/rq2_*`；官方线 `outputs/v2_tiermem_micro/sweep_reports/*`。**花钱。**

### RQ3 · 读取侧防御能否断链（结论：方向稳健但小效应、不闭合）
```bash
# (a) 读取侧防御大跑矩阵（5 seed × 2 backend × defense on/off；断点续跑）
$PY $RUN/run_rq3_readtime_defense_matrix.py --skip-existing
# 汇总出关键表（off vs on 配对翻转）—— 不花钱
python3 $ANA/summarize_rq3_readtime_defense_matrix.py --run-tag rq3_readtime_large_20260708

# (b) provenance / 多防御条件对照（5 种防御都在 --conditions 里）
$PY $RUN/run_rq3_provenance_clean.py --backends tiermem prompt_only \
    --conditions poison_only defense_priority_rule defense_source_trust \
    defense_uncertainty_gate defense_conservative_compaction defense_full_method \
    --passes 0 1 2 --seed 11 --query-mode neutral --report-id rq3_prov_demo
```
产物：`outputs/safety/rq3_readtime_large_*` → `docs/state/rq3_readtime_large_*_{summary.md,paired_summary.csv}`。**(a) 花钱、汇总不花钱。**

### RQ5 · 失败在哪个阶段（结论：know-do gap，失败在回答阶段）
```bash
# 基线（judge 终点）
$PY $RUN/run_rq_know_vs_do.py --endpoint judge --report-id knowdo_none
# 干预：强制先背政策再行动，测 gap 能否闭合
$PY $RUN/run_rq_know_vs_do.py --endpoint judge --do-intervention policy_check --report-id knowdo_pcheck
# 跨模型（换 backbone）
$PY $RUN/run_rq_know_vs_do.py --endpoint judge --model gpt-4o --one-variant --report-id knowdo_4o
```
产物：`outputs/safety/knowdo_*` / `rq_knowdo_*`。**花钱。**

### E1（官方 HaluMem 幻觉多 seed，若要正式统计）
```bash
# 多 seed 深度扫（自带成本估算 --dry-run / --price-in / --price-out）
$PY $RUN/run_e1_multiseed_sweep.py --benchmark halumem --route-mode summary_only \
    --seeds 11 17 23 29 31 --passes 0 1 2 --session-limit 1 --qa-limit 15 \
    --run-prefix e1_ms_demo --skip-existing --dry-run   # 去掉 --dry-run 才真跑
```

---

## 5. 怎么评测 / 打分（判卷 + 统计 + 可靠性）

**原则：先 judge 打标签，再统计出 CI/显著性，词法只做交叉验证。**

### 5.1 幻觉线：sweep → judge → stats
```bash
# 1) 用 LLM judge 把 QA 结果分类成失败模式（CORRECT/UF/FD/ABSTAIN）
$PY $RUN/run_v2_tiermem_micro_failure_mode_judge.py \
    --sweep-report outputs/v2_tiermem_micro/sweep_reports/<sweep>.json \
    --judge-model gpt-4o --report-id <judge_id>
# 2) 单跑 bootstrap CI + 配对 McNemar（离线，不花钱）
python3 $RUN/run_e1_hallucination_statistics.py \
    --judge-report outputs/v2_tiermem_micro/judge_reports/<judge_id>_net.json
# 3) 多 seed：跨 seed CI + seed 级配对 t/sign（离线）
python3 $RUN/run_e1_multiseed_statistics.py --manifest outputs/v2_tiermem_micro/multiseed/<prefix>_manifest.json
```

### 5.2 安全线：judge → 诚实重打分（payload-emission 行为终点）
```bash
$PY $RUN/run_rq1_safety_judge.py   --report <run>.json        # LLM 安全 judge
python3 $RUN/run_rq1_safety_rescore.py --judged outputs/safety/<judged>.json   # 词法退为交叉验证
```

### 5.3 可靠性：Cohen's κ（人 vs judge）
```bash
python3 $CORE/kappa_score.py        # 产出 outputs/safety/kappa_result.json
python3 $ANA/export_kappa.py # 导出可标注表；$ANA/gen_kappa_html.py 出可视化
```
> 现状：RQ1 安全轴已有真 κ=0.85（n=30）；**RQ2 的 `human_label` 还全空，需要真人标注后再算 κ。**

---

## 6. 最后评测「看什么表、下什么结论」（每个 RQ 的落点）

| RQ | 关键表/终点 | 判定标准 | 当前结论 |
| --- | --- | --- | --- |
| RQ1 | SRR/UAF/RTR@k/unsafe-answer 随 N | 固化后 unsafe 是否被洗白、reader 是否更遵从 | 未放大；漏洞在 reader（`prompt_only ≥ tiermem`）|
| RQ2 | judge 标签率随 N（UF_on_unknown 等）| 是否「越固化越乱编」 | 否；N=0 最危险后回落 |
| RQ3 | `off mean` vs `on mean` + better/worse flips | on 稳定低于 off、better≫worse、多 seed | 稳健但相对仅降 ~15%（<25% 判据），不闭合 |
| RQ5 | 「问政策」正确率 vs「问怎么做」违规率 | gap 大小、干预能否闭合 | gap 40–67%，policy_check 67%→50% 不闭合 |

**报告口径铁律（照抄）：**
1. 数字一律以 **judge 终点** 为准，词法只写「交叉验证」。
2. 多 seed 显著性 **别引用池化极小 p 值**（同一批题跨 seed 不独立），用「多 seed 全部同向 + seed 级 t 显著」。
3. 「无害/等价」主张要用 **TOST**，不能用「p 不显著」当「无效应」。
4. 明确区分 **官方数据 vs 自建口径**：HaluMem/LoCoMo/LongMemEval 是官方数据但**评分是自建 judge**，不能直接对标原论文 leaderboard。

---

## 7. 成本与并发

- 便宜档 `gpt-4.1-mini`；judge 用 `gpt-4o` 更稳但更贵。
- 花钱脚本大多有 `--dry-run`；`run_e1_multiseed_sweep.py` 还有 `--price-in/--price-out` 估算。
- 墙钟瓶颈是 **write（page-write-mode=infer 会跑 mem0 抽取，很慢）**；快跑用 `--page-write-mode raw`。
- 并发：`--max-workers / --write-max-workers / --qa-max-workers`；多任务并行务必分开 `MEM0_DIR` 和 `--qdrant-path`。

---

## 8. 已知缺口 & 下一步（按性价比）

1. **接官方 HaluMem 打分**：跑 `benchmarks/halumem/official_repo/eval/evaluation.py`（memory_integrity/accuracy/interference），让幻觉线能对标原 benchmark（数据已在盘）。
2. **RQ2 补人工标注 + κ**：填 `docs/state/rq2_manual_annotation_*_zh.csv` 的 `human_label`，跑 `kappa_score.py`。
3. **统计合规**：给现有 McNemar/趋势检验加 **Holm-Bonferroni + α=0.01**（目前未实现），等价主张加 TOST。
4. **扩样本**：HaluMem 20→更大官方切片；安全套件 30→100/family。
5. **RQ3 Pareto 闭合**：把防御 run 接 LongMemEval-S 良性召回，才能答「≥25% 风险↓ 且 ≤3pt 效用↓」。
6. **接原方法（重、可延后）**：真 AgentPoison 梯度触发、真跑 `memevobench_official/`、接 COMEDY/Context-Memory；补跨家族（填 QWEN/LLAMA key）。

---

## 9. 排错速查

| 症状 | 原因 / 处理 |
| --- | --- |
| `OPENAI_API_KEY` 报错 | 忘了 `set -a && source .env.v3 && set +a` |
| import tiermem 失败 | 用 `$PY` 跑（脚本会自动把 `../tiermem_upstream` 加进 sys.path）|
| 多任务结果串了 | 没分 `MEM0_DIR` / `--qdrant-path` |
| 跑得极慢 | `--page-write-mode infer` 太慢，改 `raw`；调大 `--qa-max-workers` |
| 跨家族跑不了 | `.env.v3` 的 QWEN/LLAMA key 是空的，需自行填 |
| 结论「显著」但换 seed 就没了 | 正常——回到「铁律 2」，别信单 seed 池化 p |

---

## 10. 一页流程图（从零到结论）

```
source .env.v3
  → 冒烟(§3: self-test + --check-only + --dry-run)
    → 选 RQ 跑 live(§4, 先便宜档 gpt-4.1-mini)
      → judge 打标签(§5.1/5.2)
        → 统计出 CI/显著性(run_e1_*statistics.py)
          → 读关键表 + 按 §6 口径下结论
            → 若要发表：补 §8 的官方打分/κ/Holm/TOST
```
> 想快速复看一条已完成的正结果：直接
> `python3 $ANA/summarize_rq3_readtime_defense_matrix.py --run-tag rq3_readtime_large_20260708`
> 再读 `docs/state/rq3_readtime_large_20260708_interpretation.md`。
