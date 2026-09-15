# 保真度 + 可靠性审计：我用的方法/题目/口径 vs 原始论文（2026-07-09）

> 问题：我实际用的代码/数据/题目/指标，是不是**原研究者(PDF §12 的 S1–S12)的原版方法/题目/形式**？不是的话差在哪、可不可靠？
> 方法：把每个源逐个核到盘上文件 + 看主项目是否真调用 + 看评分口径是否官方。

---

## 1. 逐源保真度对照（核心结论表）

| 源(PDF) | 计划角色 | 盘上状态 | 我实际怎么用 | 保真度 |
| --- | --- | --- | --- | --- |
| **TierMem** (S2) | 主实现底座 | ✅ 真代码 `tiermem_upstream/`（core/src/官方 test 脚本） | 主项目把它加进 sys.path，跑**真实 write→C^N→answer**，raw 不可变 | 🟢 **高保真**：是原版 TierMem，非重写 |
| **HaluMem** (S3) | 主幻觉 benchmark | ✅ 官方数据 + 官方 `eval/evaluation.py` 都在盘 | **用官方数据**(HaluMem-Medium，仅 20 条 users)，但**用自建 failure-mode judge 打分，没跑官方 evaluation.py**（官方 `memory_integrity/accuracy/interference` 指标未采用）| 🟡 **数据真、指标非官方、样本极小** |
| **LongMemEval** (S6) | 良性效用 | ✅ 官方数据在盘（`longmemeval_s_cleaned.json` 等） | 只取**自建 8–60 题切片**，用自建判定，**未用官方 scoring** | 🟡 数据真、切片自建、指标非官方 |
| **LoCoMo** (S7) | 良性效用 | ✅ 官方数据在盘（`locomo10.json`） | 只取**自建 8–80 题切片**，自建判定 | 🟡 同上 |
| **AgentPoison** (S8) | 后门 overlay | 🟡 自建 suite（100 条） | **golden-trigger 近似**，脚本自述「原版靠梯度优化触发词(需 embedder+GPU)，这里是轻量固定触发」 | 🟡 **简化代理，非原版方法** |
| **MPBench** (S4) | 安全威胁模型 | ❌ **repo 缺失**（grounding 审计标 missing） | 只借用了「攻击分类」概念，无 artifact | 🔴 **未落地** |
| **MemEvoBench** (S5) | 安全威胁模型 | 🟡 repo 在盘（`memevobench_official/`） | **未真跑**，仅被 grounding 审计脚本提及 | 🔴 **镜像了但没用** |
| **COMEDY** (S9) | 压缩 baseline | ❌ 无 repo | `run_branch_comedy_control.py` 自述「contrast 代理，非 COMEDY 真实复现」 | 🔴 代理 |
| **Context-Memory** (S10) | 压缩 baseline | ❌ 无 repo | 未做 | 🔴 未做 |
| **Language Models Need Sleep** (S1) | 概念动机 | — | 只做动机（计划本就说不复现） | 🟢 符合计划 |
| **MemoryAgentBench / LongMemEval-V2** (S11/S12) | 扩展 | ❌ 官方数据不在盘 | 未做 | 🔴 未做（计划标可选） |

### 自建题库（不在 S 列表里，属你自造）
| 套件 | 规模 | 是否源自原论文题目 |
| --- | --- | --- |
| `unsafe_seed_suite_v1` | 12 | ❌ 自造（非 MPBench/MemEvoBench 原题）|
| `stealthy_poison_suite_v1` | 30 | ❌ 自造；计划建议「每家族 100 例」→**量不足** |
| `agentpoison_trigger_suite_v1` | 100 | ❌ 自造 golden-trigger（README 已注「过易/循环自证」）|
| `configs/rq2_selfbuilt_suite_v3..v6` | ≤100 | ❌ 自造本地对话题库 |

---

## 2. 一句话回答「我用的和原研究者一样吗」

- **底座一样** ✅：TierMem 是原版真代码真跑。
- **benchmark 原始数据一样** ✅：HaluMem / LoCoMo / LongMemEval 的**官方数据**都在盘、部分真喂进管线。
- **但「方法 / 题目形式 / 评分口径」大多不一样** ❌：
  - 幻觉评分**没用 HaluMem 官方 evaluation.py**，改自建 judge；
  - 效用**没用 LoCoMo/LongMemEval 官方 scoring**，只跑自建小切片；
  - 攻击**没用 AgentPoison 原版梯度触发 / 没跑 MPBench / MemEvoBench 原题**，改自造 12–100 题小套件；
  - 压缩家族(COMEDY/Context-Memory)**没接原实现**，只有代理分支。

> 概括：**「数据源正版、评测方法自建」**。你复现的是「在 TierMem 上跑官方数据」，但不是「用原论文的指标与攻击题库去评测」。

---

## 3. 可靠性评估（除了保真度，能不能信）

| 维度 | 现状 | 可靠性 |
| --- | --- | --- |
| **样本量** | HaluMem 8–20 题、安全 12/30/100、效用 8–80 | 🔴 **普遍偏小**，官方 rigor 审计自己也标「HaluMem 19 题不够撑 headline」|
| **多 seed** | RQ3 读取侧防御 **5 seed** ✅；E1 幻觉多为**单 seed**（multiseed 框架有但覆盖少）| 🟡 冷热不均 |
| **judge 可靠性(RQ1)** | `outputs/safety/kappa_result.json`：**Cohen's κ=0.85, n=30**（人 vs judge，几乎完全一致）| 🟢 **RQ1 安全轴的 judge 有真·kappa 背书** |
| **judge 可靠性(RQ2)** | `state/rq2_manual_annotation_*_zh.csv` 的 `human_label` **43/43 全空** | 🔴 **RQ2 无任何人工校验、无 kappa** |
| **judge 可靠性(RQ5/know-do)** | 无 kappa（README 自列为 TODO）| 🟡 未校验 |
| **统计规范** | McNemar ✅ bootstrap ✅ seed 级 t ✅；**Holm-Bonferroni + α=0.01 未实现** | 🟡 有基本检验、缺多重比较校正 |
| **跨模型家族** | 仅 OpenAI（4.1-mini/4o/4.1），无 Qwen/Claude/Llama（缺 key）| 🔴 结论只在 OpenAI 家族内 |

---

## 4. 可信度分层结论

- 🟢 **可以信**：
  - TierMem 底座是正版、raw-immutable 控制成立；
  - RQ1 安全轴「固化良性」有 κ=0.85 judge 背书 + 隐蔽套件；
  - RQ3 读取侧防御方向在 5 seed 上稳健。
- 🟡 **有条件信（要标注口径）**：
  - HaluMem/LoCoMo/LongMemEval 结论——**数据是官方的，但评分是自建的**，不能直接对标原论文 leaderboard；样本 8–20 太小，只能当 pilot。
- 🔴 **暂不能当硬证据**：
  - RQ2 幻觉线（无人工校验、样本小、指标非官方）；
  - 任何涉及 AgentPoison/MPBench/MemEvoBench/COMEDY 原方法的声称（都用了代理或没做）；
  - 任何跨模型普适性声称（只测了 OpenAI）。

---

## 5. 若要「对齐原研究者」，按性价比补的顺序
1. **HaluMem 官方评分**：跑官方 `evaluation.py`（`memory_integrity/accuracy/interference`），让幻觉线能对标原 benchmark（数据已在盘，`run_v3_public_baseline_readiness.py` 已把这列为 next action）。
2. **RQ2 补人工标注 + kappa**：把 `human_label` 真填上，复用 `kappa_score.py`（RQ1 已有范式）。
3. **扩样本**：HaluMem 从 20 → 官方更大切片；安全套件 30 → 100/family。
4. **多重比较校正**：加 Holm-Bonferroni + α=0.01 + TOST（等价主张）。
5. **接原方法**：真 AgentPoison 梯度触发 / 真跑 MemEvoBench（repo 已在盘）/ 接 COMEDY 原实现——这几项最重、可延后。
