# Week 4 Research Proposal Roadmap

**日期：2026-07-28**

> 2026-07-28 五线确认实验已完成。下表与最终建议已按新证据更新；详细统计见[第一轮五线确认实验结果](./round1_followup_results_20260728.md)。

## 1. 从“本周结果”到“完整论文”还差什么

当前已经具备：真实 baseline 结果、公开产物复算、失败案例、成本账本、部分 held-out 验证和明确 NO-GO。

仍缺：一个聚焦的问题、一项明确方法、两个外部数据来源、强 adaptive baselines、跨模型确认和冻结的统计方案。

## 2. 方向排序

| Rank | Direction | 当前证据 | 新颖性（收窄后） | 完成度 | 决定 |
| ---: | --- | --- | --- | --- | --- |
| 1 | Minimum-sufficient identity continuity | MemPrivacy 48-source；stable→rotating link -50pp 且 user-cluster 稳健 | 中高 | 中高 | 主 proposal；实现非 oracle reveal + 外部确认 |
| 2 | Candidate-first safe forgetting | Lethe risk router NO-GO；6个 candidate-empty 失败定位 control-plane bug | 高（收窄后） | 中 | 重构 candidate recovery/abstention，不再调原 router |
| 3 | Replay-certified retrieval repair | MemTrace 五臂100-call GO；correct 明显胜删除/无关替换 | 中高 | 中 | 扩20–30 cases并改用 strict success 主终点 |
| 4 | Marginal-value memory invocation benchmark | 12 histories 仅2个正向；每额外正确约513k tokens | 中 | 中 | 第二数据确认稀疏收益；暂不造 generic router |
| 5 | Annotation-fidelity observable redesign | 5,670 audit；route discrimination最高0.90% | 中 | 低 | 原 validator NO-GO，先重做 observable |
| 6 | Evidence-sufficiency certificate + selective fallback | Engram representation failures | 低到中 | 中 | 普通版本撞题；仅保留 certificate 版本 |

## 3. 生命周期方向：改为 benchmark，不再直接作为主方法 proposal

### Benchmark framing

**When Does Agent Memory Pay Off? A Full-Lifecycle Audit across Update Density and Query Reuse**

### Research question

在更新密度、未来复用概率、冲突风险和完整生命周期成本共同约束下，现有 memory methods 什么时候真正产生正 utility，什么时候因 write amplification 被 full context 或朴素策略支配？

- 对比对象必须包括 Memory-R1、DeltaMem、Infini Memory、MemCon，以及 always-full/fixed-periodic/no-maintenance；
- 先做统一测量；只有发现稳定空白区域后，才决定是否提出新 scheduler。

### 为什么不是常识

“不要每轮都更新”是常识；可发表的问题必须回答：

- every-session rewrite 的 write amplification 有多大；
- 哪些在线可观测量能预测 full rebuild 的必要性；
- delta 何时因碎片化、冲突或 stale state 失效；
- 在 update density × reuse count × cache regime 的哪个区域，不同策略进入 Pareto frontier；
- 计入所有辅助调用后，结论是否仍成立。

### Measurement sketch

统一 ledger 记录 write/extract/consolidate/retrieve/answer/judge/sidecar，并操纵 update density、reuse count、history length 与 cache regime，画出 method ranking 的 phase diagram。

### Required baselines

1. no maintenance；
2. always full rewrite；
3. fixed-periodic rewrite；
4. fixed token-budget summary；
5. Memory-R1；
6. DeltaMem；
7. Infini Memory；
8. MemCon。

### Required datasets

- 一个长对话、状态持续更新的数据集；
- 一个 agent/tool trajectory 数据集；
- 每个 history 至少三个独立 future queries，确保 maintenance setup cost 可以真实摊销。

### Metrics

- task success / answer correctness；
- stale fact、conflict、missing update；
- write amplification；
- write/extract/consolidate/retrieve/answer/judge/sidecar tokens；
- p50/p95 latency；
- cache-sensitive 与 all-cold TCO；
- Pareto frontier 与 phase diagram。

### Go / no-go

GO：发现至少一个跨数据/模型稳定的 workload 区域，使现有方法排名发生可解释反转，或现有所有方法都被一个简单策略支配；这时才有新 scheduler 的空间。

NO-GO：统一计量后现有 MemCon/DeltaMem 已覆盖全部 Pareto 前沿，且没有新的测量反转；此时只保留 benchmark/audit 贡献。

## 4. 第一 proposal：OOD-aware selective forgetting

### Observation

Lethe selective-50 在 external305 上仅比 always 低 3.93pp，却节省 53.48% calls 和 59.29% tokens，0 over-delete；跨语言组却低 26.7pp。

### Research question

如何在 under-forgetting 与 over-deletion 代价不对称时，用 OOD detector 或 conformal risk control 保证最坏组风险，并在安全区域减少 LLM hook？

### Missing pieces

- 新 seed、与旧集合零文本 hash 重叠的多语言数据；
- language/script/paraphrase/attack-template 三类 OOD；
- never/always/rule/embedding/LLM/conformal selector；
- risk@coverage、worst-group、underforget、overdelete、calls/tokens；
- selector calibration/test 完全分离。

### No-go

如果新语言上为满足风险上限必须接近 100% always-hook，则 selective 方法没有部署价值。

## 5. 第二 proposal：minimum-sufficient metadata

### Observation

MemPrivacy controls 显示具体值恢复很少，但 coarse type 与跨会话链接结构本身显著改变 attribute/linkability；效用随任务强烈变化。

### Research question

对完成某类记忆任务而言，最少应暴露哪些类型、身份和链接信息？

### Method sketch

- coarse semantic type；
- session-rotating alias；
- task-gated reveal；
- 必要时才恢复稳定 identity link；
- confidence-tagged dependency。

### Missing pieces

- 实现编码方案，而不是只做 swap/shuffle；
- 个性化、时间连续性、跨会话检索三类任务；
- raw ID、hash、session-local ID、opaque、noise/DP baselines；
- utility、attribute risk、linkability、exact recovery、tokens 的联合 Pareto；
- 多攻击者、多模型、辅助知识 threat model。

## 6. 条件方向

### Representation-risk-aware fallback

普通的“何时检索/何时注入”已经拥挤。只有做成 **evidence-sufficiency certificate + provenance coverage + calibrated selective risk + local/full fallback** 才值得独立投稿。

### Annotation-fidelity-aware eviction

“坏标注会伤性能”没有新意。可发表版本必须证明存在可观测的 annotation-fidelity phase transition，并在真实 agent traces 上用风险校准 fallback 改善任务成功，而不是只在 synthetic cases 上提高 recall。

### Variance-aware causal replay

适合作为全部 proposal 的共同实验规范：identical-prompt placebo、matched-length deletion、irrelevant replacement、重复采样和 hierarchical analysis。

## 7. Related-work collision boundary

以下 broad headlines 已经拥挤，不能直接当创新：

- selective memory retrieval / abstention：[Learning When to Remember](https://arxiv.org/abs/2604.27283)
- proactive selective memory intervention：[Remember When It Matters](https://arxiv.org/abs/2607.08716)
- selective add/delete management：[How Memory Management Impacts LLM Agents](https://arxiv.org/abs/2505.16067)
- learned ADD/UPDATE/DELETE/NOOP：[Memory-R1](https://arxiv.org/abs/2508.19828)
- incremental residual memory：[DeltaMem](https://arxiv.org/abs/2606.03083)
- buffer + periodic consolidation：[Infini Memory](https://arxiv.org/abs/2606.10677)
- learned retrieve/consolidate/forget controller：[MemCon](https://arxiv.org/abs/2607.13591)
- memory vs long-context cost break-even：[Beyond the Context Window](https://arxiv.org/abs/2603.04814)
- agent unlearning / selective forgetting：[Agentic Unlearning](https://arxiv.org/abs/2602.17692)
- dependency-structured memory：[ContextWeaver](https://arxiv.org/abs/2604.23069)

本项目需要坚持的差异点：

- 生命周期方向做跨方法统一 TCO 与 workload phase diagram，而不是声称 delta/controller 本身新；
- persistent-memory mutation 的非对称遗忘风险、worst-group 与 OOD safety fallback；
- identity linkability 下的 rotating alias / task-gated reveal；
- annotation fidelity 的真实错误率、相变和风险控制；
- 所有方法使用 locked policy、fresh seed、zero-overlap 与 variance-aware causal controls。

## 8. 完整 research baseline 的最低交付清单

1. 一个可证伪的单句研究问题；
2. 一项明确方法，而不只是指出已有 baseline 有问题；
3. 两个数据来源，至少一个真正外部 held-out；
4. 4–6 个强 baselines，至少一个 adaptive/learned baseline；
5. 同样本、同模型、同预算的配对比较；
6. 端到端质量、风险、成本和延迟；
7. 机制消融与失败案例分类；
8. 至少两个模型栈；
9. 锁定参数、fresh seed、零重叠和置信区间；
10. sample-level outputs、scorer、账本和运行说明；
11. 明确 exact / substitute / mechanism / exploratory / NO-GO；
12. 大规模实验前完成正式 novelty collision audit。

## 9. Final recommendation

- 主攻：minimum-sufficient identity continuity；把 rotating alias 提升为非 oracle、可校准的 task-gated reveal，并做第二公开 benchmark / user-disjoint 确认；
- 第二线：candidate-first safe forgetting；修复 candidate-empty blind spot，再做 mutation-level routing，而不是继续调原 OOD selector；
- 第三线：replay-certified retrieval repair；扩大公开有效 cases，并以 strict task success 验证单-op repair；
- 生命周期方向只确认 marginal-value sparsity 和完整 TCO，不直接再造 generic controller；
- Annotation 原 observable 已 NO-GO，先重建设计；其余方向并入评测/机制章节，不把多条线硬塞进一篇论文。
