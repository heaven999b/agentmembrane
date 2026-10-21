# Week 14 汇报：Harness 如何影响 Agent 的灰度决策

报告日期：2026-10-21。上一期为 [Week 12（2026-10-07）](../week12/README.md)；本期集中发布截至 2026-10-16 的精简 Proposal、RQ Detail 与当前结果。这里的日期表示周报发布，不表示全部实验都在这两周新增完成。

## 当前研究问题

研究 Harness 对信息的保留与表达、证据获取和执行门控，怎样影响 Agent 的错误执行与正常任务完成。现有实验主要覆盖“环境事实确定，但 Agent 的信息不完整”；条件偏好、冲突要求和真正多解仍是更广的理论动机，尚未被当前题集充分覆盖。

例如，用户指定台灯规格，同伴提供的合法编号却指向另一款。Harness 可以只说“查不到”、只说“不符”、点名实际商品或提供查询；核验后可以给继续按钮、允许重发或拒绝执行。实验分别检查这些处理怎样影响可见信息、Agent 行动和实际状态变化。

## 各 RQ 的当前状态

| RQ | 当前回答 | 解释边界 | 对应材料 |
|---|---|---|---|
| A：现象 | 合法错值可以进入真实操作，正常有效性参照用于检查基础任务能力 | 结论限于所测委派任务和筛选题集 | [核心结果](./supporting/results/core_primary.md) |
| B：信息与查询 | 具体反馈内容影响行为；开放查询与一句查询提醒的结果需要分别看 | 提醒使查询增加，但错误写入下降尚无明确证据；部分比较同时改变信息量 | [第 2 段](./supporting/results/p0_s2_summary.md)、[E1](./supporting/results/e1_summary.md) |
| C：执行门控 | 出口设计改变执行；全面拒绝也会阻止未登记的合法真值 | 低写入不能单独解释为模型判断改善 | [出口](./supporting/results/rqc_summary.md)、[四因素](./supporting/results/factorial_summary.md) |
| D：处理机制 | 执行端见证与意图核对在所测任务中能兼顾安全和正常完成 | 主批方法优势未通过原检验；扩题有支持，不能替换主批判定；E2 未覆盖仍有多个兼容候选的取舍 | [主批](./supporting/results/p0_gate_summary.md)、[扩题](./supporting/results/p0_ext_summary.md)、[E2](./supporting/results/e2_summary.md) |
| E：稳健性 | 第二 H 模型对部分信息／出口比较提供复核 | 同供应商、部分 RQ；AgentDyn 未完成见证方法的完整跨环境复现 | [第二模型](./supporting/results/luna_primary.md)、[AgentDyn](./supporting/results/ad_baselines_final.md) |
| 边界 | 证据来源、封存时机和说服路径需要单独检验 | 红队总写入与 strict 静默不是同一指标；择优阶段只按描述性范围解释 | [规则边界](./supporting/results/p0_bd_summary.md)、[红队](./supporting/results/p0_rt_summary.md) |

## 本期交付

- [精简 Proposal](./docs/PROPOSAL_CURRENT_zh.md)：研究问题、重要性、整体设计、已有结果与实验附录。
- [RQ Detail](./docs/RQ_DETAIL.md)：各 RQ 对应的实验条件、工具接口、日志、指标、判定和结果。
- [结果索引](./supporting/results/README.md)：20 组 Markdown / JSON，保留原有分析口径与结论。
- [完整研究包](./supporting/SOURCE_PACKAGE.md)：代码、协议与原始运行记录的定位入口。

## 读表范围

核心主题集和各批预注册主检验、扩题稳健性、跨批参照以及探索性估计分别报告。E1/E2 只报估计；题内重复与同源簇不当作独立样本。这里汇总当前证据，不新增实验或改变原判定标准。
