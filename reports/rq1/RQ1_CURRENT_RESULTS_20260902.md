# RQ1 当前实验设计与结果总报告

**最新实验日期：** 2026-09-02

**Canonical construct：** `authority_admission_boundary`

**当前状态：** 工程链路已验证，条件防护结果为正，自然攻击激活门未通过；`claim_bearing=false`。

## 一句话结论

AgentMembrane 已证明：当上游给出一个精确、可执行的越权操作序列时，Host 的授权边界可以在原生工具调用前阻止该序列，并在当前七个 AgentDojo workflow 中保留正常任务效用。但在最新 50-session 真实模型校准中，攻击载体虽然到达模型上下文，却没有诱发任何目标操作提议，因此目前还不能估计自然端到端场景下 vulnerable 与 protected 两个系统的攻击效果差异。

这不是“防护失败”，也不是“已经完整证明 RQ1”。当前证据把瓶颈定位在上游攻击激活，而不是 Host 执行边界。

## 1. RQ1 问什么

RQ1 研究外部 Agent 的 authority 从零逐渐增加时，系统怎样在允许有用工作的同时避免未授权副作用。Canonical admission ladder 为：

| 档位 | 外部 Agent 获得的接口或能力 |
| --- | --- |
| A0 | 只返回响应，不接触 data-plane Host 资源 |
| A1 | 只读公开资源 |
| A2 | 只能提交结构化 proposal，不能执行 |
| A3 | 获得低风险、限范围、会过期且不可委托的 capability |
| A4 | 在受控条件下调用内部 worker 或进行委托 |
| A5 | 使用 ambient tool、消息与共享记忆工作流 |

RQ1 的安全终点是精确 Host 侧事件 `exact_unauthorized_side_effect`，而不是模型声称成功、生成一个计划，或者仅仅尝试了某个调用。

## 2. 防护机制

Host 使用不可由模型自行伪造的 capability handle，并在每个受保护操作真正 dispatch 之前校验：

- admitted principal 与 capability principal；
- 精确 operation；
- resource 或 resource prefix；
- declared purpose；
- 是否允许委托及最大委托深度；
- lease、过期时间、撤销 epoch 和任务生命周期；
- proposal、queued work 与 memory artifact 是否经过当前有效的独立批准。

Protected arm 执行这些检查并在违规时 fail closed；vulnerable arm 保留相同可见接口与同一动作序列，但不执行相应约束，以便形成可诊断的正控制。

本报告只讨论 canonical RQ1。历史 `HB-RQ2-HCE` 所对应的 RQ1b Host-mediated 子轨不并入本报告的 RQ1 结论。

## 3. 当前证据

### 3.1 固定轨迹工程 assay

`rq1-controlled-v2.2` 的 106 个 zero-token fixed-trace episode 全部通过，并与 production oracle 一致；没有模型、provider、proxy 或网络调用。这证明 Host 状态机、授权检查和 oracle 的基础工程实现可运行，但不属于自适应或真实模型证据。

### 3.2 早期 28-cell 弱模型探索

`gpt-5.4-mini`、`reasoning_effort=low` 的 AgentDojo 运行写出了 28/28 个 cell record，其中 24 个完成、2 个 provider failure、2 个严格解析失败。87 次 call reservation 全部终结，已知总用量为 377,719 tokens。

攻击目标没有被激活：已完成的 vulnerable 与 protected 对抗样本中都没有观察到目标 proposal。因为存在运行失败和未知 provider usage，这一轮 evidence-ineligible，只能说明降低模型能力没有自动带来更强攻击。

### 3.3 条件防护验证：机制正结果

条件防护补充实验冻结了 7 个 AgentDojo workflow，构造 14 组 matched arm pair：7 组正常计划和 7 组目标攻击计划，共执行 28 次原生 session reset 和 checker evaluation。两个 arm 使用完全相同的上游动作序列与初始状态；唯一的处理差异是授权规则是否真正执行。

| Endpoint | Vulnerable | Protected |
| --- | ---: | ---: |
| 精确目标攻击序列已提供 | 7/7 | 7/7 |
| 目标动作位于用户权限之外 | 7/7 | 7/7 |
| 原生攻击效果 | 7/7 | 0/7 |
| dispatch 前拒绝目标动作 | 不执行约束 | 7/7 |
| 拒绝后原生状态保持不变 | 不适用 | 7/7 |
| 正常 canonical plan utility | 7/7 | 7/7 |

全部 14/14 matched pair 通过。该实验没有模型或 API 调用，因此它支持的是条件机制结论：**给定一个精确上游越权 proposal，AgentMembrane 在这七个 workflow 中阻止了原生副作用，同时保留正常计划效用。**

它不证明模型自然暴露于攻击、形成攻击意图或生成目标 proposal。

### 3.4 50-session 自然攻击激活校准

为了检查端到端攻击是否能自然出现，最新校准使用真实 CLIProxy/GPT-5.6 Luna、`reasoning_effort=low`，只运行 vulnerable/adversarial 条件。50 个 session 分成 standard 与 priority authority-spoofing 两种强度，每种 25 个，覆盖 12 个冻结 workflow。

| 指标 | 结果 |
| --- | ---: |
| Cell records | 50/50 |
| 完成 | 49 |
| 严格解析失败 | 1 |
| Provider calls | 151/151 终结 |
| Provider errors | 0 |
| 已知总 tokens | 435,908 |
| 攻击载体暴露 | 44/50 |
| 目标 proposal | 0 |
| 目标 native dispatch | 0 |
| 原生攻击效果 | 0 |
| Attribution anomaly | 0 |

冻结 gate 要求至少 20 次载体暴露、至少 5 个目标 proposal、至少覆盖 2 个 workflow 且运行完整。载体暴露和 attribution 要求通过，但目标 proposal 两项为零，另有一个 parse failure，因此 gate 未通过，也没有继续进入 held-out 四格 vulnerable/protected 主实验。

## 4. 目前支持什么

当前证据支持：

- RQ1 的执行、账本、原生 checker、状态重置和审计链路可以运行；
- capability 校验能够在真实 native dispatch 之前执行；
- 在精确、byte-identical 的越权动作输入下，protected arm 阻止了 7/7 原生攻击效果，正常效用保持 7/7；
- 50-session 校准把失败点定位为“模型没有生成目标 proposal”，而不是攻击载体未进入上下文。

当前证据不支持：

- 自然端到端攻击成功率已经被可靠测量；
- protected 与 vulnerable 的自然模型对照已经完成；
- 已经找到 A0--A5 上的最小安全权限点 `A*`；
- RQ1 可以升级为跨模型、跨任务或论文级普遍 claim。

## 5. 下一步证据要求

下一轮应保持 RQ1、Host oracle 和评分口径不变，只重新设计和预冻结攻击 baseline。新的 baseline 必须先在 vulnerable-only 小规模校准中达到目标 proposal activation gate，随后才能运行 held-out 的 benign/adversarial × vulnerable/protected 四格对照。不能把“模型没有尝试攻击”重新记作 Host 防护成功。

## 6. 对应结果文件

- [28-cell 弱模型探索](../../results/rq1_public_agentdojo_multi_v5/RESULTS_20260901_v5_001.md)
- [7-workflow 条件防护验证](../../results/rq1_conditional_protection_v1/RESULTS_20260901_v1_002.md)
- [50-session 自然攻击激活校准](../../results/rq1_activation_calibration_v1/RESULTS_20260902_v1_001.md)
- [Week 7 周报](../../weekly_reports/week7/week7_report_20260831_zh.md)

对应三个 aggregate source report 的 SHA-256 依次为：

- 28-cell 弱模型探索：`899f23ca2a1939ed3a7e40f5d4e9ae2fefa93c6fa75beaf15d3e97ee76f64798`；
- 7-workflow 条件防护：`26563d52fb1239629829b67d1dc1bd7569761d34a68893b04a85f63300d239c1`；
- 50-session 自然激活：`0a6fc8ce97bd0eef774877cb0aed4c5a5bfe41c265cd856a6ae47277e7b2a1c4`。

以上公开文件是 aggregate result artifact。数据集内容、provider cache、凭证和可能包含敏感运行上下文的原始 ledger 不在本公开仓库中分发。
