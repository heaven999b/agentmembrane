# 第一轮确认实验结果：从五条主线到可投稿问题

**冻结日期：2026-07-28**

本文是 Week 4 主报告的确认性接续。五项实验全部使用公开 benchmark / 公开研究数据；除纯离线审计外，模型请求只经过已授权的 本地授权代理。官方按量付费 API 调用为 0，`gpt-5.6-*` 调用为 0。公开报告只保留脱敏 sample ID、聚合统计、prompt hash、scorer 和资源账本；MemPrivacy 的 benchmark 正文、原始 prompt 与模型输出只保存在本机 private 目录。

## 1. 总览

| 线路 | 公开数据与正式规模 | 真实资源 | 预注册/冻结结论 | 当前定位 |
| --- | --- | ---: | --- | --- |
| Lethe OOD forgetting | 官方 ForgetEval generator；100 calibration + 150 held-out | 321 calls；230,415 tokens | `NO_GO_OR_REDESIGN` | 原风险 router 安全但不够省；转向 candidate-first safeguard |
| MemPrivacy minimum metadata | 官方 released sample；48 source blocks、四个 storage arms、五个 utility views | 685 attempts；1,305,793 tokens | 链接机制 GO；full-48 方法门 NO-GO | 当前最强 privacy–utility 研究 seed，但现方法不能部署 |
| Lifecycle BM25 confirmation | 官方 MemoryAgentBench EventQA；12 histories×3 queries×2 arms | 72 calls；1,089,463 tokens | `INCONCLUSIVE` | 朴素 retrieval 只在少数 history 有用且代价很高 |
| MemTrace causal replay | 官方 MemTraceBench；4 cases×5 seeds×5 arms | 100 calls；500,371 tokens | 预注册 `GO`，保守解释门也通过 | 正向因果机制信号；仍需更大外部确认 |
| Annotation fidelity | 官方 TRAJECT-Bench；5,670 public-native cases×4 corruption audits | local/offline；0 calls/tokens | `NO_GO`，正式 200-case policy run 未启动 | 旧 observable 不合格，先重建设计 |

合计：**1,178 次真实本地代理调用、3,126,042 tokens**。这不是五篇论文的 paper-exact headline 复现；Lethe、MemPrivacy、Lifecycle、MemTrace 的 reader/hook 均含 `gpt-5.4` substitute，Annotation 是公开数据上的离线 feature audit。

## 2. 实验架构是否达到研究报告标准

本轮不以简单 prompt 小测替代论文协议。每条线至少冻结并审计以下组件：

1. 数据来源、仓库 commit、文件 hash、license 和与旧集合的 overlap；
2. calibration / held-out 或结果前冻结的 selection manifest；
3. 完整 prompt、官方 adapter/scorer 边界、actual model 和 substitute 说明；
4. 每个 sample 的 ID、calls、tokens、持久输出引用和可复算 scorer；
5. 预注册 go/no-go、配对比较、cluster-aware bootstrap 和失败案例；
6. private/raw 与 public/redacted 产物分离。

两次独立审计实际阻断了错误结论：MemTrace 的固定 seed 重复被隔离并用五个 outcome-blind seeds 重跑；Annotation 的 `completedActionCount` schema bug 被修正后重算 5,670 条。这说明审计不是文档包装，而确实改变了可接受结论。

## 3. 五项结果与实际发现

### 3.1 Lethe：安全 router 的位置太晚

在 150 条 held-out 上：

| Policy | Accuracy | Underforget | Overdelete | Calls | Call saving | Token saving |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| never | 79.33% | 14.67% | 7.33% | 0 | 100% | 100% |
| legacy selective-50 | 81.33% | 14.00% | 6.00% | 65 | 66.15% | 67.02% |
| always | 90.00% | 10.00% | 0 | 192 | 0 | 0 |
| risk-calibrated OOD | 90.00% | 10.00% | 0 | 170 | 11.46% | 8.82% |

风险策略与 always 逐例同分、最坏语言也同为 82%，但 call saving 只有 11.46%，未达到预注册的 30%。继续调 selector 阈值没有意义。

真正的新异常是：always 的 15 个失败全部来自中文/日文；其中 6 个 `purge_phi` 在 lexical recall 阶段就得到空候选，因此 LLM hook 根本没有机会看到输入。也就是说，控制器位于 candidate generation 之后，升级决策对 candidate-empty 失败无能为力。

**新问题**：遗忘系统应否先校准 candidate coverage，再决定 mutation hook？可行方法是 multilingual dense recovery + candidate-empty abstention + mutation-level routing。下一轮不能继续扩同一 router，必须换 control-plane placement。

### 3.2 MemPrivacy：值隐私、属性隐私和链接隐私不是同一个维度

48 source blocks 覆盖 9 users、24 questions。攻击与 utility 主结果：

| Arm | Link balanced accuracy | Attribute inference | Exact value recovery | Judge-weighted utility |
| --- | ---: | ---: | ---: | ---: |
| raw/stable | 93.75% | 79.17% | 77.08% | 56.25% |
| stable typed | 100.00% | 81.25% | 0 | 48.96% |
| rotating typed | 50.00% | 89.58% | 0 | 48.96% |
| opaque session-local + gated reveal | 54.17% | 62.50% | 0 | 51.04% |

稳定 typed 相对 rotating typed 的链接差为 `+50.00pp`：sample bootstrap 95% CI `[35.42,64.58]pp`，question-cluster CI `[40.91,58.82]pp`，user-cluster CI `[38.89,57.58]pp`；9 次 leave-one-user-out 均同方向，范围 `[46.88,52.17]pp`；McNemar exact `p=1.19e-7`。

这不是“typed placeholder 更隐私”。stable typed 虽把 exact value recovery 压到 0，却让 cross-session link 达到 100%；rotating typed 把 link 降到 chance，但 attribute inference 反而为 89.58%。隐私通道发生了分离。

utility 也不是零代价。raw 相对 gated 的 judge-weighted utility 差为 `+5.21pp`，user-cluster CI `[-4.10,+22.00]pp`；gated 相对 ungated提升 `+10.42pp`，但 question-cluster CI `[-0.96,+21.25]pp`、user-cluster CI `[0,+17.16]pp`。full-48 的 gated loss `5.21pp` 超过预注册 3pp 上限，utility recovery 只有 `66.7%`、低于 80% 门，因此当前四臂方法最终 **NO-GO**。而且 gated reveal 使用 released evidence annotation，是 oracle upper bound，不是可部署 selector。

独立复算确认 685 attempts=`672` 成功+`13` transport failures，成功 scorer mismatch=0；11 个公开 artifacts 未发现 raw target text 或凭据模式。rotating link balanced accuracy=.5 也必须谨慎解释：它来自 sensitivity=0、specificity=1，即攻击者全判“不同”，不是已经击败自适应攻击者。

**新问题**：如何只暴露任务所需的 identity continuity，而不是永久暴露稳定 link？下一步应实现可学习或可校准的 reveal policy，并把 value、attribute、link、utility 四个维度同时纳入约束。

### 3.3 Lifecycle：memory retrieval 的平均增益由少数 history 驱动

在 12 个未使用 histories、每个 3 个官方 queries 上：

- no-memory EM `86.11%`，BM25 memory EM `91.67%`，配对差 `+5.56pp`；
- history-cluster 95% CI `[0,+13.89]pp`，two-level CI `[0,+16.67]pp`；
- 12/12 histories 不为负，但只有 2/12 严格为正；
- BM25 多消耗 1,026,651 tokens，只多答对 2 题，即每个额外正确答案约 513,326 tokens；
- 预注册要求 `>=10pp` 且至少 4 个正向 histories，未通过。

因此不能再把“有 memory 比无 memory 好”当作统一事实。当前观测更像稀疏收益：大量 history 没有边际增益，少数 history 承担全部收益。

**新问题**：能否在 answer 前预测 memory 的边际价值，并把固定 retrieval 成本只分配给高增益 histories？但 generic router 已拥挤；要有发表价值，必须围绕可校准的 marginal-value estimate、全生命周期成本和 abstention risk，而不是另做一个二分类 prompt。

### 3.4 MemTrace：正确证据替换的收益超过删除、无关替换和生成噪声

修正固定 seed 缺陷后，4 个公开可机械重建 cases 使用 5 个 outcome-blind seeds，且同一 case/repeat 的五臂共享 seed：

- correct replacement − baseline F1：`+0.1864`，case-cluster 95% CI `[+0.0463,+0.3880]`；
- placebo − baseline 噪声带：`[-0.0118,0]`；
- correct − length-matched deletion：`+0.1955 [0.0598,0.3948]`；
- correct − irrelevant replacement：`+0.1882 [0.0598,0.3948]`；
- 4/4 cases 同方向；leave-one-case-out 均值 `[+0.0818,+0.2350]`，无符号翻转；
- correct replacement 平均输入 token 显著更少，但 matched controls 已表明优势不是单纯删除造成。

预注册 GO 与保守解释门都通过。不过所有 arms 的 strict EM 都为 0，且最大单 case 效应为 0.5，4-case CI 仍很宽。结论只能是“correct evidence 对 token-F1 有正向机制信号”，不能写成严格答案正确率已改善。

**新问题**：在更大的、预先冻结的 retrieval-error 子集中，哪些错误类型可通过单-op replay 真正恢复 strict task success？下一步应增加 case 数、错误类型层次和外部数据，而不是在这 4 题上继续重复。

### 3.5 Annotation fidelity：旧 validator 主要识别结构类型，而不是 annotation error

修正 schema 后的 5,670 条公开 TRAJECT-Bench 审计显示：

- clean recency override 为 29.45%，95% CI `[28.28%,30.65%]`；
- parallel 全部走 CWL，sequential 全部走 recency，说明 route 被结构类型主导；
- edge deletion / insertion 只让 `15/1670=0.90%` route 改变；
- type omission 只让 `5/5670=0.09%` route 改变；order swap 为 0；
- 所有 corruption 都低于预注册 10% discrimination 门；正式 200-case policy run 因此没有启动。

这不是“结构化 eviction 没用”，而是当前 observable 对目标 annotation corruption 几乎不可辨识。继续烧模型 token 只会放大一个不合格测量器。

**新问题**：什么 observable 能在同一结构内部区分 dependency/type/order 错误，并与 downstream failure 校准？在真实 trace 双盲 annotation 与 observable qualification 完成前，本线停止模型实验。

## 4. 哪些是 trade-off / utility 结果

| 方向 | 已识别的 trade-off | 是否可直接写方法结论 |
| --- | --- | --- |
| MemPrivacy | linkability 下降约 46–50pp；utility 损失点估计约 5pp；oracle gate 可回收约 10pp | 否；缺 deployable reveal policy 和外部用户确认 |
| Lethe | 保持 always 质量时只省 11.46% calls；高节省旧 selector 损失 8.67pp 且 overdelete 6% | 原方法 NO-GO；candidate-first redesign 有价值 |
| Lifecycle | +5.56pp EM 换 +1.03M tokens；约 513k tokens/额外正确答案 | 只能说明朴素 BM25 条件性收益 |
| MemTrace | F1 +0.186，同时上下文显著变短；matched controls 支持语义证据贡献 | 机制 GO；strict utility 尚未证明 |
| Annotation | 先证明测量器无法区分错误，避免无效 token 投入 | 不是质量—成本曲线，是实验资格门 |

## 5. 重新排序后的 shortlist

### P0：Minimum-sufficient identity continuity

重设计后继续。最强证据是 stable→rotating 的链接风险差在 sample/question/user 三种统计单位上都同向；但当前 full-48 方法门已 NO-GO。真正缺口不是再做一种 mask，而是设计 deployable task-gated continuity。最小闭环：公开 MemPrivacy + 第二个公开跨会话 benchmark；rotating alias / opaque / learned reveal；自适应和多模型攻击者；按 user 冻结 split；link、attribute、value、utility、tokens 的联合 Pareto。

### P0：Candidate-first safe forgetting

由原 OOD router 方向重构。核心不是“让 selector 更准”，而是解决 candidate-empty 时 hook 永远看不到输入的问题。最小闭环：官方 ForgetEval + 第二个公开多语言 memory-mutation 集；lexical-only、dense recovery、hybrid、abstain、always 五臂；candidate recall、underforget、overdelete、calls/tokens；新的 confirmation set 上预注册。

### P1：Replay-certified retrieval repair

继续，但先扩大外部有效 cases。贡献应是 variance-aware causal protocol + 可认证 repair subset，而不是宣称 4 个例子的 F1 提升就是新方法。GO：至少 20–30 个冻结 cases、strict success 有非零改善、case-cluster CI 下界大于 0、correct 明显胜 matched deletion/irrelevant。

### P2：Marginal-value memory invocation

保留为 benchmark/measurement，不立即造方法。先在两个公开 benchmark 上证明 memory gain 的 history-level 稀疏性可重复，再与现有 selective retrieval / abstention 强 baseline 比。若现有方法已覆盖 Pareto 前沿，停止方法线。

### 暂停：Annotation-fidelity eviction

旧 observable 已 NO-GO。只有找到同结构内部可变化、对 corruption 有至少 10% route discrimination、且与真实 downstream failure 相关的 observable，才恢复正式策略实验。

## 6. 下一轮实验顺序

1. 先实现 MemPrivacy 的非 oracle reveal policy，并在现有 48 blocks 上做 calibration-only 开发；正式结论必须换 user-disjoint confirmation 或第二公开 benchmark。
2. 并行实现 Lethe 的 candidate-empty dense recovery / abstention；先离线验证 candidate recall，再决定是否调用模型。
3. 从官方 MemTraceBench 预先冻结 20–30 个机械可重建 retrieval-error cases，复用本轮五臂 CRN 协议。
4. Lifecycle 只做第二公开数据确认和强 selective-retrieval baseline；不扩大当前 BM25 网格。
5. Annotation 只做 observable/data qualification，暂不烧模型 token。

这套顺序优先解决已观察到的机制瓶颈：identity continuity、candidate coverage、retrieval repair。它们不是“成本和质量有 trade-off”这种常识，而是可以提出具体方法、明确反例和冻结 go/no-go 的研究问题。
