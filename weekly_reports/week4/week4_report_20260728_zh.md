# 第四周研究汇报：从复现论文，到找到真正需要新增的实验





本周不是完成了一篇新论文，也不是只阅读和摘抄论文。本周完成的是：**复算公开结果、真实运行官方基线、用额外对照实验检查论文结论的边界，并从中筛出两个值得继续做成新方法的问题和一个具体评测问题。**

最重要的纠正是：实验工作量不等于研究创新。下面把“别人已经做过什么”和“我们额外做了什么”分开报告。

## 1. 本周到底做了什么？



### 1.1 第一层：检查论文和公开代码能否被正确复算



| 项目 | 本周完成的工作 | 结果 | 能否称为新发现 |
| --- | --- | --- | --- |
| Lethe | 运行官方确定性遗忘流程和官方 scorer | 244/385，63.38%，与论文244/385一致 | 不能，只是精确复现 |
| Engram | 重新计算作者发布的500条输出 | lean 83.6%、full 73.2%，与作者一致 | 不能，只是公开输出复算 |
| TokenPilot | 重新计算作者发布的质量和成本账本 | 质量79.2%→81.3%；主模型成本约7.24→2.79美元 | 不能；而且辅助模块成本缺失，完整TCO不可识别 |
| GateMem | 官方数据、官方Long-Context、原生memory injection、官方prompt/judge/scorer，只替换不可用模型 | 30 checkpoints、60成功调用、211,223 tokens、scorer复算0 mismatch | 不能称paper-table复现；属于方法一致的模型替换基线 |

GateMem 纠正轮的官方指标是：utility 8/12（66.67%）、access-control answer leakage 3/9（33.33%）、active-forgetting answer leakage 0/9、answer-only MGS 44.44%。模型和30题切片与论文完整矩阵不同，因此严格标签是 **MODEL-SUBSTITUTE / PAPER-BASELINE-METHOD-EXACT**。

MemSyco 已核验官方 OFJ 数据、官方 `NoMemory` 与 `RawDialogue` 成对协议、官方 prompt/judge/scorer。首个 gate 样本4/4调用成功；50样本正式运行尚未完成，因此本报告不写效果结论。

### 1.2 第二层：不是照跑论文，而是增加新的干预、对照和失败审计


| 增量活动 | 原论文主要研究什么 | 我们额外增加了什么 | 当前证据等级 |
| --- | --- | --- | --- |
| MemPrivacy 链接攻击 | typed placeholder＋本地恢复，在隐藏敏感值时保留任务语义 | stable/rotating/opaque 四种身份表示；分开攻击值恢复、属性推断和跨会话链接；多层置信区间和配对检验 | 有实证增量，方法尚未完成 |
| MemTrace 真实回放对照 | 错误追踪、操作归因和基于归因的prompt优化 | baseline、identical placebo、正确替换、等长删除、等长无关替换五臂；多seed和common random numbers | 有因果信号，但只有4 cases |
| TRAJECT 指标有效性审计 | 轨迹结构和trajectory-aware metrics | 对5,670条公开轨迹构造28,350个结构扰动，测指标是否真的感知边、类型和顺序错误 | 具体benchmark审计，不是新memory方法 |
| Lethe 候选阶段失败定位 | LLM在不同control-plane位置对遗忘的影响 | 新官方生成的零重叠英中日数据；拆分candidate、router、hook三个阶段；统计调用/质量Pareto | 细化诊断；高层问题原论文已研究 |
| Supersede 全生命周期成本 | bounded memory在事实更新任务上的准确率缺口 | 108个预算/跨度/维护频率条件；加入写入维护成本、延迟和utility crossover | 复现扩展；高层结论原论文已研究 |
| MemoryAgentBench 边际价值 | 记忆系统的检索、学习、长程理解和遗忘能力 | no-memory/BM25配对；按history统计收益集中度；计算每多答对一题的token成本 | 小样本诊断，不构成创新 |

### 1.3 第三层：根据负结果停止不值得继续烧资源的方向

- Lethe 原选择性 router 在新 held-out 数据上只节省11.46% calls，未达到30%门槛，停止继续调同一个阈值；
- MemPrivacy 当前 oracle-gated 方法效用损失5.21个百分点、恢复率66.7%，未达到≤3%和≥80%的门槛，当前方法 NO-GO；
- MemoryAgentBench BM25 只多答对2题却增加1,026,651 tokens，没有达到预注册提升门；
- TRAJECT 旧 observable 对关键结构扰动的感知率远低于10%，因此没有启动后续200条模型实验；
- 固定字符预算摘要在当前108条件矩阵中被完整上下文支配，不再继续扫100/150/200/300/400字符；
- 旧 LongMemEval、Agent-Native、MemSyco custom 和 GateMem shadow-adapter 结果不再计为论文复现证据。

## 2. 本周真正新增的实验证据

### 2.1 增量一：typed placeholder 隐藏了值，却可能强化跨会话追踪

MemPrivacy 原论文使用有语义的类型占位符，例如把真实邮箱替换成稳定的 `<EMAIL_1>`，再在本地恢复原值。原论文重点评估敏感信息识别和任务效用。

我们额外问了一个不同的问题：**云端虽然看不到真实值，能否仍然根据稳定占位符判断两段会话属于同一个人？**

本轮使用公开 MemPrivacy 数据的48个 source blocks、9个用户和24个问题，执行685次尝试、约130.6万 tokens。四种表示的结果是：

| 身份表示 | 精确值恢复 | 属性推断 | 跨会话链接 balanced accuracy |
| --- | ---: | ---: | ---: |
| 原始身份 | 77.08% | 79.17% | 93.75% |
| 稳定 typed placeholder | 0% | 81.25% | 100% |
| 每会话旋转 placeholder | 0% | 89.58% | 50% |
| 不透明会话身份 | 0% | 62.50% | 54.17% |

稳定到旋转的链接差异为50个百分点，McNemar `p=1.19e-7`，在source block、question和user聚类口径下方向一致。

这里真正新增的不是“元数据可能泄露隐私”这句常识，而是：

> **同一种脱敏方案可以把真实值恢复降到0，却把跨会话链接提高到100%。值隐私、属性隐私和链接隐私不能被一个总privacy分数代替。**

但这还不是完整方法。当前旋转臂的50%主要来自攻击者总是猜“不同用户”，需要加入自适应 lexical attacker、多个独立LLM attacker和用户互斥的外部确认。

### 2.2 增量二：用五臂实际回放检查错误证据是否具有因果作用

MemTrace 原论文能够定位错误操作，但论文也说明“理想化修复”主要用于定义决定性错误，并没有对每个候选操作完整回滚和重放，因为长期状态重建昂贵且后续模块仍可能失败。

我们从官方 MemTraceBench 冻结4个可机械重建的 retrieval-error cases，每个case使用5个 outcome-blind seeds，增加五个实验臂：

1. 保留原始错误证据；
2. 完全相同的placebo输入；
3. 替换为正确证据；
4. 删除相同长度内容；
5. 替换成相同长度的无关内容。

共100次调用、500,371 tokens。结果：

- 正确替换相对baseline：F1 `+0.1864`，case-cluster 95% CI `[0.0463, 0.3880]`；
- 正确替换相对等长删除：`+0.1955`；
- 正确替换相对无关替换：`+0.1882`；
- placebo波动接近0；
- 4/4 cases方向相同。

这说明收益不能只用“上下文变短”或随机生成解释。但所有臂的strict exact match仍为0，所以当前只证明了小范围因果信号，没有证明自动修复系统已经成功。

### 2.3 增量三：TRAJECT 的旧指标几乎感知不到结构内部错误

TRAJECT-Bench 宣称提供trajectory-aware metrics。我们没有直接相信指标名称，而是检查指标是否满足最基本的有效性要求：当必要依赖边、类型或执行顺序被破坏时，指标是否变化？

在5,670条公开轨迹上构造28,350个可复算扰动后：

- 删除或插入依赖边，旧路由只改变15/1,670，约0.90%；
- 删除类型信息，只改变5/5,670，约0.09%；
- 交换执行顺序，改变0次；
- 但干净数据中有29.45%被切换到保守方案。

这不是“benchmark可能有bug”的泛泛说法，而是针对一个具体observable的测量有效性证据：它更像是在识别parallel/sequential大类，而没有测量大类内部的依赖是否正确。

## 3. 哪些结果不能再冒充我们的创新？


### 3.1 Lethe 的control-plane placement不是我们提出的

[Lethe原论文](https://arxiv.org/abs/2606.15903)标题就是 *Control-Plane Placement Shapes Forgetting*，并已经比较13种系统配置、不同LLM放置位置和跨语言失败。我们新增的是更窄的 `candidate-empty` 代码路径诊断和调用成本分析，不是发现了control plane这个问题。

### 3.2 Supersede 已经发现bounded memory的maintenance gap

[Supersede原论文](https://arxiv.org/abs/2606.27472)已经报告full context 92%、bounded memory 77%，并将瓶颈归因于memory maintenance。我们的108条件矩阵增加了全生命周期成本和Pareto证据，但不能说第一次发现固定摘要有问题。

[Agent Memory系统分析](https://arxiv.org/abs/2606.06448)也已经分别统计construction、retrieval和generation成本，并讨论写侧/读侧成本和查询量摊销。

### 3.3 选择性调用记忆已经是拥挤方向

[BudgetMem](https://arxiv.org/abs/2602.06025)已经做query-aware budget routing并优化准确率—成本前沿；AdaMem、TraceRetain等工作也在做条件检索和选择性保留。因此“有些问题不用记忆”不是新方向。我们的2/12收益集中只能作为是否值得继续研究的诊断信号。

### 3.4 GateMem明确不认证物理删除

[GateMem原论文](https://arxiv.org/abs/2606.18829)定义的是agent接口上的不可恢复，并不认证数据库、向量索引、缓存、摘要或模型参数中的物理删除。[Deployment-Time Memorization](https://arxiv.org/abs/2606.10062)也已经研究derived memory tier中的deletion residue。

我们的9/9上下文暴露、0/9最终答案泄露，是官方Long-Context baseline的具体刻画，不是第一次区分“没说出来”和“真正删除”。

### 3.5 Counterfactual repair也不是空白领域

[MemTrace](https://arxiv.org/abs/2605.28732)已经研究长期记忆错误归因；[CausalFlow](https://arxiv.org/abs/2605.25338)已经对agent trace进行反事实干预和最小修复。我们的潜在贡献只能放在它们没有完成的窄问题上：**长期持久状态的真实回滚/重放、与匹配负对照共同形成可审计的因果证书。**

### 3.6 Benchmark audit已有系统研究

[Automated Benchmark Auditing](https://arxiv.org/abs/2605.26079)已经对168个benchmark系统审计。我们的新意只可能是针对[TRAJECT-Bench](https://github.com/PengfeiHePower/TRAJECT-Bench)这个具体指标的可复现失效证据，而不是发明benchmark audit。

## 4. 最诚实的本周贡献清单

| 类型 | 数量 | 本周交付 |
| --- | ---: | --- |
| 发布结果复算 | 3 | Lethe、Engram、TokenPilot |
| 方法一致、仅模型替换的基线 | 1 | GateMem Long-Context 30 checkpoints |
| 有潜力的窄实证增量 | 2 | MemPrivacy链接攻击；MemTrace五臂真实回放 |
| 具体benchmark审计 | 1 | TRAJECT结构扰动敏感性 |
| 工程/失败定位增量 | 2 | Lethe candidate-empty；Supersede全生命周期成本矩阵 |
| 完整新方法 | 0 | 尚未完成 |
| 可直接投稿的完整结论 | 0 | 尚未完成多数据集、强基线和外部确认 |

所以本周不能说“提出了七个新发现”，也不能说“什么都没有做”。准确说法是：

> **完成了复现与证据筛选，并产出两个可继续做成新方法的研究缺口和一个具体评测缺口；其他重复或拥挤方向已经降级或停止。**

## 5. 接下来已经启动的增量实验

### 5.1 Task-Scoped Unlinkable Memory

研究问题不是“怎么mask更多”，而是：

> 怎样让默认跨会话记录不可链接，只在当前任务被授权且确实需要时临时恢复最小身份连续性？

首轮设计：

- 公开 MemPrivacy/PersonaMem 或其他公开跨会话数据；
- user-disjoint calibration/confirmation；
- raw、stable typed、rotating session alias、task-scoped non-oracle reveal四臂；
- lexical attacker＋至少两个独立LLM attacker；
- value、attribute、linkability、utility、tokens联合Pareto；
- 不使用oracle正确证据决定何时恢复。

GO条件：链接风险下降在自适应攻击者下仍成立；效用损失≤3个百分点；任务恢复率≥80%。

### 5.2 Stateful Counterfactual Replay Certification

研究问题不是“能不能定位错误”，而是：

> 能否对长期记忆状态执行最小回滚和真实重放，并用负对照证明修复操作确实导致最终任务恢复？

首轮设计：

- 冻结20–30个官方 MemTraceBench retrieval-error cases；
- 使用自动 detector/editor，不由人；
- 至少3个outcome-blind seeds和common random numbers；
- strict task success为主指标，F1、repair precision、replay cost为辅指标。

GO条件：strict accuracy的置信区间下界大于0，并且repair显著胜过等长删除与无关替换。

### 5.3 TRAJECT Observable Validity Confirmation

研究问题不是“再造一个打分器”，而是：

> 一个trajectory metric的变化能否预测真实工具执行失败？

首轮只做公开数据上的离线门：保持parallel/sequential大类不变，改变必要依赖、参数数据流和工具顺序可执行性；比较旧observable与至少两个候选新observable的单调敏感性，再用公开可执行子集验证metric变化是否对应真实execution failure。资格门不过就停止，不调用模型。

## 6. 本周资源账本

原五线确认实验共完成1,178次真实本地代理调用、3,126,042 tokens。GateMem纠正轮新增60次调用、211,223 tokens；MemSyco gate新增4次调用、4,364 tokens。按当前独立账本合计至少1,242次调用、约334.2万 tokens。

所有正式实验：

- 只使用公开benchmark或公开研究数据；
- 官方按量付费API调用为0；
- `gpt-5.6`调用为0；
- 对外报告保留sample ID、实际模型、calls/tokens、持久输出和可复算scorer；
- 模型、数据、方法、切片或scorer不同的结果，不与论文表格直接比较。




## 8. 技术附件

- [第一轮五线确认实验完整数据](./round1_followup_results_20260728.md)
- [逐论文baseline数字对照](./baseline_replication_matrix_20260728.md)
- [Research proposal路线图](./research_proposal_roadmap_20260728.md)
- [下一阶段投入与停止标准](./investment_decision_20260728.md)
