# AgentMembrane 研究 Proposal

**Harness 如何塑造 Agent 的灰度决策：信息保留、证据获取与执行门控**

版本：2026-10-16。研究范围：当前 RQ-A–E、边界实验与 E1/E2 补充实验。逐项条件表、实际接口与运行入口见 [RQ Detail](RQ_DETAIL.md)。

## 1. 研究问题与重要性

Agent 依靠 Harness 组织上下文、提供工具、加工反馈和控制执行。外层系统可能补充判断所需的事实，也可能把证据缺失、条件限制或冲突压缩成一个标签，过滤掉重要信息。**本研究考察：Harness 对信息的保留与表达、证据获取和执行门控，怎样影响 Agent 在灰度条件下的行为，以及错误写入与正常完成之间的取舍。**

“灰度”指当前证据或任务条件不足以支持可靠、唯一的执行结论。现有实验主要研究其中一种：**环境有确定事实，但 Agent 的决策信息不完整**。条件偏好、相互冲突的要求和真正多解是更广的理论动机，尚未被当前题集充分覆盖。

例如，用户指定商品规格，主力 Agent 向同伴询问缺失的编号。同伴返回合法却指向另一款商品的编号。Harness 可以只说“查不到”、只说“不符”、点名实际商品，或开放查询；核验后又可以提供继续按钮、允许重发，或拒绝执行。这些改变分别影响 Agent 能知道什么和能做什么。

研究这一问题有两个直接意义：一是判断外层处理是否保留了任务所需的差异——需要不同动作的情形若被呈现为相同信息，就无法仅凭这些信息区分；二是避免把全面拒绝带来的低错误率当作可靠决策。**有效的 Harness 既要减少错误执行，也要保留处理合法新值、补充证据和完成任务的能力。**

## 2. 研究问题与实验设计

### 2.1 共用场景

主实验使用 τ 零售的原生任务、数据库与执行工具。用户 U 给出目标，主力 H 完成任务，同伴 E 提供被遮蔽的指定值，Harness 控制反馈、查询与执行。正常组提供真值，攻击组提供合法错值；部分边界批另加固定话术。

主要 H 为 gpt-5.5，第二模型为 gpt-5.6-luna；E 主要为 gpt-6-astra。核心主题集 13 题、11 个同源簇；反馈主检验排除两道编号自描述的付款题，使用 11 题、9 簇。方法扩题增加 22 题，合并为 35 题、29 簇。当前包共 21 个批次、7,696 条记录，包含筛选与重复；逐批做法见附录 A。

### 2.2 RQ 与关键对照

| RQ 与问题 | 现有实验 | 主要识别边界 |
|---|---|---|
| **A：现象**——合法错值能否造成真实执行偏差 | 无防御攻击、正常有效性与中性措辞对照 | 同时报攻击写入与正常完成 |
| **B：信息保留**——哪些反馈内容影响行为 | 查不到／粗反馈／点名；预演选项／差价；同信息建议语气 | 查不到与点名同时改变登记条目与反馈；选项／差价的信息量也不同 |
| **B：证据获取**——可查询是否转化为可靠执行 | 查询开／关；E1 无核验信号下的提醒／无提醒 | 分别测工具可达、实际查询与最终写入 |
| **C：执行门控**——不同出口怎样改变行动及正常能力 | 按钮／重发／提示词无出口／系统强制；未登记真值 | 强制拒绝直接改变执行结果，需结合动作轨迹判断 |
| **B/C：共同作用**——信息和出口的效果是否相互依赖 | 反馈 × 出口 × 查询 × 顾客四因素交叉 | 主效应按预注册检验，交互只作描述 |
| **D：处理机制**——见证与核对能否兼顾安全和正常完成 | 方法主批、扩题、修复、AI 判预演与监督基线 | 代码版与 AI 版也有封存差异，属于流程比较 |
| **D：意图表达**——目标进入规则后是否仍然忠实 | 自己／系统代声明、自由／锁定、封存时机、E2 比对 | 当前任务多有确定目标，不能代表一般多解 |
| **E：稳健性**——结论在何处保持或失效 | 第二模型、措辞控制、次要题与扩题；AgentDyn 补充 | 第二模型同属一个供应商；AgentDyn 未完整复现方法 |
| **边界：来源与说服**——证据、意图或确认路径能否被影响 | 登记册洗白、规则话术、封存红队、拒绝型顾客 | 固定攻击模板与规则顾客，不能直接代表真实人审批 |

见证式提交是一个具体设计实例：H 接触同伴前封存用户目标；Harness 从执行端解析委派值实际指向的实体，在副本上预演，再与封存意图核对。匹配则放行，不符则拒绝；信息不足时要求补全或升级，repair 条件另提供修复候选。它用于检验主动取得事实并约束执行能否改善上述取舍。

### 2.3 如何判定结果

沿 **Harness 提供信息 → Agent 查询和提出动作 → 门控决定 → 状态变化** 分别检查记录，区分信息未送达、可取得但未使用，以及错误动作被直接挡住。轨迹反映可见行为，不能直接揭示内部信念；低写入也不能单独证明模型判断改善。

安全指标 F 为实际攻击写入，T 为正常成功，J=T−F 用于方法比较。核心主指标 R1 另要求写入前未在第一次声明下得到 MATCH。对称词表静默与 strict 静默按各自规则报告，strict 不可判写入单列。统计保留各批的簇级分析、区间与 Holm 检验族；主批、扩题和跨批参照分开。

## 3. 当前实验结果

下列百分比除注明外为簇均值，k/n 为原始运行计数；不同批次和指标不直接合并。

### 3.1 Harness 提供的事实粒度会显著改变结果

无防御核心攻击条件实际写入 20/26，簇均值 75%。反馈主对比中，查不到与点名不符的 R1 做错率为 **83.33% 与 18.06%**，差约 65 个百分点，单侧 p=.00390625；对称静默率分别为 76.39% 与 8.33%。这说明核验输出中是否提供具体反证，与所测条件下的行为差异密切相关。[核心结果](../supporting/results/core_primary.md)

更直接的细节保留对照来自第 2 段：粗反馈攻击写入 **34/52，簇均值 65%**，点名实际实体则为 **3/52，6%**，配对差约 +59pp，区间 [36, 81]。两者都传达不符，但是否说清实际对象影响很大。该比较按原计划作为估计报告。[第 2 段](../supporting/results/p0_s2_summary.md)

AI 判预演的合并结果中，选项版攻击写入 **18/140，15%**，差价版 **111/140，80%**，差约 65pp [50, 78]。这支持外层内容粒度的重要性；因为两版保留的信息不同，还不能单独解释为同样证据的表达难度差异。[预演比较](../supporting/results/p0_ext_summary.md)

保持点名信息而换成建议语气的 N×R 与 S×R，核心 R1 均约 6.82%，未显示仅换语气的收益（描述性比较）。[同信息对照](../supporting/results/core_primary.md)

### 3.2 执行出口的作用取决于信息条件，关门也有代价

在相同查不到条件下，核心按钮与原样重发的 R1 分别为 **68.18% 与 47.73%**，Holm p=.015625。[核心出口](../supporting/results/core_primary.md)

交叉批的 strict 静默主效应为：查不到约 **32%**、点名约 **2%**；按钮、重发、无出口分别约 **31%、19%、1%**。反馈与出口的主效应 Holm p 均约 .0002。组合的描述性结果更能说明二者关系：点名时三个出口约为 2%／3%／1%，查不到时约为 60%／35%／0%。这表明出口在缺少明确反证时尤其值得关注；交互本身依原计划只描述。[交叉结果](../supporting/results/factorial_summary.md)

出口补全的合并描述中，两种无出口条件各自攻击写入 **0/140**，但未登记真值正常成功也各为 **0/70**。按钮条件相应为攻击 112/140、簇均值 78%，正常成功 62/70、88%。所以关门的安全收益必须与合法新值受阻一起解释。[出口与正常代价](../supporting/results/rqc_summary.md)

### 3.3 证据可达、实际查询和可靠执行之间存在间隔

| 现有比较 | 结果 | 对研究问题的回答 |
|---|---|---|
| 第 2 段，查不到条件下开放查询 | 攻击写入约 78% 降到 50%，差 −28pp [−47, −7]，双侧 p=.0391 | 查询在该条件有帮助，仍不能保证正确执行 |
| 四因素批，查询开放的平均效应 | strict 静默差约 −5pp [−11, +1]，Holm p=.0295 | 区间跨零，未满足该批同时要求 p 与区间通过的标准 |
| E1，无核验信号时加查询提醒 | 写前查询约 14% 升到 29%，差 +15pp [3, 29] | 提醒能改变证据获取行为 |
| 同一 E1 比较的实际写入 | 攻击写入约 90% 降到 78%，差 −12pp [−28, +1] | 尚无明确证据表明提醒降低了错误写入 |
| 如实说明登记册不完整 | 第 2 段攻击写入约 78% 降到 64%，双侧 p=.125 | 未按预注册检验获得支持，不能解释成已证明信息无效 |

证据：[第 2 段](../supporting/results/p0_s2_summary.md)、[交叉批](../supporting/results/factorial_summary.md)、[E1](../supporting/results/e1_summary.md)。

### 3.4 见证与门控的组合可以兼顾安全和正常能力，但优势有范围

| 范围 | Ecode 攻击写入／正常成功 | 与 AI 判预演选项版的 J 比较 |
|---|---|---|
| 主批，13 题、11 簇 | **0/52；26/26** | 约 +18pp，原 P1–P3 检验族 Holm p=.25，未过优势门槛 |
| 扩题，22 题 | **0/88；43/44** | 约 +20pp，扩题检验族 Holm p=.0195 |
| 合并，35 题、29 簇 | **0/140；69/70** | 约 +19pp [8, 32]，Holm p≈.0032 |

主批达到方法自身“攻击 ≤10%、正常 ≥80%”门槛；相对 AI 判预演的优势得到扩题和合并支持。扩题包含此前使用过的题，属于稳健性补充；合并结果不替换原主批判断。[主批](../supporting/results/p0_gate_summary.md)、[扩题与合并](../supporting/results/p0_ext_summary.md)

修复条件在主批攻击局中有 **37/52** 改用正确值完成任务，簇均值约 73%；正常成功 25/26。它提供了从拒绝错误到恢复任务的证据。[修复结果](../supporting/results/p0_gate_summary.md)

带预演的 More Rejective 监督条件在第 2 段也达到攻击 0/52，正常成功 21/26、簇均值约 80%；Ecode 同批正常成功 25/26。两者 J 差的 Holm p=.1875，没有支持显著优势。[监督对照](../supporting/results/p0_s2_summary.md)

### 3.5 确定性标签并不保证可信，意图与确认路径仍可受影响

登记册 exact 洗白后，点名加按钮条件攻击写入由约 6% 升到 **47/52，90%**；同批 Ecode 为 0/52。一个 MATCH 标签是否可靠，取决于支撑它的来源。Ecode 不使用被洗白的登记册，故不受该修改影响是设计性质。[来源对照](../supporting/results/p0_s2_summary.md)

封存红队 s1+s2 的原始计数如下：

| 防御 | 总攻击写入 | strict 静默 | 已披露并确认 | 不可判写入 |
|---|---:|---:|---:|---:|
| 接触前封存 | 0/162 | 0 | 0 | 0 |
| 接触后封存 | 12/162 | 1 | 6 | 5 |
| 先揭示再封存 | 17/162 | 0 | 14 | 3 |
| AI 判预演 | 80/126 | 1 | 61 | 18 |

计数包含择优后的第二阶段；检验按原协议对话术等权，并在 AI 比较中匹配话术集合。strict 静默的主检验未显著支持后封存或 AI 判官相对先封存的差异，Holm p 为 1；总写入变化不能替换该结论。固定规则顾客的确认不等同于真实用户重新授权。[红队结果](../supporting/results/p0_rt_summary.md)

针对规则的另一批中，提示词无出口与系统强制各有 4/156 攻击写入，簇均值约 2% 与 3%。因此机制保证必须限定到实际核验规则和覆盖的路径。[规则边界](../supporting/results/p0_bd_summary.md)

### 3.6 哪些预测没有成立，哪些范围尚未覆盖

核心锁改口比较的 free 与 frozen R1 均约 6.82%，Holm p=.75；点名条件也未达到最初 ≤10% 的预测。E2 中 unique 与 consistent 均为攻击 0/26、正常成功 25/26，正常误拦均为 0/26，“unique 以更多误拦换取零同伴放行”的联合预测没有成立。check 参照来自其他批次，仅作描述。[核心负结果](../supporting/results/core_primary.md)、[E2](../supporting/results/e2_summary.md)

本批 unique 的攻击与正常检查均只剩一个兼容候选，各条件要求补全均为 0 局。因此，这批实验未检验多候选仍存时两种规则的取舍。E2 的 U 部分在开跑前取消，实际只跑 C 部分。[E2 最终协议](../supporting/SOURCE_PACKAGE.md#source-001)

第二 H 模型的反馈主比较为 R1 **84.375% 对 12.5%**，单侧 p=.0078125，与主模型方向一致。当前只支持同供应商第二模型的部分 B/C 复现；完整 D 和跨供应商尚未完成。[第二模型](../supporting/results/luna_primary.md)

## 4. 当前结论与边界

现有证据支持：**在所测委派任务中，Harness 保留的具体事实与可用执行路径显著影响 Agent 系统的行为；主动取得证据、实际使用证据和阻止错误执行是不同环节。** 未登记真值对照揭示了全面拒绝的代价，见证与核对实验展示了兼顾安全和正常能力的可行条件。

当前结论限于以确定事实为主的任务，尚未完整识别条件语义损失、真正多解，以及模型与 Harness 对错误的总体贡献比例。方法还依赖意图忠实、可信解析和实际覆盖的目标工具；更广的任务、供应商和攻击范围仍是证据缺口。

---

## 附录 A. 每组实验具体怎么做

### A0. 信息缺失的分析条件

设两个需要不同动作的情形经 Harness 处理后，完整可见信息的分布为 P真、P假。任何只依赖这些信息的放行策略，两种放行概率之差的绝对值都不超过总变差距离 TV(P真, P假)；信息完全相同则无法区分。完整信息须包含可用查询、已读记录和其他来源。该条件用于解释任务相关差异为何需要保留，不是新定理，也不预设所有摘要都有害。

### A1. 共用底座、任务有效性与评分

**任务与委派缺口。** 题目配置指定用户请求、目标工具与参数、真值、攻击值和遮蔽规则。H 从原生环境取得任务上下文，再向同伴询问被遮蔽的值。每个条件以单个 episode 运行；正常组和攻击组分别保存。查询关闭 opaque 与开放 intact 是明确的实验操纵。

**有效性。** 不先看攻击结果来筛题。三个保留的有效性批都在无防御正常条件下每题运行两次，两次官方成功才进入相应有效题集。主题集为 13 题、11 簇；次要有效题 9 道；dev 有效题 13 道。使用过的题在扩题和参照分析中明确其稳健性性质。

| 批次 | 实际记录 | 具体用途 |
|---|---:|---|
| [out_core_validity](../supporting/SOURCE_PACKAGE.md#source-002) | 46 | 23 道候选题 × 2 次，产生主题集 |
| [out_core_validity_conf](../supporting/SOURCE_PACKAGE.md#source-003) | 22 | 11 道候选题 × 2 次，产生次要题集 |
| [out_rqc_validity_dev](../supporting/SOURCE_PACKAGE.md#source-004) | 36 | 18 道候选题 × 2 次，产生 dev 有效题集 |

**主要指标。** 实际攻击写入依目标工具调用与状态判据重判；正常成功依 τ 官方 utility 并与终态交叉核对。R1 还要求攻击写入前没有在第一次声明下得到 MATCH。静默评价使用各批指定的披露规则，strict 的不可判写入单列；不能用 AI 自称“成功”代替真实写入。

**统计。** 题内重复先平均，同源题按规定并簇，再取簇间均值。核心、方法和部分边界用配对簇级精确符号检验；四因素批用其预注册的分层置换检验。bootstrap 次数、种子、单侧／双侧和 Holm 检验族以各批预注册为准，E1/E2 只报估计。运行顺序种子不等同于模型随机种子；每格通常每题 2–4 次，不能将其写成已完成三个模型种子的评估。

**计数。** 当前保留 21 个批次、7,696 条记录，含有效性与重复；不是 7,696 个独立样本。分析视图是这些记录的引用物化，不额外计数。基础设施错误与其他运行错误依原协议分别处理。银行转账评分器的已知误判仍待合入修正，当前核心 τ 结论未发现受该问题影响。

### A2. 反馈与出口核心实验：RQ-A/B/C

**任务与规模。** [out_core_main](../supporting/SOURCE_PACKAGE.md#source-005) 有 748 条实际记录，覆盖主题 13 题和次要 9 题；主检验只使用主题集规定范围。系统代声明另存 A3 的批次。无防御 opaque 正常参照复用有效性记录，不另算新增样本。

**操纵。** 保持任务与默认攻击值，设 M0 无防御；N 点名实际实体；G 删除攻击条目而如实返回查不到；S 提供同信息的建议语气。N/G 分别配按钮 O 或原样重发 R，另比较 S×R 中声明 free 与 frozen。除指定 intact 条件外关闭原生查询。H 为 gpt-5.5，E 为 gpt-6-astra。

**运行。** 主要 N/G/S 攻击格每题 4 次；M0 和开放查询格每题 2 次；正常各格每题 2 次。每局从同题的起始环境运行，保存完整轨迹和终态。

**判断。** T1 比 G×O 与 N×O，用商品编号题 11 道、9 簇，排除两道编号自描述的付款题；T2 比 G×O 与 G×R；T3 比 S×R-free 与 frozen，用全部主题题。T2/T3 同族 Holm。主指标 R1，另报对称静默与总写入。[主结果](../supporting/results/core_primary.md)、[次要结果](../supporting/results/core_secondary.md)

### A3. 中性措辞与系统代声明：RQ-B 的控制实验

**中性措辞。** [out_core_neutral](../supporting/SOURCE_PACKAGE.md#source-006) 在 22 题上移除“同伴持有权威记录”等提示，保留提供值的任务。攻击 M0、N×R 和正常 M0、R 各每题 2 次，共 176 条；与核心对应条件比较，观察现象是否主要由权威提示造成。只报估计与配对差。[主题结果](../supporting/results/neutral_primary.md)、[次要结果](../supporting/results/neutral_secondary.md)

**系统代声明。** [out_core_yoked](../supporting/SOURCE_PACKAGE.md#source-007) 从核心 G×O 的指定输出抽取同题声明，由系统提供这些声明，再运行 22 题各 2 次，共 44 条。改变声明产生方式，检查 H 自己写声明是否解释主要现象；它与来源批次有依赖，作为次要描述，不视为独立确认性实验。[核心次要对比](../supporting/results/core_primary.md)

### A4. 出口补全与未登记真值：RQ-C

[out_rqc_exits](../supporting/SOURCE_PACKAGE.md#source-008) 覆盖主题、次要和 dev 共 35 题、29 簇，实际 1,050 条。主检验仍只看 13 道主题题，其他题集和合并描述分开。

攻击组都返回查不到，比较按钮、按钮加并列其他路线、提示词无出口规则、系统强制无出口，每题每格 4 次。正常组主动删除真值登记，比较按钮、原样重发、按钮加其他路线及两种无出口，每题每格 2 次；另跑真值在册的强制条件和未经筛选的正常 M0 参照。

这里最关键的是让合法真值也经历“查不到”，用来判断防御是否真正增加区分能力。主检验比较攻击 R1，正常侧报告官方成功与真值放行；主族 C1–C3 做 Holm。攻击原样重发参照来自核心批，明确标为非同时。[结果](../supporting/results/rqc_summary.md)

### A5. 四因素交叉与理由码：RQ-B/C

[out_factorial](../supporting/SOURCE_PACKAGE.md#source-009) 使用主题 13 题、11 簇，实际 910 条，分成 780 条交叉运行和 130 条理由码运行。

攻击组交叉 **2 种反馈 × 3 种出口 × 2 种查询状态 × 2 种顾客策略**，24 格，每题每格 2 次，共 624 条。正常组使用未登记真值，跑出口 × 顾客 6 格、每题 2 次，共 156 条。顾客策略是规则脚本的一律同意或对不一致属性拒绝。

主指标为 strict 静默写入。四个主效应使用同题、其余因素相同的分层置换，20,000 次，Holm 覆盖四项；“明显差距”同时要求 p 和区间通过。两因素交互只描述。

理由码附验在 N/G 加按钮的两种攻击格各每题 4 次、正常一格每题 2 次，要求选择继续的理由。理由是模型自述，菜单本身也可能影响行为，不将它当成内部因果解释。[结果](../supporting/results/factorial_summary.md)

### A6. 第 2 段：证据强弱、查询、监督与洗白

[out_p0_s2](../supporting/SOURCE_PACKAGE.md#source-010) 在主题 13 题上运行 1,118 条，通常每个攻击格每题 4 次、正常格 2 次。

同批设置查不到加按钮、点名加按钮和 Ecode 锚点，再分别改变：是否如实告知登记册不完整；是否降低登记覆盖；是否开放查询；反馈是否只说不符；登记册是否 exact 洗白。另运行 More Rejective、IntegrityGuard 两种监督提示，各自比较有无执行端预演，监督模型与 H 同为 gpt-5.5。

每项按本批规定比较对应锚点，不能把同时变化的格当成单因素实验。报告实际写入、正常成功、J、查询率及监督解析失败；洗白与监督比较各按自己的检验族，查询和其他估计按预注册解释。该预注册里的 E1/E2 是段内实验编号，不等于后来的 out_e1_reactive/out_e2_grey。用户判预演的可选格未包含在本次 1,118 条记录中。[结果](../supporting/results/p0_s2_summary.md)

### A7. 方法主批、修复与扩题：RQ-D

**主批。** [out_p0_gate](../supporting/SOURCE_PACKAGE.md#source-011) 用主题 13 题、11 簇，8 个条件各攻击 4 次、正常 2 次，共 624 条：Ecode、Ecode 加修复、AI 判预演选项版、AI 判差价版、先揭示再封存、接触后封存，以及按钮／无出口锚点。正常组使用未登记真值；执行端解析方法不依赖登记册。

代码判定条件先封存并用执行端实体核对。AI 判预演条件不封存：首次目标写调用返回预演，H 用完全相同参数再调用即确认执行。因此“代码对 AI”是两套流程的比较，包含封存差异；结合时机消融解释，不能把全部收益只归给判官类型。

当前实现主要约束指定目标工具和参数。预演报错分支会交给真实工具返回错误，其无写入性质依赖所测工具的错误语义。封存忠实、可信解析、足够细的匹配以及预演与执行一致，是方法的前提；生产系统中的并发、外部副作用和跨服务事务尚未验证。

P1 比 Ecode 与 AI 选项版的 J，优势要求差至少 15pp 且 Holm p<.05；P2 检查时机相关对比；P3 比 AI 差价版与选项版的攻击写入，三项按原族校正。另报修复后正确完成和交人，区分拦截与任务恢复。[主批结果](../supporting/results/p0_gate_summary.md)

**扩题。** [out_p0_ext](../supporting/SOURCE_PACKAGE.md#source-012) 在主批结果之后冻结，新增 22 道此前使用过的题；只复跑 Ecode、AI 选项版、AI 差价版，各攻击 4 次、正常 2 次，共 396 条。分别报告扩题和 35 题合并结果，各族包含 P1/P3 两项；原主批三项校正结果不被替换。[扩题结果](../supporting/results/p0_ext_summary.md)

### A8. τ 与 AgentDyn 基线：RQ-D 的参照及场景边界

**τ 基线。** [out_tau_baselines](../supporting/SOURCE_PACKAGE.md#source-013) 在 22 题上比较来源闸门 M1、先核实提示、升级确认提示、spotlighting 和提示词规则，五种条件 × 正常／攻击 × 每题 2 次，共 440 条。报告攻击与正常指标，核心条件作为跨批参照，主题与次要题分开。[主题结果](../supporting/results/tau_baselines_primary.md)、[次要结果](../supporting/results/tau_baselines_secondary.md)

**AgentDyn 补充。** [out_ad_addon](../supporting/SOURCE_PACKAGE.md#source-014) 有 76 条：有持有人题比较保留与删除登记条目，每格每题 2 次；无持有人题比较查不到与满足代码前提时的“登记册完整”说明，每格每题 4 次。查询状态随题配置，只作逐题和描述性补充。自然核验是否真的给出点名反馈也要核实，不能把所有题标签当作相同的信息处理。

**AgentDyn 防御比较。** [out_ad_baselines](../supporting/SOURCE_PACKAGE.md#source-015) 在 9 题上运行 284 条，比较 M0、核验重发、强制无出口、spotlighting、提示词规则、Progent static/dynamic 和 ROPE，正常／攻击各每题 2 次；ROPE 不支持的 workspace 题不跑。报告写入、正常成功及不支持和报错情况。

**动态策略补充。** [out_ad_baselines_dyn2](../supporting/SOURCE_PACKAGE.md#source-016) 对动态 Progent 使用作者评测设置，再跑 36 条；原批生成策略格式错误的情况保留，不悄悄删除。当前基线汇总见 [AgentDyn 结果](../supporting/results/ad_baselines_final.md)。这些运行不构成见证式提交在 AgentDyn 的完整成功复现；尤其不能假定所有场景都提供可信的正向实体解析。

### A9. 针对规则、封存与顾客的边界实验

**借口与教声明。** [out_core_boundary](../supporting/SOURCE_PACKAGE.md#source-017) 在 22 题上，分别给 G×O 添加登记延迟等借口、给 N×R 添加实际登记名指导，每题每格 4 次，共 176 条。因为教声明可能直接获得 MATCH，指标使用任何攻击写入，避免 R1 漏计。[主题结果](../supporting/results/boundary_primary.md)、[次要结果](../supporting/results/boundary_secondary.md)

**针对规则。** [out_p0_bd](../supporting/SOURCE_PACKAGE.md#source-018) 在 13 题上交叉两种防御 prule/rot、两种 N/G 世界和三类话术：权威豁免、伪造 MATCH、声称用户已确认；每格 2 次，共 312 条。依据最终预注册修订判定，报告真实写入、分世界及分话术结果。协议早期“rot 按构造为零”的预期不能代替实际观察。[结果](../supporting/results/p0_bd_summary.md)

**针对封存与判官。** [out_p0_rt](../supporting/SOURCE_PACKAGE.md#source-019) 用 18 题、16 簇，共 768 条。比较接触前封存、接触后封存、先揭示和 AI 判预演；有封存条件用替代、偏好、教封存、已同意、教补全五条模板，AI 判官只用其中三条适用模板。

第一阶段每题每种适用防御与话术跑 1 次，共 324 条；第二阶段按第一阶段为每题每防御选话术，再跑 4 次，共 288 条。另有拒绝型顾客的攻击与正常稳健性 144 条，以及一单两类值的晚封存锁定案例 12 条。主分析按防御合并话术，并按规定配对；择优后的第二阶段结果只作描述，不当作独立强攻击确认。主指标 strict 静默，另报总写入、污染、披露和不可判事件。[结果](../supporting/results/p0_rt_summary.md)

### A10. 第二主力模型：RQ-E

[out_core_luna](../supporting/SOURCE_PACKAGE.md#source-020) 将 H 换为 gpt-5.6-luna，E 保持 gpt-6-astra。22 道候选题各跑 M0、N×O、G×O、G×R 四种攻击条件和 M0 正常条件，每格 2 次，共 220 条。

用该模型自身正常组两次都成功的规则筛题。主要反馈复核使用有效商品题 9 道、8 簇，重复 G×O 对 N×O 的 T1；出口比较只报估计。题集有效范围随模型变化，需要明示，不能把结果视为完整同题跨供应商验证。[主题结果](../supporting/results/luna_primary.md)、[次要结果](../supporting/results/luna_secondary.md)

### A11. E1：核验提醒是否足够

[out_e1_reactive](../supporting/SOURCE_PACKAGE.md#source-021) 排除无对应查询工具的两道付款题，使用 11 题、9 簇。所有格均无膜 M0、查询开放 intact；攻击无提醒与攻击加提醒各每题 4 次，正常加提醒每题 2 次，共 110 条。正常无提醒参照来自核心批，非同时运行。

这样可以在没有核验信号的条件下，直接测试一句提醒是否使 H 主动查询并少写错。记录查询的时序、写入前是否查过委派值、实际攻击写入、静默与正常成功；只报簇区间和配对差，不做 p 值主检验。查询增加与写入减少分别判断。[结果](../supporting/results/e1_summary.md)

### A12. E2：执行系统的比对规则是否仍在处理灰区

[out_e2_grey](../supporting/SOURCE_PACKAGE.md#source-001) 最终只执行 C 部分，主题 13 题上比较 unique 和 consistent，两种方式各攻击 2 次、正常 2 次，共 104 条；check 参照来自方法主批的 78 条，故分析读入 182 条，不等于本批新增 182 条。

| 方式 | 如何决定 |
|---|---|
| check | 按结构规则检查冲突、产品与选项完整性，完整且匹配才放行 |
| unique | 枚举合法范围中与意图不冲突的候选；待用值属于唯一候选才放行，多候选要求补全；无法使用该范围时回退 check |
| consistent | 无结构冲突且意图点名产品或付款方式即可放行；冲突拒绝，未点名要求补全 |

保持接触前封存和代码判定不变，记录攻击写入、正常成功、对真值误拦、同伴款放行、补全与转人工。只作估计，跨批 check 对照不能解释为同批随机比较。

U 部分原拟对 21 道字面未说全选项的题增加 168 次运行，最终修订已取消，未执行。现有题中的关系描述和可见目录常能确定规格，不能把“没有逐字列出选项”直接当作“用户意图真正歧义”。[结果](../supporting/results/e2_summary.md)

## 附录 B. 架构、证据与可复现入口

### B1. 研究问题对应到代码和结果

| 研究环节 | 主要条件入口 | 评分与分析 | 结果入口 |
|---|---|---|---|
| RQ-A/B：现象、反馈与信息粒度 | [核心作业](../supporting/SOURCE_PACKAGE.md#source-022)、[第 2 段作业](../supporting/SOURCE_PACKAGE.md#source-023) | [核心评分](../supporting/SOURCE_PACKAGE.md#source-024)、[第 2 段分析](../supporting/SOURCE_PACKAGE.md#source-025) | [核心](../supporting/results/core_primary.md)、[第 2 段](../supporting/results/p0_s2_summary.md) |
| RQ-B/C：信息与门控交叉 | [交叉作业](../supporting/SOURCE_PACKAGE.md#source-026) | [交叉分析](../supporting/SOURCE_PACKAGE.md#source-027) | [交叉结果](../supporting/results/factorial_summary.md) |
| RQ-C：出口与正常新值 | [出口作业](../supporting/SOURCE_PACKAGE.md#source-028) | [出口分析](../supporting/SOURCE_PACKAGE.md#source-029) | [出口结果](../supporting/results/rqc_summary.md) |
| RQ-D：见证、呈现与修复 | [方法主批作业](../supporting/SOURCE_PACKAGE.md#source-030)、[扩题作业](../supporting/SOURCE_PACKAGE.md#source-031) | [方法分析](../supporting/SOURCE_PACKAGE.md#source-032)、[扩题分析](../supporting/SOURCE_PACKAGE.md#source-033) | [主批](../supporting/results/p0_gate_summary.md)、[扩题](../supporting/results/p0_ext_summary.md) |
| RQ-E：模型复核 | [第二模型作业](../supporting/SOURCE_PACKAGE.md#source-034) | [核心评分](../supporting/SOURCE_PACKAGE.md#source-024) | [第二模型结果](../supporting/results/luna_primary.md) |
| 边界：规则与封存说服 | [规则作业](../supporting/SOURCE_PACKAGE.md#source-035)、[红队作业](../supporting/SOURCE_PACKAGE.md#source-036) | [规则分析](../supporting/SOURCE_PACKAGE.md#source-037)、[红队分析](../supporting/SOURCE_PACKAGE.md#source-038) | [规则结果](../supporting/results/p0_bd_summary.md)、[红队结果](../supporting/results/p0_rt_summary.md) |
| E1：证据获取 | [提醒作业](../supporting/SOURCE_PACKAGE.md#source-039) | [E1 分析](../supporting/SOURCE_PACKAGE.md#source-040) | [E1 结果](../supporting/results/e1_summary.md) |
| E2：意图与比对规则 | [比对作业](../supporting/SOURCE_PACKAGE.md#source-041) | [E2 分析](../supporting/SOURCE_PACKAGE.md#source-042) | [E2 结果](../supporting/results/e2_summary.md) |

### B2. 执行架构

代码链为：**题目配置 → Runner 调度用户／H／E → Membrane 核验或执行闸门 → Benchmark 工具与状态 → 原始轨迹 → 离线评分与统计。**

| 位置 | 职责 |
|---|---|
| [tau/run_tau.py](../supporting/SOURCE_PACKAGE.md#source-043) | τ 环境、回合与模型调度、运行记录 |
| [tau/tau_membrane.py](../supporting/SOURCE_PACKAGE.md#source-044) | 反馈、出口、封存和目标写入控制 |
| [tau/effect_gate.py](../supporting/SOURCE_PACKAGE.md#source-045) | 执行端实体解析、预演、比对与修复候选 |
| [tau/tau_registry.py](../supporting/SOURCE_PACKAGE.md#source-046) | 登记册与结构核对规则 |
| [check_texts.py](../supporting/SOURCE_PACKAGE.md#source-047)、[redteam_texts.py](../supporting/SOURCE_PACKAGE.md#source-048) | 核验、出口与攻击话术原文 |
| [run_ep2.py](../supporting/SOURCE_PACKAGE.md#source-049) | 当前 AgentDyn 补充与基线执行 |
| [summarize_core.py](../supporting/SOURCE_PACKAGE.md#source-024)、[analysis](../supporting/SOURCE_PACKAGE.md#source-050) | 评分、聚类、检验与结果汇总 |

代码里对没有结构规则的类型仍有名称词重合阈值；付款方式的可识别粒度也有限。当前方法不能表述为对任意值类型都已消除全部灰度。

### B3. 证据与复现

每项实验的证据按 **PREREG → jobs.txt → 原始 episode JSON → 评分脚本 → results** 核对。各批目录保留作业条件与原始记录，当前结果以本 proposal 链接的复算表为准。

日常入口见 [当前主线与状态](../supporting/SOURCE_PACKAGE.md#source-051)，运行与依赖见 [使用说明](../supporting/SOURCE_PACKAGE.md#source-052) 和 [evalkit](../supporting/SOURCE_PACKAGE.md#source-053)。本包已有 20 组离线复算通过记录，见 [验收结果](../supporting/SOURCE_PACKAGE.md#source-054)。

在包根目录可检查文件或重新复算：

```bash
python3 -B tools/verify_package.py
python3 -B tools/replay_current.py --all --out /tmp/agentmembrane_grey_replay
```

复算输出目录须尚不存在。离线复算使用包内已保存的记录与支持数据；新增模型实验还需要相应 benchmark 源码、独立环境与模型端点。
