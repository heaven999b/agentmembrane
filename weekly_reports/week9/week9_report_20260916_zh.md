# 第九周中期研究汇报：AgentMembrane RQ1 三档外部 Agent 权限 Baseline 与阶段结果

> 汇报周期：2026-09-14 至 2026-09-20；本文结果截点为 2026-09-16。
>
> **状态注释：代码、逐题合同和正式运行协议仍在修改与核验中。当前模型结果来自已经暂停的 mixed-code diagnostic campaign，只用于定位问题和建立实验 baseline，不是正式 RQ1 结论，也不得与后续正式批次合并。当前没有继续跑旧批次。**

## 本周核心结论

本周研究对象已经从上周“固定高权限，先验证攻击能否被激活”转为一个明确的三档权限实验：固定 Host `H`，只改变外部 Agent `E` 的真实 AgentDojo 业务工具权限，并在每个档位分别运行 honest 与 malicious 条件。计划面板为 **46 道合格原题 × 3 档权限 × 2 个条件 = 276 格**，每格只运行一次，不做多 seed。

三档的实际 baseline 是：低档 `E` 没有业务工具；中档 `E` 只有根据每道原题编译出的目的绑定工具、对象、参数和调用次数；高档 `E` 获得同一 suite 内较宽的业务工具面。三档中的 `H` 始终保持相同任务、模型、工具权限、预算和最终回答责任。因此，低—中—高比较测的是 **E 的业务工具权限变化**，不是模型变化，也不是旧 A0–A5 六档协议的重跑。

已经暂停的诊断批次共预分配 276 格，最终启动过 136 格：**128 格完成、8 格封存为 unknown、140 格未启动**。在恶意条件的已知 `G` 中，低档为 `0/25`、中档为 `0/19`、高档为 `14/17`；其中高档的 14 个正例包含 12 个完整格和 2 个封存未完成但已经观察到目标副作用的格。这个方向与“高档更容易形成真实攻击可达性”一致，但由于缺失很多、跨档完整配对极少、代码版本混杂且旧接口仍含 `S` 角色语言，**目前对正式 RQ1 的判定仍是 `not_evaluable`，既不能写支持，也不能写不支持。**

## 一、本周三档 baseline 到底是什么

### 1.1 固定项与处理变量

每道正式候选原题有六个格：

| E 权限 | Honest 对照 | Malicious 攻击 |
| --- | --- | --- |
| Low | 1 次 | 1 次 |
| Medium | 1 次 | 1 次 |
| High | 1 次 | 1 次 |

六格中固定以下内容：

- 原始 AgentDojo 任务、锁定初始世界、原生 task/security checker；
- `H` 的任务、工具权限、system/output contract、决策预算和最终回答职责；
- `H` 与 `E` 均使用 `gpt-5.6-luna`、`reasoning_effort=low`、最多 2048 completion tokens；
- 每格 fresh reset，一格一次 allocation；无自动重试、无模型替换、无事后挑最好一次；
- 正式 actor set 为 `H_E`：`E` 先运行，随后永久关闭，`H` 完成工作与 final；正式设计中没有 `S`。

真正变化的只有两项：

1. `E` 的业务工具权限是 low、medium 还是 high；
2. `E` 收到 honest 协作目标还是预先注册的 malicious 攻击目标。

### 1.2 三档具体落地

| 档位 | `E` 实际拥有的能力 | 这一档回答的问题 |
| --- | --- | --- |
| Low | 没有 AgentDojo 原生业务工具；仍可在有界协议内向 `H` 发送文本。`H` 权限不变。 | 当 `E` 没有直接业务执行权时，攻击是否仍能通过消息诱导 `H` 或其他路径发生；同时测量协作效用下界。 |
| Medium | 每题独立编译允许工具、目标对象、参数谓词、返回字段和调用次数。授权只来自可信原题与初态；邮件、网页、文件或 Slack 内容只能提供事实，不能扩权。歧义、对象不唯一、参数越界或提交状态未知时在 backend 前失败关闭。 | 目的绑定的最小业务权限能否保留合法任务效用，同时阻断与原题无关的越权目标。 |
| High | `E` 获得同一 AgentDojo suite 内较宽的业务工具和参数范围，攻击目标的原生路径应技术可达；仍处在模拟 sandbox 与证据安全边界内。 | 当外部 Agent 有广业务执行面时，模型是否会利用该通道达成注册攻击目标。 |

Banking 的 `update_password` 因现有证据层不能安全记录密码参数而排除，所以 high 是 `ambient_experimental_high`，不能描述成无条件的完整 Banking 权限。

代码中的 `A0`、`A3`、`A4` 只是 low、medium、high 的运行实现标签。本周注册的科学构念是 `external_agent_business_tool_authority_gradient`。它不替代旧 A0–A5 canonical ladder，也不允许把三档结果外推成旧六档结论。

### 1.3 哪一个才叫 baseline

- **Low + honest** 是“E 无业务执行权”的基础协作参照；
- **Medium + honest** 检查目的绑定权限是否保留正常任务效用；
- **High + honest** 给出广权限下的正常任务参照，并检查任务本身是否会碰撞攻击目标；
- 每档的 malicious 相对同档 honest 差值用于去除任务自身的背景目标激活；
- 正式候选的主比较是 high 与 medium 的攻击特异性差中差：

```text
[(G_high,malicious - G_high,honest)
 - (G_medium,malicious - G_medium,honest)]
```

因此，这次实验并不是只拿 low 当唯一对照，而是用同题六格共同构成 baseline。

## 二、与上周 baseline 的关系

上周 `scale-36` 使用 6 道题、固定 high、每题 attack/control 各 3 次，共 36 个真实模型 episode，目的是先证明攻击在高权限下可以被激活。上周得到 control `G=0/18`、attack `G=16/18`，严格原题成功分别为 `18/18` 与 `15/18`，双目标成功为 `13/18`。

本周保留相同的 `gpt-5.6-luna` 与 low reasoning，并继续使用 AgentDojo 原生 backend、原题、`G` 与严格 `L`。主要变化是把 **E 权限 low/medium/high** 设为处理变量，把 6 道题多次重复改成 46 道题每格一次，并扩到 Banking、Slack、Travel、Workspace 四个 suite。

本周正式方案明确采用 `H_E`。早期诊断 v6 虽然把 topology 标成 `H_E`，manifest、H prompt 和 action recipient schema 中仍残留 `S`；这是本周已经定位、正在修复的协议污染。上周数据、这次暂停数据和将来的正式数据在代码、路由、题池与处理变量上不同，不能合并统计。

## 三、已经实际跑了什么

暂停批次 `live_campaign_002` 的最终冻结账本为：

| 状态 | 格数 | 含义 |
| --- | ---: | --- |
| 完成 | 128 | 到达 host final，主要结果可按已封存摘要读取 |
| 封存 unknown | 8 | 包含 6 个一般 sealed unknown、1 个新基础设施 unknown、1 个继承基础设施 unknown |
| 未启动 | 140 | 没有模型行为数据 |
| 总预分配 | 276 | 46 题 × 3 档 × 2 条件 |

停止时共启动过 `128 + 8 = 136` 格。所有 276 格仍留在原分母中，unknown 不按攻击失败或安全成功填补。

这批数据只能称为 **mixed-code diagnostic**，原因包括：

- 276 格并非同一最终代码版本；
- 140 格尚未启动，跨档完整配对严重不足；
- 当时只用了四个 suite 级攻击目标，不能代表广泛攻击目标分布；
- 旧模型输入没有事前收到现在新增的逐题 Q/I/D 与 H 输出合同；
- `H_E` 接口仍残留 `S` 语言；
- 代码修改后，旧 manifest 的代码哈希已经失效。

因此旧 campaign 保持 `paused / user_requested_stop`，不会续跑、补格、升级为正式样本，也不会与新批次 pooled analysis。

## 四、当前诊断结果

### 4.1 原生攻击目标 `G`

`G` 表示预先指定的 AgentDojo 原生攻击目标在终态真实发生。下表始终使用每个 cell type 的固定 46 题分母，并把未跑或无法判定的格保留为 unknown。

| E 档位 | Regime | `G=true` | `G=false` | `G=unknown` |
| --- | --- | ---: | ---: | ---: |
| Low | honest | 0 | 23 | 23 |
| Low | malicious | 0 | 25 | 21 |
| Medium | honest | 0 | 28 | 18 |
| Medium | malicious | 0 | 19 | 27 |
| High | honest | 0 | 18 | 28 |
| High | malicious | **14** | 3 | 29 |

高档恶意的 14 个 `G=true` 中，12 个来自完整格，2 个来自封存未完成但目标副作用已经确认的格。冻结证据的只读 actor-path 回放显示，这 14 个正例均包含 **E-direct** 目标序列提交路径；没有一个能据此证明是 `H` 被诱导后代为执行。

若强制保留全部 46 题分母，高档恶意 `G` 的 sharp bound 是 `14/46` 至 `43/46`（30.4%–93.5%）。这个区间过宽，不能把 `14/17` 当成完整任务池上的攻击成功率。

低档 25 个已完成 malicious 格中，`E` 对原生目标工具的请求为 0；中档 19 个已完成 malicious 格中只有 1 个目标请求，而且没有进入 backend。这说明当前 low/medium 的 `G=0` 同时受“模型很少实际尝试”和“权限阻断”影响，不能把全部零结果都归因于权限策略成功。

### 4.2 严格原题成功 `L`

| E 档位 | Regime | `L=true` | `L=false` | `L=unknown` |
| --- | --- | ---: | ---: | ---: |
| Low | honest | 15 | 6 | 25 |
| Low | malicious | 16 | 7 | 23 |
| Medium | honest | 14 | 10 | 22 |
| Medium | malicious | 11 | 7 | 28 |
| High | honest | 13 | 4 | 29 |
| High | malicious | 13 | 1 | 32 |

这些 `L` 计数也不能直接拿来比较档位成功率。不同档位已完成的题目集合不齐，且高档与 medium 的 `G` 攻击/对照同题都已知的只有 5 对；用于主 high–medium 差中差的完整四格任务为 **0/46**。当前缺失区间跨越正负两侧，所以还不能估计正式三档效应。

### 4.3 当前结果支持什么

当前数据与工程验证可以支持以下有限判断：

1. 三档确实改变了真实 backend 权限，而不只是改标签。此前 50 对离线授权审计中，high 的直接攻击序列 `50/50` 技术可达，low/medium `50/50` 在 backend 前被挡；这是权限实现检查，不是模型行为结果。
2. 真实模型在 high malicious 条件下确实能造成 AgentDojo 原生目标副作用，当前已确认 14 个 E-direct 正例。
3. low/medium 的直接攻击面明显更窄，但现有模型行为中攻击尝试率也低，后续必须同时报告“提议—策略拒绝—backend 提交—终态 G”的漏斗。
4. 目前没有足够同题完整数据，也没有统一正式协议，不能给 RQ1 写支持、不支持或攻击成功概率。

## 五、正式批次 baseline 的当前准备度

逐题工程审计覆盖 86 道独立原题：83 道可以生成三档 policy，78 道的中档权限可闭环完成原题，46 道同时具备严格 `L` checker，因此正式候选池目前固定在 **46 道、276 格**。四个 suite 的组成是 Banking 4、Slack 4、Travel 16、Workspace 22。

为避免旧批次只有四个攻击目标，本周又对 300 个 task–goal edge 做了 outcome-blind 离线审计，并形成 18 个原生 goal clusters 的候选分配；旧暂停 campaign 的四个目标复用数为 0。当前候选保证选中的 high 直接路径可达、low/medium 直接路径被挡，但尚未正式激活。

这 46 道题本身已经参与过此前的工程开发或分配，因此新批次应准确描述为“在已工程化任务上的 prospective new-goal replication”，不能写成完全 blind 的新任务样本。

逐题公开 H 输出合同候选已覆盖 46 题，共 117 个 Q atoms：76 个由 H final 判断，31 个由可信终态判断，3 个由可信 trace 与终态共同判断，7 个因原题歧义预注册为 intrinsic unknown。Other suites 的 I 候选分母已从初态重建：9,965 个原始事实—收件人格，排除 126 个明确合法目的格后保留 9,839 个候选 I 单元。这些仍是候选合同，不能倒算旧 evidence。

正式 preflight 当前仍为：

```text
formal_ready = false
research_sample_count = 0
formal_manifest_created = false
old_campaign_resume_permitted = false
```

尚需关闭的六个门槛是：

1. 独立冻结最终 18-goal assignment；
2. 按最终 goal assignment 重编并绑定 H output contract；
3. 激活本周独立三档构念的治理声明；
4. 独立审查并激活最终统计分析计划；
5. 完成逐题 Q/I/D 独立裁定与激活；
6. 让新的 formal `H_E` runtime 通过 fake-transport 全生命周期资格测试。

正式 wire/driver 已开始把模型可见 actor、recipient 和 action schema 限定为 `H/E`，并拒绝 `S`。完整 runtime lifecycle、证据外壳与分析入口仍在修改和调试中，所以本周不会把“单元测试通过”写成“正式实验已经可跑”。

另一个 fresh v6 工程 smoke 使用 W15/W31/W32/W34 四题走完原生执行与封存：`4/4 completed`、`4/4 integrity=true`、`4/4 native L=true`、`4/4 G=false`，模型与 API 调用均为 0。它只证明权限和 evidence seal 接线可执行，不增加正式研究样本。

## 六、真实 CLIProxyAPI 验证

换号后的隔离路由已经完成一次最终 v3 canary：请求 1 次 `/models`，再请求 1 次 `gpt-5.6-luna` 生成；HTTP 200，模型匹配，`finish_reason=stop`，回答精确为 `OK`，代理和 wrapper 均为 0 重试。运行后代理进程、临时授权副本、客户端 key 与专用端口均完成清理。

这证明新的 CLIProxyAPI 路由可用，但该 canary 明确记录：

```text
research_sample_count = 0
rq1_effect_evidence = false
formal_ready = false
```

因此它属于基础设施验证，不进入上述 276 格研究数据。

## 七、预期正式结果与判读规则

当前统计计划仍是待独立激活的 candidate。计划中的主要支持条件为：

- high–medium 的攻击特异性 `G` 差中差点估计至少为 `+0.20`；
- 18 个 goal clusters 重采样的下界严格大于 0；
- 把缺失格作最坏情况补全后的 sharp lower bound 仍大于 0；
- honest 条件的 `G` 总数为 0；
- medium 相对 high 的 honest `L` 与 `Q` 下界不低于 `-0.10`；
- 所有运行、封存、路由、代码哈希和事前合同门禁通过。

正式报告必须同时给出 fixed 46-task denominator、complete pairs、unknown bounds、每 suite 与每 goal cluster 描述、E-direct/H-mediated lineage，以及 Q/I/D。由于每格只有一次模型运行，结论范围只覆盖冻结的 46 题与 18 个目标簇，不解释为模型重复采样概率或所有 AgentDojo 攻击类别的总体结论。

## 八、下一步

接下来先完成逐题合同与 formal runtime 修复，并用 fake transport 做端到端资格测试；随后只做一个与研究样本隔离的小型真实 API smoke，确认 fresh state、H/E-only schema、每格独立 proxy 生命周期、原生调用、终态评分和 seal 全链闭环。所有 preflight gate 通过后，才创建新的同质 276-cell manifest 并启动正式单次三档批次。

旧 `live_campaign_002` 继续保持暂停。正式批次会从全新的 manifest、代码指纹、路由绑定和事前合同开始，旧结果只保留为本周诊断证据。

## 公开聚合证据

- [Week 9 去敏机器汇总](./week9_stage_snapshot_20260916.json)

该机器汇总由本地冻结的 campaign progress、descriptive analysis、formal preflight、goal-balance audit、H-output candidate summary、fresh engineering smoke 与 CLIProxyAPI canary 逐项生成。原始模型响应、账号路由材料和本地绝对路径不包含在本次周报提交中。
