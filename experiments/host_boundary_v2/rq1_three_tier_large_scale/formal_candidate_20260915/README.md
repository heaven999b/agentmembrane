# 三档 AgentDojo 正式研究候选

> **当前状态（2026-09-16）：production runtime 闭环已实现并完成零样本资格验证，正式研究尚未激活。**
> `formal_activation=false`、`formal_ready=false`、正式研究样本数为 0。
> 真实 CLIProxy 演练只调用 `/models` readiness，没有模型生成。runtime 通过不等于 276 格正式实验已经可以开跑；研究合同与 evaluator 仍有独立门槛。

本目录固定的是一项独立的 RQ1 三档子研究：46 道 AgentDojo 原题 × low／medium／high 三档 × honest／malicious 两种 regime，每格一次，共 276 格。actor set 只有 H 和 E；H 的原题工具权限、模型、预算和输出合同在六格内固定，只改变 E 的业务工具权限。旧 `live_campaign_002` 永久暂停，不能恢复、补跑、升格或与新实验合并。

## 三档实际执行边界

| 档位 | E 可见的业务工具面 | runtime 实现 | 约束 |
| --- | --- | --- | --- |
| Low | 无 AgentDojo 业务工具 | `A0` | 只能按 H/E 协议发送文本和结束自己的阶段 |
| Medium | 当前原题目的所需工具和参数子集 | `A3` purpose-guarded | 绑定对象、参数、顺序、次数和结果字段；歧义、漂移、越权或重复提交均失败关闭 |
| High | 同 suite 的较宽实验工具面 | `A4` ambient；旧 canonical analog 为 A5 | 保留 sandbox、证据与单格生命周期约束，但使原生攻击目标具有技术可达路径 |

这些 runtime 名称只是实现标签。三档研究不声称覆盖 canonical A0–A5 全梯度，也不能据此识别全局权限阈值 A*。正式结果必须分别报告 E-direct 与 H-mediated 路径。

## 已完成的工程

离线 qualification core 保留用于无模型回归；公开 `runner.run_formal_cell` 已接入 production outer controller，并且不接受调用方传入 driver、transport、lifecycle receipt 或指标。

- 完整的 46×3×2 条件矩阵、H/E-only action schema 和 S／delegation 拒绝规则；
- manifest、任务、攻击目标、H 合同、Q/I/D、route 和代码哈希的逐层绑定；
- 离线 core 中的一次性 driver／transport／collector、fresh native worker、阶段预算和无自动重试；
- 同一 collector 内先写 evidence 再 seal，以及从 sealed trace 重算 native endpoint；
- evaluator 和 analysis 只接受注册 manifest、外部 seal hash 与内容寻址文件；调用方填入的指标、重哈希篡改、错题目标、旧 evidence 和 seal 后写入均被拒绝；
- 缺失或无法判定的值保持 missing／unknown 并进入固定 46 题分母上的 sharp bounds。
- 每个 production cell 自行启动绑定的独立 CLIProxy，完成 readiness 后运行 H/E；transport 凭据清空、proxy 停止和 secret root 删除全部确认后，才把五事件链式 receipt 与 formal evidence 一起 seal。
- offline fake evidence 明确标记 `formal_sample_eligible=false`，不能被 evaluator 升格为研究样本。

离线验证记录如下。formal runtime 组合回归使用私有工作区中锁定的 AgentDojo 源和 Python 3.12 runtime；transport 为确定性 fake HTTP，没有网络、凭据或真实模型调用。

| 验证组 | 结果 | 能证明什么 |
| --- | ---: | --- |
| 零样本 preregistration | 11/11 | 研究身份、H/E topology、276 格、阈值、unknown 与旧批次隔离 |
| Formal analysis | 10/10 | sealed 输入重算、缺失边界、篡改拒绝和三值 verdict |
| Wire／protocol／sealed runtime／permission evidence 组合回归 | 35/35 | H/E schema、离线单格 core 与 evidence 闭环、legacy 与伪造输入拒绝 |
| Production runtime qualification | 17/17 | 本地真实子进程与 HTTP；正常路径、stop 故障恢复、cleanup-before-failure-seal、offline evidence 拒绝入池 |
| 专用账号 CLIProxy 零生成演练 | 通过 | 精确绑定 runner／binary／route；start、readiness、stop、secret cleanup；0 generation、0 formal actor、0 research sample |

零样本 rehearsal 只证明本机绑定的 runner／binary／route 当前可用；它本身不是研究证据。正式 cell 还必须由 production runner 生成自己的 `start → readiness → actor run closed → stop → secret cleanup` receipt。当前代码已经执行并校验这一规则，离线 evidence 与缺少 receipt 的旧 evidence 都不能入池。

公开快照可直接审阅；仓库内的聚合修复 ledger 足以重新生成并测试零样本 preregistration：

```sh
cd experiments/host_boundary_v2/rq1_three_tier_large_scale/formal_candidate_20260915
python build_preregistration.py
python -m unittest -v test_preregistration.py
```

正式入口保持 fail closed。公开的 `build_formal_gate.py` 不带账号、endpoint、route、attestation 或本机 CLI 默认值；私有输入与三个 create-only 输出必须由调用方显式传入，缺一项或目标已存在都会在写文件前拒绝。可在仓库根目录核验这个公开 wrapper：

```sh
PYTHONPATH=. python experiments/host_boundary_v2/rq1_three_tier_large_scale/formal_candidate_20260915/test_build_formal_gate.py
PYTHONPATH=. python experiments/host_boundary_v2/rq1_three_tier_large_scale/formal_candidate_20260915/build_formal_gate.py --help
```

## 尚未关闭的正式门槛

当前仍缺少或尚未完成独立复核的项目是：

1. 18 个 goal clusters 的 final assignment；
2. 从 final goal assignment 重新编译的 final H contract；
3. 三档构念治理决定；
4. 最终统计计划的独立审查；
5. 全部 46 题的 Q/I/D scorer 与 evaluator qualification；
6. 汇总上述对象且在首个正式 actor 之前 create-only 生成的最终 manifest。

前五项 outcome-blind 门槛关闭后，才可用当前已经通过核验的 runtime qualification 与 production lifecycle receipt 创建新的 276 格正式 manifest。任何绑定文件变化都会使资格证明失效并强制重验；任何门槛失败都必须停止，不能回退到旧 campaign。

所以当前唯一成立的结论是：**production runtime 已形成可审计闭环，但正式实验仍未开始，现有材料不能判定 RQ1“支持”或“不支持”。** 完整设计见 [FORMAL_PROTOCOL_DESIGN.md](./FORMAL_PROTOCOL_DESIGN.md)，本轮工程状态见 [三档工程状态报告](../../../../docs/THREE_TIER_ENGINEERING_STATUS_20260916.md)。
