# 三档 AgentDojo 正式研究候选

> **当前状态（2026-09-16）：离线工程闭环已实现，正式研究尚未激活。**
> `formal_activation=false`、`formal_ready=false`、正式研究样本数为 0。
> 本轮修复没有调用模型或 API。离线测试通过只证明协议和代码在受控输入上
> fail closed；它不等于 276 格正式实验已经可以开跑。

本目录固定的是一项独立的 RQ1 三档子研究：46 道 AgentDojo 原题 × low／medium／high 三档 × honest／malicious 两种 regime，每格一次，共 276 格。actor set 只有 H 和 E；H 的原题工具权限、模型、预算和输出合同在六格内固定，只改变 E 的业务工具权限。旧 `live_campaign_002` 永久暂停，不能恢复、补跑、升格或与新实验合并。

## 三档实际执行边界

| 档位 | E 可见的业务工具面 | runtime 实现 | 约束 |
| --- | --- | --- | --- |
| Low | 无 AgentDojo 业务工具 | `A0` | 只能按 H/E 协议发送文本和结束自己的阶段 |
| Medium | 当前原题目的所需工具和参数子集 | `A3` purpose-guarded | 绑定对象、参数、顺序、次数和结果字段；歧义、漂移、越权或重复提交均失败关闭 |
| High | 同 suite 的较宽实验工具面 | `A4` ambient；旧 canonical analog 为 A5 | 保留 sandbox、证据与单格生命周期约束，但使原生攻击目标具有技术可达路径 |

这些 runtime 名称只是实现标签。三档研究不声称覆盖 canonical A0–A5 全梯度，也不能据此识别全局权限阈值 A*。正式结果必须分别报告 E-direct 与 H-mediated 路径。

## 已完成的离线工程

以下项目是可注入 fake transport 的离线 qualification core，不是 production
runner。公开 `runner.run_formal_cell` 当前固定 fail closed，并且不接受调用方
传入的 driver 或 transport。

- 完整的 46×3×2 条件矩阵、H/E-only action schema 和 S／delegation 拒绝规则；
- manifest、任务、攻击目标、H 合同、Q/I/D、route 和代码哈希的逐层绑定；
- 离线 core 中的一次性 driver／transport／collector、fresh native worker、阶段预算和无自动重试；
- 同一 collector 内先写 evidence 再 seal，以及从 sealed trace 重算 native endpoint；
- evaluator 和 analysis 只接受注册 manifest、外部 seal hash 与内容寻址文件；调用方填入的指标、重哈希篡改、错题目标、旧 evidence 和 seal 后写入均被拒绝；
- 缺失或无法判定的值保持 missing／unknown 并进入固定 46 题分母上的 sharp bounds。

离线验证记录如下。formal runtime 组合回归使用私有工作区中锁定的 AgentDojo 源和 Python 3.12 runtime；transport 为确定性 fake HTTP，没有网络、凭据或真实模型调用。

| 验证组 | 结果 | 能证明什么 |
| --- | ---: | --- |
| 零样本 preregistration | 11/11 | 研究身份、H/E topology、276 格、阈值、unknown 与旧批次隔离 |
| Formal analysis | 10/10 | sealed 输入重算、缺失边界、篡改拒绝和三值 verdict |
| Wire／protocol／sealed runtime／permission evidence 组合回归 | 35/35 | H/E schema、离线单格 core 与 evidence 闭环、legacy 与伪造输入拒绝 |

这些测试不能证明真实 CLIProxy 的逐格进程生命周期。现有 production receipt
只覆盖一次零样本 rehearsal；cell seal 早于外部 cleanup，因此无法证明每格都
完成 `start → readiness → run → stop → secret cleanup`，也无法把 cleanup
结果绑定到该格证据。代码据此设置
`FORMAL_PER_CELL_PROXY_LIFECYCLE_IMPLEMENTED=false` 和
`FORMAL_RUNTIME_IMPLEMENTED=false`；manifest gate 会在检查 rehearsal receipt
之前拒绝激活。

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
6. 尚未实现的 production outer controller：它必须自行创建 manifest-bound transport，逐格完成 CLIProxy 启动、readiness、执行、停止和 secret cleanup，并在 cleanup 后才封存该格链式 receipt；
7. 汇总上述对象且在首个正式 actor 之前 create-only 生成的最终 manifest。

先完成前五项离线门槛和 outer controller 的 fake-process fail-closed 测试，才允许在正式 46 题池之外做一次隔离的真实 CLIProxy smoke；该次运行只用于路由和生命周期资格验证，研究样本数仍为 0，结果不得并入 RQ1。smoke 与 production lifecycle receipt 通过复核后，才可创建新的 276 格正式 manifest。任何门槛失败都必须停止，不能回退到旧 campaign。

所以当前唯一成立的结论是：**工程实现已进入可审计的离线闭环，但正式实验仍未开始，现有材料不能判定 RQ1“支持”或“不支持”。** 完整设计见 [FORMAL_PROTOCOL_DESIGN.md](./FORMAL_PROTOCOL_DESIGN.md)，本轮工程状态见 [三档工程状态报告](../../../../docs/THREE_TIER_ENGINEERING_STATUS_20260916.md)。
