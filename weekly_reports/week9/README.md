# Week 9 Package

本目录记录 AgentMembrane RQ1 三档外部 Agent 业务工具权限实验的 baseline、120 格最终工程结果、中档倒挂原因、剩余问题与下周计划。

| 文件 | 内容 |
| --- | --- |
| [week9_report_20260916_zh.md](./week9_report_20260916_zh.md) | 本周完整汇报（09-17 更新）：直接包含六组结果表、baseline、逐题诊断、待修问题和下周验收计划 |
| [week9_stage_snapshot_20260917.json](./week9_stage_snapshot_20260917.json) | 最新周报对应的最终计数、配对计数与来源哈希 |
| [week9_stage_snapshot_20260916.json](./week9_stage_snapshot_20260916.json) | 09-16 历史快照：旧暂停批次及当时准备度，保留不变 |
| [120 格最终工程汇总与中档倒挂诊断](../../reports/rq1/THREE_TIER_FINAL_MEDIUM_DIAGNOSIS_20260917.md) | 全部关闭：113 正常执行、7 unknown；最终表、配对比较及具体工程原因，非正式 RQ1 验证 |
| [105 格历史阶段汇总](../../reports/rq1/THREE_TIER_PILOT_PROGRESS_105_20260917.md) | 六组实测结果、7 格异常与剩余 15 格；工程诊断、代码仍在修复 |
| [20 原题真实 API 初期更新](../../reports/rq1/THREE_TIER_PILOT_20260916.md) | 20×6 工程试跑的初期修复、连接问题与 24 格截点 |
| [三档工程状态](../../docs/THREE_TIER_ENGINEERING_STATUS_20260916.md) | 本轮 formal runtime、sealed evaluator/analysis 的落地状态、离线测试和剩余硬门槛 |
| [正式协议设计](../../experiments/host_boundary_v2/rq1_three_tier_large_scale/formal_candidate_20260915/FORMAL_PROTOCOL_DESIGN.md) | 46×3×2、H/E-only、逐格生命周期、评分与三值裁决的完整设计 |

formal runtime 的离线执行、封存、evaluator 和 analysis 路径已经实现并通过 fake-transport 验证；production lifecycle 也已完成代码接入与本地启停验证；正式 Q/I/D 和 final H/goal/statistical contracts 仍未取得完整资格。`formal_ready=false`、正式样本数为 0；旧暂停批次永久不具备 formal 资格。
