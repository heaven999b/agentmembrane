# Week 9 Package

本目录记录 AgentMembrane RQ1 三档外部 Agent 业务工具权限实验的 baseline、暂停诊断结果与正式化进度。

| 文件 | 内容 |
| --- | --- |
| [week9_report_20260916_zh.md](./week9_report_20260916_zh.md) | 第九周中期研究汇报；明确区分旧 mixed-code diagnostic 与尚未启动的正式 46 题 × 6 格批次 |
| [week9_stage_snapshot_20260916.json](./week9_stage_snapshot_20260916.json) | 与周报关键数字对应的去敏机器汇总 |
| [105 格最新阶段汇总](../../reports/rq1/THREE_TIER_PILOT_PROGRESS_105_20260917.md) | 六组实测结果、7 格异常与剩余 15 格；工程诊断、代码仍在修复 |
| [20 原题真实 API 试跑更新](../../reports/rq1/THREE_TIER_PILOT_20260916.md) | 20×6 工程试跑的修复、连接问题与最新运行状态 |
| [三档工程状态](../../docs/THREE_TIER_ENGINEERING_STATUS_20260916.md) | 本轮 formal runtime、sealed evaluator/analysis 的落地状态、离线测试和剩余硬门槛 |
| [正式协议设计](../../experiments/host_boundary_v2/rq1_three_tier_large_scale/formal_candidate_20260915/FORMAL_PROTOCOL_DESIGN.md) | 46×3×2、H/E-only、逐格生命周期、评分与三值裁决的完整设计 |

formal runtime 的离线执行、封存、evaluator 和 analysis 路径已经实现并通过 fake-transport 验证；production lifecycle 也已完成代码接入与本地启停验证；正式 Q/I/D 和 final H/goal/statistical contracts 仍未取得完整资格。`formal_ready=false`、正式样本数为 0；旧暂停批次永久不具备 formal 资格。
