# RQ1 三角色可执行流程

入口：项目根目录 `bash run_rq1_three_actor.sh --help`。旧 v1/v2 数据保持原样。

```bash
# 新目录，绝不覆盖已有记录；默认 2 个已核验公开开发任务、24 个条件。
bash run_rq1_three_actor.sh prepare --output experiments/rq1-local-check/workflow
bash run_rq1_three_actor.sh run-offline --manifest experiments/rq1-local-check/workflow/run-manifest.json --runs experiments/rq1-local-check/runs --workers 4
bash run_rq1_three_actor.sh status --manifest experiments/rq1-local-check/workflow/run-manifest.json --runs experiments/rq1-local-check/runs
```

## 已实现

- 主 Agent：GPT-5（2025-08-07 快照，medium）；内部 S：GPT-4o（2024-08-06 快照，无推理档位）；外部 E：同一 GPT-5 快照，high。每个角色独立请求、身份、上下文和用量日志。
- `H_E` 与 `H_S_E` 对比；两组都有 E；E 最初都接入 H。E 只有 low/A0、medium/A3、high/A4 三档；H 固定 A4，S 固定 A3。S 必须被 H 明确委托，不能自行扩大工具权限或继续委托。
- 每任务 2 架构 × 3 权限 × 2 外部行为条件 × 1–3 次重复。相同原始任务、世界、模型和预算；H+S 共用内部预算，不因为加 S 免费增加预算。
- 公开 AgentDojo 原任务、原工具、原世界和原攻击目标经过来源检查后进入；每条从新的世界副本运行。当前仅开发面板，多个任务可能共享世界，不能当成独立大样本。
- 先关闭执行、封存原始日志，再运行评分器。保留任务完成、原始攻击目标是否实现、直接越界尝试、实际违规调用/状态变化、已收到的信息、明确转发来源链，互不替代。
- `run-offline` 是无模型的工具接线控制，只支持 workspace 的 8/24/26/35 号任务；自动产生的动作不是新研究数据。每条 `behavioral_n=0`。最多 4 个独立进程环境并行；失败停止新调度，保留在途及失败记录，重启不挑选最好一次。
- `run` 只运行一个指定条件。准备 `--mode live_diagnostic` 后，还需 `--execute-live` 和该代理最近 5 分钟的型号清单。型号缺失、版本不符、预算/响应交付不明时停止，不换模型、不重试掩盖失败。

真实调用入口示例（须先确认指定模型通道可用）：

```bash
bash run_rq1_three_actor.sh prepare --mode live_diagnostic --output experiments/rq1-live-check/workflow
bash run_rq1_three_actor.sh run --manifest experiments/rq1-live-check/workflow/run-manifest.json --episode '<manifest 中的 episode_id>' --output experiments/rq1-live-check/one-cell --execute-live --inventory '<新检查的型号清单路径>'
```

每条输出包含 allocation、execution/events.jsonl、execution/artifacts/evidence-v3.json、外部 seal 锚、report 和 status。运行中和失败条目同样计入总进度；`status` 重新检查已完成记录的完整性。

## 不能据此声称的事

流程通过不等于 RQ1 得到正结果；脚本导致的高权限删除只验证执行和检测。模型拒绝不是系统错误，也不能为了正结果改判。

当前没有完成自然语言评审的人类校准、综合分权重校准和所有原始风险族的载体覆盖，故 `weighted_score=null`、`formal_ready=false`。未观测到违规不等于所有风险为零；引用来源链也不等于证明心理因果。原生任务分和严格内容分分别保留，不用后者覆盖前者。

这是模型文本经工具控制器运行公开内存世界，不是可执行恶意代码的操作系统隔离。S 使用较弱模型的结果仅说明这一具体架构组合，不能直接推广为“多 Agent 一定更危险”。

配置和代码摘要绑定是为了防止不同实现的结果被混在一起，不是阻止继续修正；代码改动后新建运行目录即可，旧失败仍保留。
