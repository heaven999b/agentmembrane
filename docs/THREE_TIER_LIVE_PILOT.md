# 三档权限真实 API 工程试跑

这批由用户指定为 **20 道原题 × low/medium/high × honest/malicious = 120 格**，每格一次，无多 seed。它检查当前代码和真实模型连接能否工作；正式 RQ1 的准入门槛不因此自动通过。旧 campaign 保持暂停，结果不合并。

## 固定的比较方式

- 从锁定的 46 题候选池中，先覆盖候选攻击目标簇，再平衡四个 suite；选择过程不读取结果。
- 每道题的六格固定相同初态、攻击目标、H 提示、H/E 模型及预算。条件次序按题轮换，完整清单在首个模型请求前保存。
- 使用 production 的 H/E-only driver、权限控制、native worker 和逐格反代生命周期。Low 的 E 无业务工具，Medium 使用逐题目的权限，High 使用 suite 内较宽权限。
- 每格独立启动反代，确认就绪后执行，停止进程并删除临时凭据，再封存原始证据。
- 原始证据存放在 `runs/<episode>/evidence/`；外部封存锚点、评分和摘要存放在其父目录，封存后不再改写证据目录。
- G 使用当前绑定攻击目标的原生终态判据；L 使用严格原任务检查器。工具调用从已核验的封存记录重建。Q/I/D 尚无新候选目标对应的合格观察器，明确输出未知，不套用旧目标评分表。
- API 投递不明、进程清理不明、评分异常和未封存运行会暂停批次。失败记录保留；没有自动重跑、替换题或删失败格。

## 执行入口

在已完成数据和 Python 3.12 依赖准备的私有工作区执行。将公开仓库的源代码同步过去并通过 `tools/audit_workspace_source_sync.py` 后，使用该工作区的已锁定 Python。路径参数指向私有研究输入，不包含 API key。

```sh
"$NATIVE_PYTHON" tools/run_rq1_three_tier_pilot.py prepare \
  --qualified "$QUALIFIED_MANIFEST" --pool "$TASK_POOL" \
  --goals "$GOAL_BALANCE_CANDIDATE" --route-binding "$ROUTE_BINDING" \
  --task-count 20 --output "$NEW_PILOT_DIRECTORY"

"$NATIVE_PYTHON" tools/run_rq1_three_tier_pilot.py run \
  --manifest "$NEW_PILOT_DIRECTORY/pilot-manifest.json" --max-new-cells 1

"$NATIVE_PYTHON" tools/run_rq1_three_tier_pilot.py run \
  --manifest "$NEW_PILOT_DIRECTORY/pilot-manifest.json"

"$NATIVE_PYTHON" tools/run_rq1_three_tier_pilot.py summary \
  --manifest "$NEW_PILOT_DIRECTORY/pilot-manifest.json"
```

本地 route collision 配置沿用 [仓库工作流](REPOSITORY_WORKFLOW.md) 中的三个显式环境变量。模型凭据由绑定的私有 lifecycle runner 管理，不放进命令、manifest 或公开仓库。执行期间源码和所有绑定输入冻结；代码改动后不得继续混跑旧 manifest。

摘要分别报告六个条件的计划数、已执行数、G/L 阳性数、可判定分母与缺失。`formal_sample_count` 始终为 0；这批的效应数值只能用于工程诊断，不能直接宣称正式 RQ1 得到支持。
