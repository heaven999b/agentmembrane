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

"$NATIVE_PYTHON" tools/summarize_rq1_three_tier_pilot.py \
  --manifest "$NEW_PILOT_DIRECTORY/pilot-manifest.json" \
  --output "$NEW_PUBLIC_SNAPSHOT" --aggregate-only
```

本地 route collision 配置沿用 [仓库工作流](REPOSITORY_WORKFLOW.md) 中的三个显式环境变量。模型凭据由绑定的私有 lifecycle runner 管理，不放进命令、manifest 或公开仓库。执行期间源码和所有绑定输入冻结；代码改动后不得继续混跑旧 manifest。

摘要分别报告六个条件的计划数、已执行数、G/L 阳性数、可判定分母与缺失。`formal_sample_count` 始终为 0；这批的效应数值只能用于工程诊断，不能直接宣称正式 RQ1 得到支持。

导出入口逐格重新检查原始封存证据、外部锚点和评分绑定。加 `--aggregate-only` 才生成公开聚合结果；不加该选项的逐格诊断仅留在私有工作区。两种输出均不含调用参数、消息、账号信息或私有路径。它额外报告 source-bound native observer 能识别的越界效果，作为工程诊断；该项不是正式 D，未覆盖的现象保持 unknown。攻击目标未达成也可能伴随其他越界效果，两者分别报告。

## 超时后继续与评分修正

`tools/continue_rq1_three_tier_pilot.py` 接受两类经过明确审核的失败：已封存并清理的孤立 HTTP 408，以及 actor 启动前、零模型请求且已完整封存和清理的基础设施失败。review 文件必须绑定 manifest 和每个失败格的外部 seal hash，声明 `retry_existing_cells=false`；基础设施失败还必须绑定 `failure.json` 的 hash，并通过零请求事件链核验。评分错误、账号错误和未完成证据不在可继续范围内。先运行 `--check-only`，再执行同样的命令去掉该选项。它只运行从未尝试的格，遇到新失败再次暂停，不覆盖超时格。

在原冻结执行快照目录运行：

```bash
"$NATIVE_PYTHON" tools/continue_rq1_three_tier_pilot.py \
  --manifest "$NEW_PILOT_DIRECTORY/pilot-manifest.json" \
  --review "$REVIEW_RECEIPT" --check-only
```

review JSON 字段为 `manifest_sha256`、`reason="isolated_upstream_timeout_reviewed"`、`retry_existing_cells=false` 和 `acknowledged_failures`；最后一项逐格列出 `episode_id` 与 `execution_seal_sha256`。必须先核对原证据确为孤立上游 408 且清理已确认，才能写入 review。混合基础设施失败的 review 使用 `reason="sealed_failures_reviewed_no_replay"`，相应项增加 `failure_kind="pre_actor_infrastructure_failure"` 与 `failure_record_sha256`；这些失败保留 unknown，不重新执行。

如果在工程试跑中修正了评分器，执行仍在原提交导出的冻结源码快照中继续；actor 提示、权限、模型、预算和所有任务保持不变。评分修复在规范仓库维护，最终导出时用 `--checker-reanalysis` 指定修正版。该重算明确标记为事后诊断，保留 `L_original`、修正后的 `L`、执行代码 hash 与新评分器 hash；不重新调用模型、不替换原始结果。冻结快照是运行证据档案，不是另一份开发源。

续跑控制器可用 `--execution-source "$FROZEN_EXECUTION_SOURCE"` 指向原冻结源码；控制器版本单独留存和记录 hash。启动前先在相同权限环境中做零模型请求的反代启停验证。本地端口被沙箱阻止时，必须通过宿主工具的授权提权启动，不能把环境权限问题当作实验失败连续消耗新格，也不能更换账号或修改冻结生命周期。

## 持久续跑与问题格留档

`tools/supervise_rq1_three_tier_pilot.py` 在同一独占进程内执行剩余注册格，不依赖聊天子代理持续存活。已经尝试的格不会重跑。遇到已封存、清理已确认、无评分错误的孤立 408，或经过严格核验的 controller `ValueError`，生成独立 review 并通过完整证据核验后保留 unknown、继续下一格。后者还核验 summary/config/failure hash、完整调用轨迹、生命周期收据以及每个已记录请求的交付状态；不接受混合账号或接口错误。

未知错误、账号失效、封存或清理问题、连续三个失败会停止并写 `attention.json`。完成时写 `closed.json`，含最终 review 路径和“最终分析仍待完成”的标记。该执行闭合标记不代表科研评分已通过。

```bash
"$NATIVE_PYTHON" tools/supervise_rq1_three_tier_pilot.py \
  --execution-source "$FROZEN_EXECUTION_SOURCE" \
  --manifest "$PILOT_MANIFEST" --review "$REVIEW_RECEIPT" \
  --guard "$REVIEWED_CONTINUATION_GUARD" --guard-sha256 "$GUARD_SHA256" \
  --audit "$NEW_SUPERVISOR_AUDIT_DIRECTORY"
```

所有路径均使用绝对路径；从通过启停验证的权限环境启动。控制器及审核器需各自冻结版本与 hash；保留原失败证据和后续自动审核记录。相关离线防护测试：`python3 -m unittest tests.rq1_three_tier.test_pilot_supervisor -v`。
