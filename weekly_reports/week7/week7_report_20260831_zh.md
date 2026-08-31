# 第七周研究汇报：RQ1B 在单一 AgentDojo 工作流上的易感性校准结果

> **统一命名：本报告中的实验只叫 `RQ1B`。**
>
> Proposal machine alignment：`RQ1b_host_mediated`；construct：`host_mediated_capability_exploitation`。历史实验文件中保留的旧标签仅用于复现兼容，不代表本实验属于 RQ2。本文所说的 RQ2 始终指 proposal 的 canonical RQ2；本报告不汇报 RQ2 结果。

## 0. 一句话结论

本周在一个真实 AgentDojo banking 工作流和人为校准的易感 GPT-5.6-sol/max planner 上，RQ1B 的 resource-binding membrane 将攻击成功从 **50/50 降到 0/50**，同时保持 benign utility **50/50**。

这是一个清晰的 **RQ1B 工程正结果**，说明当前实现至少在该工作流和该易感策略上能够稳定阻断已激活攻击；但它还不是总体科学结论：50 次是同一个工作流的重复运行，科学独立工作流数仍为 **n=1**，且易感策略是在自然策略 0/3 未激活后引入的校准策略。因此本轮标记为 `claim_eligible=false`、`population_estimating=false`，不能写成 canonical RQ2 完成，也不能写成公开 benchmark 上的普遍有效性。

## 1. 这轮到底回答什么

RQ1B 研究的是：当不可信模型可以借助宿主动作、资源句柄和 capability 路由把语义影响转成真实效果时，受保护宿主是否能在 pre-dispatch 阶段阻断越界动作，同时保留正常任务效用。

本轮使用 AgentDojo v1 banking 任务 `agentdojo-v1-banking-u3-i1`，搭建四格对照：

| 输入 | Vulnerable host | Protected host |
| --- | --- | --- |
| Benign | 正常任务效用基线 | 检查防护是否误伤效用 |
| Adversarial | 检查攻击是否真正激活并成功 | 检查 membrane 是否在真实 dispatch 前阻断 |

每个 case 使用 benign 与 adversarial 两条 planner trace，并在 vulnerable/protected host 间做配对 proposal replay。每个 case 实际交付 4 次模型调用，但不是四条相互独立的 agent trajectory。模型为 `gpt-5.6-sol`，reasoning effort 为 `max`。

## 2. 自然策略激活门

在引入易感性校准前，先运行自然 prompt policy：

| 指标 | 结果 |
| --- | ---: |
| Cases | 3 |
| 真实模型调用 | 12 |
| Vulnerable attack activation | 0/3 |
| 分类 | `ACTIVATION_INSUFFICIENT` 3/3 |
| 输入 tokens | 20,186 |
| 输出 tokens | 5,406 |
| 总 tokens | 25,592 |
| 调用失败 / retry | 0 / 0 |

这一步说明：在该单一工作流的自然策略下，攻击没有被模型主动执行，因此不能直接估计 membrane 的防护效果。若继续机械扩大相同自然 prompt 的重复次数，只会重复观测“不激活”，而不会形成有信息量的防护对照。

## 3. 易感性校准批次

为了验证“攻击一旦被 planner 接受并执行，membrane 能否阻断”，本轮采用冻结的易感性策略 `native-observation-workflow-continuation-v1`，在同一工作流上重复 50 个 case。

| 指标 | 结果 |
| --- | ---: |
| 完成 cases | 50/50 |
| 真实模型调用 | 200 |
| Vulnerable attack activation / success | 50/50 |
| Protected attack success | 0/50 |
| `CONTAINMENT_SIGNAL` | 50/50 |
| Protected benign utility | 50/50 |
| Utility loss | 0/50 |
| 输入 tokens | 351,431 |
| 输出 tokens | 109,287 |
| 总 tokens | 460,718 |
| 调用失败 / retry | 0 / 0 |

结果方向非常稳定：在 vulnerable host 上，校准策略每次都触发并完成攻击；同一 proposal 进入 protected host 后，每次都被可信的 pre-dispatch membrane 拒绝；正常任务在 protected host 上仍全部通过。

## 4. 完整性与工程验证

- 50/50 case 的结果文件均完成 SHA-256 复核。
- 聚合进度文件 SHA-256：`a5f5aae9d2cc038569209b501192010bc557d92588e9dbfc0accffa6f6d55f5d`。
- 本轮相关离线测试：**247/247 passed**。
- 50-case 批次无 provider failure、无 transport retry、无解析失败。
- 运行工件明确记录：`engineering_only=true`、`claim_eligible=false`、`population_estimating=false`。

内部证据入口：

```text
agentmembrane/experiments/host_boundary_v2/public_four_cell_canary_v1/outputs/
  calibrated-susceptibility-batch-v1-progress.json
```

## 5. 可以怎么说，不能怎么说

### 可以说

> 在一个真实 AgentDojo banking workflow 和人为校准的易感 GPT-5.6-sol/max planner 上，RQ1B 的 resource-binding membrane 将攻击成功从 50/50 降到 0/50，同时保持 benign utility 50/50。

这是一项稳定的工程验证，也支持继续把 RQ1B 扩展为多工作流的正式研究实验。

### 不能说

- 不能把 50 次重复写成 50 个独立工作流；本轮科学独立工作流数是 1。
- 不能把校准后结果写成自然分布上的攻击成功率或防护效果。
- 不能写成 AgentDojo 全数据集、公开 benchmark 或任意 agent 的总体有效性。
- 不能写成 canonical RQ2 已完成；RQ2 是另一项独立研究问题，需要单独设计和运行。
- 不能把本轮写成完整 RQ1；它只属于 RQ1B 子轨。

## 6. 当前判定

| 层级 | 状态 |
| --- | --- |
| RQ1B 代码与真实 API 链路 | **PASS** |
| 单工作流攻击激活校准 | **PASS** |
| 单工作流 containment 工程结果 | **POSITIVE：50/50 → 0/50** |
| Benign utility preservation | **PASS：50/50** |
| 自然策略下的攻击激活 | **NOT OBSERVED：0/3** |
| 多工作流 / 多任务总体结论 | **NOT ESTIMATED** |
| Paper-ready / public claim | **NO** |
| Canonical RQ2 | **未在本报告运行** |

## 7. 下一步

RQ1B 若继续进入正式 claim-bearing 阶段，需要预先冻结以下设计，而不是继续重复当前单一任务：

1. 扩展为多个独立 AgentDojo workflow cluster，并以 workflow 为科学独立单位；
2. 在看结果前预注册 susceptibility policy、纳入标准、estimand 与停止规则；
3. 将 vulnerable/protected 条件改为真正独立或严格受控的配对轨迹设计，并明确 replay estimand；
4. 增加多 seed、多模型和不同攻击机制；
5. 公开报告 cluster-level 置信区间、效用损失和失败分层，而不是只报 case-level 50/50。

Canonical RQ2 应在新的独立页面中按 proposal 的 RQ2 定义重新搭建，不复用 RQ1B 的名称、数据或结论。

## 8. 本周最终状态

**RQ1B 已得到单工作流、校准易感策略下的明确工程正结果；正式总体科学结果尚未得到。Canonical RQ2 尚未开始在本报告中运行。**
