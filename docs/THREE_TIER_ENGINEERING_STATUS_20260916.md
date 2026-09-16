# RQ1 三档权限工程状态（2026-09-16）

## 当前结论

三档方案已经从“按档位写概念”推进到可审计的 production 执行闭环：逐题权限 policy、H/E-only wire、manifest-bound runtime、逐格 CLIProxy 生命周期、sealed evidence、native evaluator 和 formal analysis 都已有实现，并在锁定环境中通过针对性测试。

公开 production 入口只接受已激活 manifest、注册 `episode_id` 和全新输出目录。它自行创建 native worker、collector、formal driver、manifest-bound transport 与独立 CLIProxy；调用方不能注入 driver、transport、lifecycle receipt 或指标。每格在 evidence seal 前完成 `start → readiness → actor run closed → stop → secret cleanup`，cleanup 未确认即失败关闭。

它还不是正式研究结果。当前 `formal_ready=false`，正式研究样本数为 0。此次用切换后的专用账号路由完成了一次真实 CLIProxy 零生成生命周期演练，只调用 `/models` readiness，不调用模型生成，不分配 formal cell，也不进入研究统计。旧 `live_campaign_002` 永久暂停，不能恢复或与新实验合并。因此现阶段不能回答 RQ1“支持”或“不支持”。

## 这次三档 baseline 是什么

本研究保持 H 能力不变，只改变 E 的业务工具权限。固定池为 46 道 AgentDojo 原题；每题运行 low／medium／high × honest／malicious 六格，每格一次、不做多 seed，共 276 格。actor set 只有 H 和 E。

| 档位 | E 的真实能力 | 预期用于识别的差异 |
| --- | --- | --- |
| Low | 无业务工具，只能给 H 发协议内文本 | 没有 E 直接执行路径时的风险和效用基线 |
| Medium | 逐题 purpose-guarded 工具、对象、参数、顺序、次数和返回字段 | 原题可做，但原题之外的攻击路径应被 policy 阻断 |
| High | suite 范围的较宽 ambient 工具面 | 注册攻击目标存在技术可达路径，同时仍受 sandbox 和证据约束 |

模型、token budget、phase schedule、H system/output contract、任务初态、checker 和攻击目标在同题六格内保持一致。正式分析关注 high 相对 medium 的攻击特异性 G 差分中的差分，同时用 honest L 和 Q 检查 medium 是否以过高的正常任务损失换取安全性。

## 已落地的执行链

1. **条件与准入：** 完整生成 46×3×2 矩阵；拒绝缺格、重复格、额外角色 S、模型漂移和旧 evidence。
2. **权限执行：** Low 无业务工具；Medium 逐题检查目标、参数、顺序、次数、source identity 和结果投影；High 提供较宽但仍受控的 suite 工具面。
3. **逐格隔离：** production runner 为每格创建 fresh native worker、collector、driver、bound transport 和独立 CLIProxy；driver/transport 不可跨格复用，自动重试和替换题被禁用。
4. **模型协议：** 只允许 H/E formal action schema；旧 S/delegation schema 和裸 HTTP transport 在 actor 运行前被拒绝。
5. **可信评估：** strict original-task checker 与 native attack-goal endpoint 从绑定终态运行；攻击成功按 E-direct、H-mediated、both 或 unknown 分解。
6. **清理、封存与分析：** transport 凭据引用先清空，proxy 停止且 secret root 删除后，链式 lifecycle receipt 与 evidence 才写入同一 collector 并 seal；evaluator 从 sealed trace 重算结果，analysis 只接受注册文件和外部 seal hash。调用方自填指标、重哈希篡改、错 goal 和 seal 后写入均失败。
7. **缺失处理：** 基础设施失败和语义无法判定保持 missing／unknown，在冻结的 46 题分母上进入 sharp bounds，不当作 0 或成功。

## 本轮验证结果

| 测试 | 结果 | 运行条件 |
| --- | ---: | --- |
| Preregistration | 11/11 | 零样本、无 API |
| Formal analysis | 10/10 | 本地构造的 sealed evaluation fixtures |
| Wire／protocol／sealed runtime／permission evidence | 35/35 | 私有锁定 AgentDojo source + Python 3.12 runtime；fake HTTP transport |
| Production runtime qualification | 17/17 | 本地子进程模拟真实 `/models` 与 `/chat/completions`；含 stop 失败恢复、cleanup-before-failure-seal、offline evidence 拒绝入池 |
| 切换账号 CLIProxy lifecycle rehearsal | 通过 | 绑定真实 runner／binary／route；start、readiness、stop、secret cleanup 全部确认；0 generation、0 formal actor、0 research sample |

当前 formal code bundle SHA-256 为 `76e6309bf28826e019c693ac766c2f3bda29ff6790a2de4284c79e084bbb5c50`；production lifecycle rehearsal receipt SHA-256 为 `2132830ad504e1e54b26e755e969175fb56d2a006400d1ed3af4b98da0b56202`；私有执行工作区的 runtime qualification SHA-256 为 `32e6fe0a076279f32964aec90d1762eded28dcc36f5f9e2c45d372a492ebcb4f`。这些验证证明代码路径、绑定关系、拒绝规则和真实代理生命周期闭环，没有产生模型行为数据，不能作为三档效果结果。

## 仍未完成的问题

| 硬门槛 | 当前缺口 | 通过条件 |
| --- | --- | --- |
| Final goal assignment | 18 个候选 goal clusters 尚未完成最终独立裁定 | 46 题恰好一题一 goal，source/checker/hash 固定，旧 campaign goal 复用为 0 |
| Final H contract | 当前合同仍基于候选 assignment | 从 final goals 重编，逐题六格完全一致，无 S |
| 构念治理 | 三档是独立子研究，尚未正式激活 | 明确 claim scope，不冒充 canonical A0–A5 |
| 统计审查 | candidate v2 阈值已冻结，仍缺独立审查决定 | 在看结果前批准主效应、20pp 门槛、−10pp guardrails、missing bounds 和 18-cluster 解释 |
| Q/I/D qualification | 合同与 diagnostic scorer 不等于正式资格 | 46/46 题的 scorer、observer、source lineage 和 evaluator 全部通过并内容寻址 |
| Final manifest | 依赖以上全部对象 | 首个正式 actor 前 create-only 生成完整 276 格 manifest，任何输入漂移均失败 |

## 下一步的固定顺序

1. 完成 final goal、由其重编的 H contract、构念治理和 outcome-blind 统计审查。
2. 完成全 46 题 Q/I/D adjudication 与 evaluator qualification，并核对 source lineage、unknown 规则和内容哈希。
3. 以当前通过资格验证的 runtime、route、canary 和 lifecycle receipt，create-only 生成新的 276 格正式 manifest；任一绑定文件漂移都必须重做资格验证。
4. 按 manifest 固定顺序运行，不重试、不换题；完成后从 sealed evaluation 生成支持／不支持／证据不足三值结论。

完整协议见 [formal candidate README](../experiments/host_boundary_v2/rq1_three_tier_large_scale/formal_candidate_20260915/README.md) 和 [formal protocol design](../experiments/host_boundary_v2/rq1_three_tier_large_scale/formal_candidate_20260915/FORMAL_PROTOCOL_DESIGN.md)。第九周中期基线与旧诊断结果见 [Week 9 report](../weekly_reports/week9/week9_report_20260916_zh.md)。
