# Week 12 Package (as of 2026-10-07)

本目录记录第十二周(2026-10-01 至 10-06)的进展:核心实验(核对怎么说 × 给什么出口)落地并完成;"查不到"两难的补全批;独立审核;方法"见证式提交"及其同题消融;针对封存与判官的红队;四因素交叉设计与理由码;18 篇近邻论文全文精读;评测工具打包。

- **研究设计与各 RQ 进展:[新版研究设计与各 RQ 进展](../../docs/AGENTMEMBRANE_V2_DESIGN_AND_STATUS_zh.md)**
- **proposal 原文:[AgentMembrane v2 研究 proposal](../../docs/PROPOSAL_V2_20260927_zh.md)**

| 文件 | 内容 |
| --- | --- |
| [week12_report_20261007_zh.md](./week12_report_20261007_zh.md) | 本周汇报,按 RQ 组织:RQ-A 到 RQ-E 与边界各一节,每节写问什么、怎么实现、证据(数字与级别)、状态;旧编号 RQ1–RQ9 的去向与本周新增证据(RQ3 过程、RQ7 人在环有了数据);另有跨 RQ 材料、修掉的问题、下一步 |
| [week12_stage_snapshot_20261007.json](./week12_stage_snapshot_20261007.json) | 各批 episode 数与错误数、预注册 / 判定 / 运行哈希文件的 sha256、代码哈希、测试结果、报告中全部关键数字 |
| [supporting/fig1_diagonal.png](./supporting/fig1_diagonal.png) | 核心图:各防御设计在"放行真值 × 放行假值"平面上的位置;不带见证的设计都在对角线附近 |

证据等级:核心实验主题集、"查不到"补全批、方法第 1 段、红队主检验、交叉设计主效应为预注册确认性结果(单模型对、单场景);三套题合并与第二模型为稳健性;零 API 解剖与近邻估算为诊断。快照整体标 `claim_bearing = false`。实验工作区与原始输出位于主仓库之外。
