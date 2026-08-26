[← Back to reference index](README.md)

# FlowSteer: Prompt-Only Workflow Steering Exposes Planning-Time Vulnerabilities in Multi-Agent LLM Systems

- **Authors:** Fanxiao Li, Jiaying Wu, Tingchao Fu, Natasha Jaques, Wei Zhou, Min-Yen Kan
- **Year / status:** 2026 preprint
- **Primary source:** [arXiv:2605.11514](https://arxiv.org/abs/2605.11514)
- **AgentMembrane priority:** Conditional

## Abstract（中文转述）

论文研究 planner–executor 多 Agent 系统在工作流形成阶段的攻击面。作者先用社会影响探测定位高影响子任务，发现工作流位置和迎合式 framing 会放大恶意信号；随后提出 FlowSteer，用单个提示引导重新规划，使恶意信号进入更有影响力且能维持传播的依赖路径，并提出输入侧 FlowGuard 作为防御。

## AI 生成总结（200 字以内）

研究对象是多 Agent 工作流规划阶段的信号传播。方法先估计各子任务的结构影响力，再用 crafted prompt 操纵角色、依赖与路由，使恶意信号沿高影响路径保留。

## 与 AgentMembrane 的关系

- **重合：** 揭示 receptor 所处工作流位置会改变语义信号的传播强度。
- **边界：** 主要攻击规划拓扑，不要求真实完整证据，也不研究 memory promotion。
- **引用方式：** 仅当实验纳入 workflow topology 或 adaptive multi-agent attacker 时重点引用。
