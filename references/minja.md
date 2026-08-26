[← Back to reference index](README.md)

# Memory Injection Attacks on LLM Agents via Query-Only Interaction (MINJA)

- **Authors:** Shen Dong, Shaochen Xu, Pengfei He, Yige Li, Jiliang Tang, Tianming Liu, Hui Liu, Zhen Xiang
- **Year / status:** 2025 preprint; revised 2026
- **Primary source:** [arXiv:2503.03704](https://arxiv.org/abs/2503.03704)

## Abstract（中文转述）

论文研究攻击者无法直接编辑 Agent memory 时，是否仍能仅通过查询和观察输出注入恶意记录。MINJA 构造从受害查询连接到目标恶意推理的 bridging steps，先用 indication prompt 引导 Agent 生成这些步骤，再逐渐缩短提示，使记录能够在未来相关查询中被检索并触发目标行为。实验覆盖多类 Agent 与受害—目标组合。

## AI 生成总结（200 字以内）

研究对象是无内存写权限的 query-only 攻击者。方法通过桥接推理、诱导提示和渐进缩短，让 Agent 自己生成并存入可被未来目标查询召回的恶意记忆。

## 与 AgentMembrane 的关系

- **重合：** 与“外部参与者经合法接口建立持久影响”高度相关。
- **边界：** MINJA 的目标记录包含恶意推理或行为诱导；AgentMembrane 的核心攻击不得包含显式指令或答案。
- **引用方式：** 作为显式 memory injection 基线，并帮助定义外部 Agent 的实际权限假设。
