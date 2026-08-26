[← Back to reference index](README.md)

# Prompt Infection: LLM-to-LLM Prompt Injection within Multi-Agent Systems

- **Authors:** Donghyun Lee, Mo Tiwari
- **Year / status:** 2024 preprint
- **Primary source:** [arXiv:2410.07283](https://arxiv.org/abs/2410.07283)
- **AgentMembrane priority:** Conditional; bio/virus framing

## Abstract（中文转述）

论文研究恶意提示如何在相互连接的 LLM Agent 之间传播。Prompt Infection 把攻击载荷设计成能够诱使接收 Agent 继续复制和转发的提示，类似计算机病毒，可导致数据窃取、诈骗、虚假信息或系统扰乱。作者在多 Agent 设置中测试传播，即使通信不完全公开仍观察到脆弱性，并提出 LLM Tagging 与既有防护组合来降低扩散。

## AI 生成总结（200 字以内）

研究对象是多 Agent 间可自我复制的提示注入。方法把恶意指令嵌入 Agent 消息，使接收者执行载荷并继续传播，再以感染范围和系统危害评估扩散，并测试标签式防御。

## 与 AgentMembrane 的关系

- **重合：** 最适合支撑 external carrier → receptor → propagation 的生物感染类比。
- **边界：** 它传播的是显式恶意指令；authorized semantic infection 传播的是权限合规但可能误导的语义 artifact。
- **引用方式：** bio-inspired appendix 必引；若主文不使用病毒/复制框架，可仅在背景中简短引用。
