[← Back to reference index](README.md)

# Securing AI Agents with Information-Flow Control

- **Authors:** Manuel Costa, Boris Köpf, Aashish Kolluri, Andrew Paverd, Mark Russinovich, Ahmed Salem, Shruti Tople, Lukas Wutschitz, Santiago Zanella-Béguelin
- **Year / status:** 2025 preprint
- **Primary source:** [arXiv:2505.23643](https://arxiv.org/abs/2505.23643)
- **System:** FIDES

## Abstract（中文转述）

论文为 Agent planner 建立信息流控制形式模型，分析动态 taint tracking 能执行哪些安全性质，并用任务分类刻画不同 planner 的安全—效用权衡。基于该分析，FIDES 为数据维护机密性与完整性标签，确定性执行安全策略，并提供选择性隐藏信息的原语；作者在 AgentDojo 上验证其能够在提供安全保证时完成多类任务。

## AI 生成总结（200 字以内）

研究对象是 Agent planner 的可执行安全保证。方法以 IFC 标签追踪机密性和完整性，形式化可强制执行的性质，并通过确定性策略门控工具调用和信息可见性。

## 与 AgentMembrane 的关系

- **重合：** 是 RQ1 的 IFC 与 taint baseline，也提供 expressiveness–security 的系统视角。
- **边界：** 主要约束运行时信息流，不测完整真实证据经不同 receptor 产生的语义偏置。
- **引用方式：** 与 CaMeL 合并讨论结构化 authority defenses。
