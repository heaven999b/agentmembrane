[← Back to reference index](README.md)

# Defeating Prompt Injections by Design (CaMeL)

- **Authors:** Edoardo Debenedetti, Ilia Shumailov, Tianqi Fan, Jamie Hayes, Nicholas Carlini, Daniel Fabian, Christoph Kern, Chongyang Shi, Andreas Terzis, Florian Tramèr
- **Year / status:** 2025 preprint
- **Primary source:** [arXiv:2503.18813](https://arxiv.org/abs/2503.18813)
- **AgentMembrane priority:** Core authority baseline

## Abstract（中文转述）

论文把提示注入视为系统设计问题，而不是依赖模型识别恶意文本。CaMeL 从可信用户请求中显式提取控制流与数据流，让处理不可信数据的模型无法改变程序控制，并使用 capability 限制未经授权的数据流和工具能力。作者在 AgentDojo 上评估任务效用与可证明安全性，展示结构化隔离能在底层模型仍可能受注入影响时保护执行层。

## AI 生成总结（200 字以内）

研究对象是工具型 Agent 的提示注入。方法把可信控制逻辑和不可信数据处理分开，并在工具调用前执行 capability 检查，从系统层阻止不可信文本改写执行流程。

## 与 AgentMembrane 的关系

- **重合：** 对应 RQ1 的 control/data separation 与 authority isolation。
- **边界：** 保证重点是工具和数据流，不判断合法文本是否导致错误语义判断。
- **引用方式：** 作为 Authority Ladder 的主防御基线，并支撑“authority-safe 不自动等于 semantic-safe”的待检验命题。
