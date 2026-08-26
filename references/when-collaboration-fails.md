[← Back to reference index](README.md)

# When Collaboration Fails: Persuasion-Driven Adversarial Influence in Multi-Agent Large Language Model Debate

- **Authors:** Insaf Kraidia, Iyas Qaddara, Alhanof Almutairi, Nada Alzaben, Samir Brahim Belhouari
- **Venue:** Scientific Reports 2026
- **Primary source:** [Nature / Scientific Reports](https://www.nature.com/articles/s41598-026-42705-7)

## Abstract（中文转述）

论文研究多 Agent 辩论中，一个对抗 Agent 能否依靠连贯、自信、误导性的自然语言论证影响群体结论。实验把攻击者嵌入多轮辩论，并测试 Best-of-N、RAG、Agent 数量和辩论轮次等因素。结果显示攻击会显著降低群体准确率并提高对错误答案的共识，而增加 Agent 或轮次和简单警告并不能稳定防御。

## AI 生成总结（200 字以内）

研究对象是多 Agent 辩论中的说服攻击。方法让攻击者针对错误目标生成多层论证、反驳与 RAG 支持内容，在多轮交互中测量准确率下降和错误共识上升。

## 与 AgentMembrane 的关系

- **重合：** 证明自然语言说服本身可成为跨 Agent 攻击向量。
- **边界：** 攻击论证可明确支持错误答案，不要求 truth-only、完整同证据或持久记忆。
- **引用方式：** 作为 RQ2 的说服机制背景，不作为严格 authorized framing 的直接等价实验。
