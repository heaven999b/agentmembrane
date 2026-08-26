[← Back to reference index](README.md)

# AgentPoison: Red-teaming LLM Agents via Poisoning Memory or Knowledge Bases

- **Authors:** Zhaorun Chen, Zhen Xiang, Chaowei Xiao, Dawn Song, Bo Li
- **Venue:** NeurIPS 2024
- **Primary source:** [NeurIPS Proceedings](https://proceedings.neurips.cc/paper_files/paper/2024/hash/eb113910e9c3f6242541c1652e30dfd6-Abstract-Conference.html)
- **AgentMembrane priority:** Core memory-attack baseline

## Abstract（中文转述）

论文研究如何通过污染长期记忆或 RAG 知识库，为通用与检索增强 Agent 植入后门。攻击者优化触发器，使含触发模式的查询优先检索恶意示例，而普通查询保持正常。实验覆盖自动驾驶、知识问答和医疗 Agent，在极低污染比例下取得较高攻击成功率，同时对正常性能影响很小。

## AI 生成总结（200 字以内）

研究对象是长期记忆与 RAG 的后门风险。方法联合优化可检索触发器和恶意记忆样本，使特定查询稳定召回攻击内容，并以 ASR、正常任务性能和污染比例评估隐蔽性。

## 与 AgentMembrane 的关系

- **重合：** 都测量外部内容进入长期状态后对未来任务的影响。
- **边界：** AgentPoison 使用触发器和恶意记录；AgentMembrane 关注真实、合规、无显式注入的外部 artifact。
- **引用方式：** 作为 RQ3 的经典攻击基线和显式 memory poisoning 对照。
