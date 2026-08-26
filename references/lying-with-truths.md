[← Back to reference index](README.md)

# Lying with Truths: Open-Channel Multi-Agent Collusion for Belief Manipulation via Generative Montage

- **Authors:** Jinwei Hu, Xinmiao Huang, Youcheng Sun, Yi Dong, Xiaowei Huang
- **Venue:** ACL 2026 Long Papers; Outstanding Paper
- **Primary source:** [ACL Anthology](https://aclanthology.org/2026.acl-long.270/)
- **AgentMembrane priority:** Core; strongest semantic-manipulation incumbent

## Abstract（中文转述）

论文研究多个攻击 Agent 如何只使用真实证据片段，通过公开渠道操纵受害 Agent 的信念。作者提出 Writer–Editor–Director 生成式蒙太奇框架，对事实片段进行选择、编排、叙事合成和对抗优化，并构建源自真实谣言事件的 CoPHEME。跨 14 个模型家族的实验显示，受害模型会从局部真实材料中形成并继续传播全局错误结论。

## AI 生成总结（200 字以内）

研究对象是“真实证据如何组成误导叙事”。方法用多 Agent 分工选择、排序和润色事实片段，再由 Director 对攻击效果迭代优化，并在 CoPHEME 上测量受害 Agent 及下游判断的错误采纳率。

## 与 AgentMembrane 的关系

- **重合：** 都研究不伪造事实的语义操纵。
- **边界：** 该工作允许证据子集选择和顺序优化；AgentMembrane 的严格条件冻结完整、逐字节相同的证据包。
- **引用方式：** 作为 RQ2 的最强 incumbent，并用于定义 selection、ordering、narration 三个待消融通道。
