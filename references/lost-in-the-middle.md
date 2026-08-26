[← Back to reference index](README.md)

# Lost in the Middle: How Language Models Use Long Contexts

- **Authors:** Nelson F. Liu, Kevin Lin, John Hewitt, Ashwin Paranjape, Michele Bevilacqua, Fabio Petroni, Percy Liang
- **Venue:** TACL 2024
- **Primary source:** [ACL Anthology](https://aclanthology.org/2024.tacl-1.9/)

## Abstract（中文转述）

论文系统研究长上下文模型是否能稳定利用输入中的相关信息。作者在多文档问答和键值检索任务中改变相关信息的位置，发现模型通常在信息位于开头或结尾时表现较好，而位于上下文中部时明显下降；这一现象在具备长上下文能力的模型上仍然存在，并形成了位置鲁棒性的诊断协议。

## AI 生成总结（200 字以内）

研究对象是长上下文中的位置偏差。方法保持任务与证据内容不变，仅移动关键信息位置，在问答和检索任务上比较准确率，从而隔离模型利用上下文的位置效应。

## 与 AgentMembrane 的关系

- **重合：** 说明 ordering/position 能改变相同证据的实际利用程度。
- **边界：** 不是对抗性 framing，也不涉及 Agent authority 或 memory promotion。
- **引用方式：** 用作排序通道和 complete-evidence 条件仍需位置平衡的依据。
