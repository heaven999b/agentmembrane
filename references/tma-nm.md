[← Back to reference index](README.md)

# Securing LLM-Agent Long-Term Memory Against Poisoning: Non-Malleable, Origin-Bound Authority with Machine-Checked Guarantees

- **Author:** Yedidel Louck
- **Year / status:** 2026 preprint
- **Primary source:** [arXiv:2606.24322](https://arxiv.org/abs/2606.24322)
- **AgentMembrane priority:** Core authority/promotion baseline

## Abstract（中文转述）

论文研究跨会话记忆投毒如何经过 Agent 自我总结、可信工具回显和伪造佐证来清洗不可信来源。作者形式化记忆写入—检索—行动流程中的可塑性，提出 TMA-NM：在写入时绑定不可篡改的来源权限，并要求抗 Sybil 的独立佐证才能提升权限。TLA+ 机器检查与八个模型上的评估支持其对后果性行动的安全保证。

## AI 生成总结（200 字以内）

研究对象是持久记忆来源被“洗白”后触发敏感行动。方法用形式化分离定理证明内容和普通 lineage 防御不足，再以写入时 origin binding、不可降级标签和独立佐证门控阻断权限提升。

## 与 AgentMembrane 的关系

- **重合：** 直接覆盖 provenance、laundering、promotion 与 consequential action。
- **边界：** 论文明确将非后果性的 free-text answer bias 排除在保证之外，这正是 AgentMembrane RQ4 的剩余空间。
- **引用方式：** RQ1/RQ3 的最强近邻；不可声称 provenance laundering 或 origin binding 本身是 AgentMembrane 首创。
