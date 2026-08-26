[← Back to reference index](README.md)

# MemLineage: Lineage-Guided Enforcement for LLM Agent Memory

- **Authors:** Ciyan Ouyang, Rui Hou
- **Year / status:** 2026 preprint
- **Primary source:** [arXiv:2605.14421](https://arxiv.org/abs/2605.14421)

## Abstract（中文转述）

论文将 Agent memory 安全视为 chain-of-custody 问题。MemLineage 为每条记忆附加签名 provenance 和由 LLM 介导的 derivation lineage，以 Merkle 日志记录条目，以加权 DAG 表示检索记忆对新条目的影响，并向后传播不可信路径。敏感行动 gate 拒绝由外部祖先支撑的调用，同时允许普通记忆召回；评估包含确定性 harness 和 AgentDojo bridge。

## AI 生成总结（200 字以内）

研究对象是记忆派生过程中 provenance 丢失。方法以签名日志和加权 derivation DAG 保存来源链，并在敏感行动前检查当前理由是否继承自外部不可信祖先。

## 与 AgentMembrane 的关系

- **重合：** 直接对应 P2 provenance、P3 transitive taint 和 action gating。
- **边界：** 能限制 memory-to-action authority，但不能保证外部 artifact 的解释在认识论上正确。
- **引用方式：** 与 TMA-NM 共同界定 lineage-based promotion 的能力和边界。
