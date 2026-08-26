[← Back to reference index](README.md)

# Selection Integrity for LLM Graph Memory: An Accumulability Criterion for Information-Flow-Blind Retrieval

- **Authors:** Zeming Fei, Hongming Fei, Xiaoyang Wang, Yang Yang, Prosanta Gope, Biplab Sikdar, Ying Zhang
- **Year / status:** 2026 preprint
- **Primary source:** [arXiv:2606.12290](https://arxiv.org/abs/2606.12290)
- **AgentMembrane priority:** Core selection-channel baseline

## Abstract（中文转述）

论文研究图式长期记忆中的选择完整性：攻击者不必伪造事实，只需写入可影响图结构的内容，就能改变 top-k 检索到哪些已认证事实，使只检查已选记录 provenance 的 IFC 防御失效。作者提出 accumulability 条件刻画易受攻击的 selector，并设计在认证子图上重算选择的防御，以较低延迟阻止结构性重定向。

## AI 生成总结（200 字以内）

研究对象是“事实都可信，但检索选择被操纵”的图记忆漏洞。方法分析结构写入如何重新分配 top-k 成员资格，并以 accumulability 判据和认证子图重算恢复 selection integrity。

## 与 AgentMembrane 的关系

- **重合：** 与 R0 evidence selection 最接近，说明 authenticated evidence 不等于完整、公正的 evidence set。
- **边界：** 操纵的是图结构和检索，而不是冻结完整证据后的自然语言 framing。
- **引用方式：** 用于拆分 selection channel 与 interpretation/framing channel，避免把二者合并成一个 ASR。
