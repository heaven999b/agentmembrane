[← Back to reference index](README.md)

# Ghost in the Agent: Redefining Information Flow Tracking for LLM Agents

- **Authors:** Yuandao Cai, Wensheng Tang, Cheng Wen, Shengchao Qin
- **Year / status:** 2026 preprint
- **Primary source:** [arXiv:2604.23374](https://arxiv.org/abs/2604.23374)
- **System:** NeuroTaint; benchmark: TaintBench
- **AgentMembrane priority:** Core semantic-taint baseline

## Abstract（中文转述）

论文指出传统程序 taint analysis 难以追踪 LLM 中由自然语言推理产生的信息流。NeuroTaint 离线审计执行轨迹，联合语义匹配、反事实因果分析和持久上下文图，追踪显式内容传播、隐式决策影响及跨会话记忆复用。作者在覆盖 20 个开源 Agent 框架、400 个场景的 TaintBench 上与 FIDES 等方法比较。

## AI 生成总结（200 字以内）

研究对象是非逐字复制的 Agent 信息流。方法建立跨工具和跨会话的动态 provenance 图，再用语义证据与反事实分析判断不可信来源是否真正影响后续 sink。

## 与 AgentMembrane 的关系

- **重合：** 覆盖 semantic transformation、causal influence 和 cross-session persistence。
- **边界：** NeuroTaint 评估检测准确率；AgentMembrane 识别接口表达力与 promotion 策略对攻击效果和效用的因果边界。
- **引用方式：** RQ3/RQ4 的检测 baseline，并用于设计跨 session taint 与 causal-attribution 指标。
