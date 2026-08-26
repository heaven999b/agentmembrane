[← Back to reference index](README.md)

# InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated Large Language Model Agents

- **Authors:** Qiusi Zhan, Zhixiang Liang, Zifan Ying, Daniel Kang
- **Venue:** Findings of ACL 2024
- **Primary source:** [ACL Anthology](https://aclanthology.org/2024.findings-acl.624/)

## Abstract（中文转述）

论文构建工具集成 LLM Agent 的间接提示注入 benchmark。攻击指令隐藏在邮件、网页或工具返回等外部内容中，诱使 Agent 伤害用户或泄露隐私。InjecAgent 包含 1,054 个测试案例、17 类用户工具与 62 类攻击工具；作者评估 30 种 Agent 配置，并分析模型、提示方式与强化攻击对成功率的影响。

## AI 生成总结（200 字以内）

研究对象是工具型 Agent 读取外部内容时的间接提示注入。方法组合正常用户任务、外部恶意文本和可验证工具结果，自动判定任务效用、用户伤害与数据泄露。

## 与 AgentMembrane 的关系

- **重合：** 为 RQ1 提供成熟的 authority-security 测试场景和自动化指标。
- **边界：** 攻击依赖显式恶意指令，不是 policy-compliant truthful framing。
- **引用方式：** 作为 Authority Track benchmark，而非 RQ2 的主语义 benchmark。
