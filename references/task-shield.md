[← Back to reference index](README.md)

# The Task Shield: Enforcing Task Alignment to Defend Against Indirect Prompt Injection in LLM Agents

- **Authors:** Feiran Jia, Tong Wu, Xin Qin, Anna Squicciarini
- **Venue:** ACL 2025 Long Papers
- **Primary source:** [ACL Anthology](https://aclanthology.org/2025.acl-long.1435/)

## Abstract（中文转述）

论文把间接提示注入防御重新表述为任务对齐：Agent 的每条指令和工具调用都必须服务于用户指定目标。Task Shield 在测试时检查动作与任务的贡献关系，不依赖单纯检测恶意字符串。作者在 AgentDojo 上同时评估攻击成功率和任务效用，展示该方法能显著降低攻击，同时保留较高的正常任务完成能力。

## AI 生成总结（200 字以内）

研究对象是间接提示注入下的工具行动偏离。方法在每一步验证指令或工具调用是否促进用户目标，以任务依赖关系门控执行，并联合报告安全与效用。

## 与 AgentMembrane 的关系

- **重合：** 提供 action-level safety–utility baseline，可对应 RQ1 和 security–utility frontier。
- **边界：** 任务对齐不一定发现合法 artifact 对判断或记忆内容的渐进偏置。
- **引用方式：** 在比较 capability、IFC、task alignment 三类 action defense 时引用。
