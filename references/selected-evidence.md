[← Back to reference index](README.md)

# Selected Evidence, Omitted Information, and Belief Updating in Large Language Model Decision Support

- **Authors:** Zebang Deng, Jubo Yan
- **Year / status:** 2026 SSRN preprint
- **Primary source:** [SSRN](https://ssrn.com/abstract=7060438)

## Abstract（中文转述）

论文测试 LLM 在看到经过条件选择的证据时，是否会推断未显示信息并做出接近贝叶斯的更新。作者改造 WYSIATI 实验，将 selected、posterior-equivalent control 和 full-information 条件用于通用数值任务及招聘、采购、尽调场景，并分析最终估计和解释。结果揭示模型容易围绕可见样本更新，而不能稳定补偿证据选择过程。

## AI 生成总结（200 字以内）

研究对象是 LLM 对“被选择出来的证据”的更新偏差。方法显式操纵可见样本、遗漏侧信息与完整信息条件，将模型估计同贝叶斯和 visible-sample 基准比较。

## 与 AgentMembrane 的关系

- **重合：** 为 evidence selection/omission 通道提供认知与测量依据。
- **边界：** 不是多 Agent 或持久记忆实验，且目前为非归档预印本。
- **引用方式：** 作为机制支持；不要用它单独承担核心 novelty。
