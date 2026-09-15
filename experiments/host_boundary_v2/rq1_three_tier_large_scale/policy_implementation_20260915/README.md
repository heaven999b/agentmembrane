# 三档逐题权限接线：33 道原题工程状态

> **证据级别：工程候选。** 本目录记录逐题权限 policy、source-native 测试和
> `admission_status.json`。它不包含模型行为样本，正式研究样本数为 0。

本轮处理此前缺少中档 policy 的 33 道 AgentDojo 原题：Banking 11 道、Slack
13 道、Workspace 9 道。当前冻结状态为：33/33 源绑定通过，33/33 可以编译
low/medium/high 权限接口，0/33 已取得本目录口径下的完整 strict-checker 与
formal-pair 准入。五道原题因请求歧义或不可安全记录的效果保持只读或部分执行；
代码不会为了提高可执行率而扩大中档权限。

三档在 backend 前执行以下真实边界：

| 档位 | E 的业务权限 | 强制规则 |
| --- | --- | --- |
| Low (`A0`) | 无 AgentDojo 业务工具 | E 只能给 H 发送协议内文本，不能直接读取或修改业务状态 |
| Medium (`A3`) | 每题目的绑定工具子集 | 原题与初态绑定对象、参数、调用顺序、次数和返回字段；歧义、漂移、越界或重复提交失败关闭 |
| High (`A4`) | 同 suite 的较宽实验工具面 | 保留 sandbox 与证据约束，但允许原生攻击目标具有技术可达路径 |

中档不是工具名 allowlist。读结果先投影为完成原题所需字段，写操作要求精确目标
与参数，并在提交后核对终态；攻击内容、其他收件人、其他文件／频道、重复写入和
运行中 source identity 变化都会被拒绝。High 仍是实验性 ambient 权限，不能
表述为生产系统里的无限权限。

本目录的 22 个测试方法覆盖 11 道 Banking、13 道 Slack 和 5 道本轮新增／修复
的 Workspace workflow；其余四道 Workspace policy 在
`tests/rq1_collab_v1/` 的独立 native 测试中覆盖。本轮已在锁定 AgentDojo 源上
实际运行本目录测试，结果为 **22/22 通过**，包括合法提交、恶意／非目标参数
拒绝、重复提交拒绝、源漂移拒绝、结果投影和三档工具集合关系。

干净 checkout 可按以下方式复现测试：

```sh
./tools/bootstrap_research_workspace.sh
.venv/bin/python -m unittest discover \
  -s experiments/host_boundary_v2/rq1_three_tier_large_scale/policy_implementation_20260915 \
  -p 'test_*.py' -v
```

公开的 `admission_status.json` 是脱敏工程快照。若要从头重建它，还需把私有、
内容寻址的原始 repair drafts 路径传给 `RQ1_POLICY_DRAFTS`；AgentDojo checkout
可通过 `AGENTDOJO_SOURCE_ROOT` 覆盖。缺少这些输入时 builder 会失败关闭，不会
伪造一个“已准入”状态。

这 33 道 policy-ready 只说明三档权限执行面已经接线。正式运行仍需最终 46 题的
Q/I/D 与 evaluator qualification、final H/goal/statistical contracts、真实每格
proxy 生命周期证明和激活 manifest；这些 gate 未关闭前，任何测试通过数都不算
RQ1 支持证据。
