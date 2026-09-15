# AgentMembrane 本地代码与 GitHub 统一迁移审计（2026-09-16）

## 结论

本轮本地到 canonical public checkout 的受控迁移已经完成：Week 1–9、当前
Python package、测试、发布工具及本周三档研究的公开复现材料已经进入同一棵
待发布工作树；不适合公开的账号路由、attestation、raw run、旧 campaign 恢复
入口、大型数据与本地 runtime 均有明确排除规则。机器可读清单见
[LOCAL_TO_GITHUB_MIGRATION_MANIFEST_20260916.json](./LOCAL_TO_GITHUB_MIGRATION_MANIFEST_20260916.json)。

这份完成状态指“公开 allowlist 迁移、差异复核和本地验证完成”。仓库负责人仍需
把当前 reviewed worktree 作为一个提交 push，并从远端复读 commit；该远端动作
不能由包含自身哈希的 manifest 预先证明。

## 唯一权威与目录职责

| 角色 | 权威内容 | 明确不存放的内容 |
| --- | --- | --- |
| GitHub `heaven999b/agentmembrane` | 已审查代码、测试、协议、公开聚合结果、Week 1 起周报 | 凭据、route attestation、原始模型记录、大型数据与运行环境 |
| canonical public checkout | GitHub 唯一可写本地工作副本；公开改动从这里提交 | 第二套独立研究实现 |
| active private workspace | 数据、缓存、runtime、raw run、账号路由与逐 episode 证据 | 公开代码的长期 source of truth |
| 旧 checkout／临时 clone／staging | 只作可删除或冻结的迁移保全 | 新开发和新周报 |

现有 active tree 约 15 GiB，不能整体变成 Git 仓库。完成 push 与进程检查后，
可把它冻结成带日期的 private archive，并让 canonical checkout 使用日常项目名。

## 周报统一状态

Week 1–5 已以 pre-AgentMembrane lineage 导入，Week 6 和 Week 8 的本地稿也已
纳入；Week 7、Week 9 原本就在 AgentMembrane。现在 Week 1–9 均在
`weekly_reports/weekN/`，来源关系写入 [LINEAGE.md](../weekly_reports/LINEAGE.md)。
以后只按 [PROCESS.md](../weekly_reports/PROCESS.md) 在最终目录写报告，用仓库相对
链接和脱敏聚合证据，并让报告、该周 README 与总索引处于同一提交。

`reports/` 的稳定入口也已闭环：总索引、RQ1 当前结果与 RQ2 完整报告共
3 个文件、21242 bytes；总索引把
canonical RQ1、三档子研究、RQ2 与最新 weekly stage report 分开，避免把诊断结果
误写成 formal result。

## 原有目录的收口结果

- active private workspace 保留为带日期的私有归档，只承载 raw data、runtime、
  route／attestation 与逐 episode evidence；公开源码已由单向同步门核验。
- 当前 canonical public checkout 是唯一公开提交入口。
- 审计开始时的 clean `origin/main` 临时副本只用于基线对比，远端复核后可清理。
- `RQ1B_WEEKLY_REPORT_STAGING` 的 Week 8 已导入并进入总索引，staging 不再有
  发布权威性。
- predecessor memory research repo 的 Week 1–5 已作为 pre-AgentMembrane lineage
  导入，Week 6 已作为 transition 导入；其代码历史继续作为独立前身项目保存。

## package、tests、tools 最终同步核验

计数和 SHA-256 均在两个工作区重新读取后生成；tree digest 是“相对子路径到
文件 SHA-256”的排序 JSON 再做 SHA-256，排除 cache、隐藏文件和 symlink。

| 子树 | active 文件 | canonical 文件 | 内容相同 | 内容不同 | canonical 缺失 | canonical 独有 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `agentmembrane/` | 395 | 395 | 395 | 0 | 0 | 0 |
| `tests/` | 294 | 294 | 293 | 0 | 1 | 1 |
| `tools/` | 17 | 21 | 17 | 0 | 0 | 4 |

差异已经闭环分类：

- canonical 与 private 的 publishable 同路径内容差异：无。此前本机路由／默认值已同步为两边一致的公开安全版本。
- canonical 专用工具：`tests/test_audit_public_repo.py`、`tools/audit_public_repo.py`、`tools/audit_workspace_source_sync.py`、`tools/bootstrap_research_workspace.sh`、`tools/monitor_v3.py`。
- private 明确排除：`tests/test_rq1_large_campaign_runner.py`。它依赖已归档 campaign 或 private evidence，不属于公开 runtime。

formal runtime/QID 相关 11 个关键 package/test 文件已逐个复核：11
个与 active 原件字节相同；0 个是经过测试的
公开化差异；缺失 0 个。状态为 `completed`，没有待同步项。
`tools/audit_workspace_source_sync.py` 还从 private 方向检查了
705 个 publishable 文件，
公开匹配 705 个，结果通过；唯一不进入
比较集的 private 文件已在 manifest 中给出逐路径理由。

## `rq2-live-monitor` 的明确边界

private workspace 的 `rq2-live-monitor/` 有唯一第一方源码：本地只读 status API、
RQ2 dashboard 与 UI 组件。排除 `.openai/`、`.vinext/`、`.wrangler/`、`dist/`、
`node_modules/`、`__pycache__/`、build/state/outputs/work 后为 77 个文件、
633,193 bytes。它固定读取历史 RQ2 confirmation controller 的本地输出，且
canonical package、tests、tools 和三档 runtime 都不导入它。

它已归类为 `local_auxiliary_app_excluded`，保留在本地冻结归档且不阻塞 core
统一。若恢复维护，应作为独立应用迁移并先参数化 API URL 与 run schema；不得
复制依赖目录、构建产物、本地 state 或 hosting state。

## 本轮公开纳入的三档材料

本轮三档 allowlist 共 48 个文件、856954 bytes：

- `PROTOCOL_RQ1.md` 与五个顶层离线 audit／准备脚本；
- `formal_candidate_20260915/` 的协议、builder、测试和零样本候选 metadata；
- 参数化 `build_formal_gate.py` 及其 4 个离线测试：route、attestation、runtime、
  canary、CLI binary、候选输入和三个 create-only 输出都必须显式传入，没有
  账号、endpoint 或本机路径默认值；
- `policy_implementation_20260915/` 的 README、状态 builder、5 个离线测试及
  `admission_status.json`，证据级别明确为工程候选；
- `qid_formal_adjudication_20260915/` 的公开说明与 outcome-blind builder；
- `qid_contract_drafts_other_001/` 的 11 个 frozen benchmark contract、builder、
  coverage／compile／sealed development replay 聚合材料；无 per-cell raw、route
  或 credential，并明确不是 formal evidence；
- `task_repair_ledger_003/` 的 3 个聚合账本文件，共 51,760 bytes、86 个唯一题号；
  它不含题目文本、模型 I/O、账号、endpoint、凭据或 route attestation。

其中 47 个文件与 private workspace 原件逐字节相同，
0 个是受控公开化差异，
1 个是 canonical 新增的公开说明或测试。
所有候选仍保持 `formal_activation=false`、`research_sample_count=0`，不能冒充已跑的
正式三档实验。

## 明确排除的三档与仓库内容

- `campaign_continuation.py` 和账号专用 run/smoke 脚本：能恢复旧 campaign 或绑定
  私有账号；旧 campaign 必须永久暂停且不得与新设计并池。
- switched-account proxy、route、attestation、local canary 和 stage repair：含
  私有运行绑定。
- `H-output-contract-current-assignment.json` 与 `route-runtime-binding.json`：含本机
  source path、localhost endpoint 或 CLI 绑定。
- live/prepared/candidate/readiness runs、inventories、private evaluation、per-cell
  evidence 与可续跑状态：属于 raw 或本地 runtime evidence。
- `missing_policy_drafts_001/` 和 QID `adjudication-draft.json`：逐题非最终草稿；
  公开的是完成复现闭环所需的聚合 ledger、冻结合同和 builder。
- runtime environments、source caches、嵌套 Git 仓库、下载的 benchmark、数据库、
  parquet、archives、wheels 与 native libraries。

原先 unsafe 的 formal gate wrapper 不再属于排除项；canonical 版本已经参数化并
fail closed，且同一安全版本已同步回 private workspace。账号 route、attestation
和本机 CLI 绑定仍只作为显式 private 输入，不随 wrapper 公开。

## 安全与可复现性自检

- push 前的完整候选扫描覆盖 884 个文件、15176486 bytes：
  862 个 tracked 文件，加上由
  10 个 `git status` 目录级条目
  展开得到的 22 个实际
  non-ignored 文件；
  个人绝对 home path、账号 label、Bearer token、GitHub token、OpenAI 风格 key、
  private key 六类模式均为 0 命中；
- GitHub OAuth 缺少 `workflow` scope，因此最终提交仅省略一个可选的
  `.github/workflows/public-repository-audit.yml` 自动化入口；仓库内审计脚本与
  测试完整保留。省略后最终 883 个 tracked 文件再次通过
  `tools/audit_public_repo.py`，Week 1–9 结构、全仓 Markdown 相对链接、10 MiB
  上限和敏感内容扫描均通过；
- allowlist 中 24 个 Python
  文件通过 AST parse，16 个 JSON
  文件全部解析；
- formal gate CLI 4/4、goal-balance 6/6、preregistration 11/11、formal analysis
  10/10、wire／protocol／sealed runtime／permission evidence 组合回归 35/35、
  锁定 AgentDojo 源 QID 20/20、policy 22/22、route/config 37/37、permission 6/6
  均通过；
- 35 项组合回归从 private workspace 读取公开仓库明确排除的锁定 fixture 与 Python
  runtime；执行前 publishable source 已完成 705/705 字节匹配，并显式绑定纯合成
  loopback shared-proxy policy，没有 credential value、网络或模型调用；
- public repository audit 自身的 3 个 fail-closed 测试通过；
- preregistration builder 与落盘候选一致：46 题、276 cells、0 正式研究样本；
- `git diff --check` 通过。

policy 22 项测试使用 canonical 代码和 private 锁定 AgentDojo source 实际执行，
没有模型或 API 调用；它与上述离线测试都属于 engineering validation，不产生
formal research sample。

## 交付入口与完成判定

日常入口是 canonical checkout；公开安全门是 `python3 tools/audit_public_repo.py`；
private-to-public 源码差异门是 `python3 tools/audit_workspace_source_sync.py
--private-workspace <PRIVATE_WORKSPACE>`；三档 formal gate 用 README 中的显式参数
入口。旧 publish checkout、临时 clone 和 staging 不再作为发布源。

本地迁移审计状态为 **completed**：所有当前第一方内容已纳入、受控公开化或明确
排除，没有 unresolved/pending 分类。仓库 owner 在同一 reviewed worktree 完成
stage、commit、push 并验证 `local commit == origin/main == GitHub main` 后，远端统一
即闭环。
