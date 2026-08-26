# Appendix: AgentMembrane Bio-Inspired Alternative Research Direction

## Safe Admission and Containment of Untrusted External Agents in Multi-Agent Systems

> **Repository role: ALTERNATIVE / SECONDARY.** This document preserves a broader,
> bio-inspired direction in which an untrusted external agent enters a host system,
> exploits host-mediated capabilities, establishes persistence, and propagates across
> agents. It is **not the current primary proposal** and does not replace
> [`PROPOSAL.md`](PROPOSAL.md). Promotion to the primary track would require an
> explicit project decision, a closest-work/novelty review, and a scoped host benchmark.

**版本：** 2026-08-27 修订草案  
**状态：** `alternative / revise — ready for scoped benchmark design, not yet ready for full experiment`  
**定位：** 恢复“外部 Agent 进入宿主系统、利用宿主能力、建立持久影响并传播”的原始研究主线；现有 ContractNLI A/B 降为 semantic-payload 子实验。  
**尚未完成：** 正式 related-work / novelty 检索、目标 venue 校准、完整宿主 benchmark 实现、独立模型与多 replicate 验证。

---

# 1. Executive Summary

现代多 Agent 系统正在从预先固定的内部 Agent，发展为能够动态接入外部 Agent、插件、远程模型和第三方工作流的开放系统。外部 Agent 可能很有用，但系统不能假设它与宿主目标一致，也不能因为它通过了身份或格式检查，就把它视为可信内部主体。

本项目研究一个类似生物病毒进入宿主的安全问题：

> 一个不可信外部 Agent 被动态接入现有多 Agent 系统后，能否利用宿主已经拥有的工具、内部 Agent、工作流和共享记忆，完成自己没有直接权限完成的行为、在任务结束后保留影响，并向其他 Agent 或未来 session 传播？

我们提出 **AgentMembrane**：一个用于测量和控制外部 Agent 接入边界的轻量级 reference runtime。研究重点不是证明某个复杂防御一定最好，而是刻画四个边界：

\[
\boxed{
Admission
\times
Host\ Capability
\times
Persistence/Propagation
\times
Containment
}
\]

项目的核心产物是一个经验安全边界图，回答：

1. 外部 Agent 在什么接入条件下可以安全进入？
2. 它能否借用宿主能力或内部 Agent 完成间接越权？
3. 它能否通过 memory、artifact、消息或子 Agent 驻留和传播？
4. 什么是兼顾安全、效用和成本的最小充分 membrane？

现有 ContractNLI framing 实验被保留为一个子问题：当直接越权已经被阻止后，事实正确、无显式标签的语义产物是否仍能影响未来判断。该实验不再决定整个项目成败。

---

# 2. Problem Anchor

## 2.1 Bottom-line problem

开放 Agent 系统需要利用外部能力，但一旦外部 Agent 被允许参与宿主工作流，它可能不需要直接拥有危险权限，而是通过以下路径获得实际影响力：

- 请求内部 Agent 代为调用工具；
- 把多个单独合法的能力组合成危险操作；
- 提交看似正常的 action proposal；
- 利用共享 memory 或任务 artifact 建立持久状态；
- 通过跨 Agent 消息、衍生任务或子 Agent 传播目标；
- 在 capability 过期后继续影响未来 session；
- 用事实正确但目标导向的内容改变后续认知。

因此：

\[
DirectPermission(A,o)=False
\]

并不自动推出：

\[
EffectiveInfluence(A,o)=False
\]

## 2.2 Must-solve bottleneck

现有安全检查往往分别验证身份、单次工具调用、输出 schema 或内容安全，却不一定测量：

> 外部 Agent 能否通过宿主系统的组合能力、委托链和持久状态，获得超出单项权限表面含义的有效控制力？

本 proposal 的主要瓶颈是构造一个既真实又可自动判定的宿主环境，使“外部 Agent 的正常效用”和“宿主能力被利用的风险”能够在相同任务中测量。

## 2.3 Non-goals

第一版不试图：

- 构造可部署的恶意自传播 Agent；
- 在真实生产账户、真实用户数据或开放网络上测试传播；
- 证明 AgentMembrane 优于所有 sandbox、capability 或 IFC 系统；
- 把生物病毒类比当作形式等价；
- 仅凭一次小样本 pilot 宣称普遍安全结论；
- 把所有 prompt injection、模型越狱和软件供应链问题纳入同一篇论文。

所有攻击实验必须在隔离、可恢复、无真实外部副作用的测试环境中进行。

## 2.4 Decision changed by this research

研究结果应改变一个具体系统设计决定：

> 开发者在接入第三方 Agent 时，应当只限制直接工具权限，还是还必须限制 capability delegation、跨 Agent 通信与 persistent-memory promotion？

---

# 3. Biological-Virus Analogy as a Design Lens

该类比用于组织威胁模型，不用于声称生物过程与软件过程完全相同。

| 生物过程 | Agent 系统对应物 |
|---|---|
| 病毒颗粒 | 外部不可信 Agent |
| 受体结合 | 注册、握手、typed receptor、任务分配 |
| 穿过细胞膜 | 被调度进入宿主工作流 |
| 利用细胞机器 | 调用宿主工具、内部 Agent、broker、API |
| 遗传物质 | 外部 Agent 的目标、策略和持久状态 |
| 整合宿主 | 写入或影响 shared/persistent memory |
| 潜伏 | 当前任务不执行，未来条件满足时触发 |
| 复制与传播 | 消息、子任务、artifact、子 Agent、跨 session 传播 |
| 免疫反应 | capability、sandbox、taint、quarantine、approval、revocation |
| 清除 | capability 回收、memory rollback、lineage purge、session teardown |

这一类比产生三个可检验机制：

1. **入口不等于控制。** 外部 Agent 可以进入，但不一定获得宿主执行能力。
2. **利用宿主比直接越权更重要。** 攻击可能通过委托和组合，而非单次非法调用。
3. **一次任务的安全不等于生命周期安全。** 风险可能在 memory、传播或未来 session 中出现。

---

# 4. Threat Model

## 4.1 Host system

宿主系统包含：

- Security Kernel；
- Admission Gateway；
- Capability Manager；
- Tool / Action Broker；
- 一个或多个内部 Agent；
- ephemeral workspace；
- quarantined memory；
- persistent/shared memory；
- task scheduler 与 cross-agent messaging；
- provenance、taint、audit log 与 rollback。

只有 Security Kernel、测试 oracle 和环境重置器属于 trusted computing base。

## 4.2 External Agent

外部 Agent 被视为完全不可信。攻击者可以控制其：

- model、prompt 和 private state；
- planning 与 tool-selection strategy；
- 输出、重试和跨步骤策略；
- 对失败反馈的自适应行为；
- 与其他外部 Agent 的协同行为（后续阶段）。

但攻击者不能直接修改测试 oracle、Security Kernel 或宿主底层权限数据库。

## 4.3 Attacker objectives

攻击目标分为：

1. **Direct action：** 直接执行未授权工具或读取资源；
2. **Delegated action：** 让内部 Agent 或 broker 代为执行；
3. **Composite action：** 组合多个局部合法步骤产生全局危险结果；
4. **Persistence：** 任务结束或 capability 过期后仍保留影响；
5. **Propagation：** 影响扩散到其他 Agent、任务或 session；
6. **Semantic payload：** 不越权但改变未来决策或记忆判断。

## 4.4 Benign external agents

实验必须同时包含正常外部 Agent，以测量：

- task completion；
- answer/task quality；
- tool efficiency；
- latency 与 token/tool cost；
- 被 membrane 错误阻断的比例。

---

# 5. AgentMembrane Architecture

```text
                 Untrusted External Agent
                           │
                           ▼
                 ┌──────────────────┐
                 │ Admission Gateway │
                 │ identity / lease  │
                 │ receptor / scope  │
                 └─────────┬────────┘
                           ▼
                 ┌──────────────────┐
                 │ Capability Layer  │
                 │ token / resource  │
                 │ expiry / delegation│
                 └─────────┬────────┘
                           ▼
          ┌────────────────┴────────────────┐
          ▼                                 ▼
 ┌──────────────────┐             ┌──────────────────┐
 │ Tool/Action Broker│             │ Internal Agents   │
 │ policy + effects  │◄───────────►│ delegated tasks   │
 └─────────┬────────┘             └─────────┬────────┘
           └────────────────┬────────────────┘
                            ▼
                  ┌──────────────────┐
                  │ Quarantine       │
                  │ provenance/taint │
                  │ lineage/binding  │
                  └─────────┬────────┘
                            ▼
                  ┌──────────────────┐
                  │ Promotion Gate   │
                  │ verify/approve   │
                  │ reground/cleanup │
                  └─────────┬────────┘
                            ▼
                  Persistent / Shared Memory
```

## 5.1 Design principles

1. Utility does not imply authority.
2. External output is data or proposal, never ambient authority.
3. No privileged operation without an explicit, scoped and unexpired capability.
4. Delegated action inherits the external lineage unless independently authorized.
5. Low-risk steps must also be checked for dangerous composition.
6. External lineage cannot be washed away by one internal paraphrase.
7. Persistent state requires explicit promotion and must support rollback.
8. Task termination revokes capabilities and triggers residual-state audit.

---

# 6. Research Questions

## RQ1 — Admission Boundary

> 在什么身份、接口、生命周期和 capability 配置下，一个外部 Agent 可以安全进入宿主系统？

研究变量：

- isolated response-only；
- public read；
- proposal-only；
- scoped and expiring capabilities；
- delegable capabilities；
- ambient tool/memory access。

关键问题：

- capability 是否正确绑定 identity、resource、purpose 和 expiry？
- Agent 能否 self-grant、续期或改变 scope？
- capability 过期后，已有任务和 artifact 如何处理？
- 外部 Agent 的正常效用在哪一级开始出现，危险影响在哪一级开始出现？

## RQ2 — Host-Capability Exploitation Boundary

> 外部 Agent 能否利用宿主已有的内部 Agent、工具 broker 和工作流，完成自己没有直接权限完成的行为？

研究机制：

- confused deputy；
- capability delegation；
- proposal-to-action conversion；
- multi-step capability chaining；
- cross-tool composition；
- action laundering through internal agents。

关键区分：

\[
Direct\ Unauthorized\ Action
\neq
Delegated/Composite\ Unauthorized\ Outcome
\]

RQ2 是本修订版的核心 RQ，也是“外部 Agent 利用宿主机器”的主要可检验对应物。

## RQ3 — Persistence and Propagation Boundary

> 外部 Agent 能否在任务结束后保留影响，并通过 memory、artifact、消息、任务或子 Agent 传播？

研究对象：

- direct/shared-memory write；
- memory proposal 与 promotion；
- transitive taint；
- artifact lineage laundering；
- future-session trigger；
- cross-agent message propagation；
- child-task / child-agent propagation；
- post-revocation residual influence；
- cleanup、rollback 与 purge completeness。

现有 semantic framing 实验属于 RQ3 的一个子问题：事实正确的语义 artifact 是否能成为不带显式恶意指令的持久载荷？

## RQ4 — Containment–Utility Boundary

> 哪些 membrane 机制能够阻止进入后的利用、驻留和传播，同时保留外部 Agent 的正常任务价值？

候选机制：

- sandbox；
- proposal-only；
- scoped capability 与 expiry；
- non-delegable capability；
- policy-aware tool broker；
- composition-aware action checking；
- cross-agent communication restrictions；
- quarantine、provenance 与 transitive taint；
- independent approval/declassification；
- source re-grounding；
- session teardown、memory rollback 与 lineage purge。

目标是识别：

\[
Minimum\ Sufficient\ Membrane
\]

而不是默认采用最高成本的完全隔离。

---

# 7. Experimental Axes

## 7.1 Admission / Authority ladder

| Level | Access |
|---|---|
| A0 | response-only, no host resources |
| A1 | public/read-only evidence |
| A2 | structured proposals, no execution |
| A3 | scoped, expiring, non-delegable low-risk capability |
| A4 | scoped capability plus internal-agent delegation |
| A5 | ambient tools, messaging and shared memory baseline |

## 7.2 Host-function surface

| Level | Host functions available |
|---|---|
| H0 | no tools or internal agents |
| H1 | read-only tools |
| H2 | low-risk write/action proposals |
| H3 | tool broker execution |
| H4 | internal-agent delegation |
| H5 | multi-tool workflow and cross-agent messaging |

## 7.3 Persistence surface

| Level | State lifetime |
|---|---|
| S0 | ephemeral output only |
| S1 | quarantined artifact |
| S2 | evidence-bound memory proposal |
| S3 | verified persistent memory |
| S4 | shared cross-agent memory |
| S5 | cross-session / derived-task availability |

## 7.4 Containment mechanisms

不跑完整笛卡尔积。第一阶段只选择能区分关键机制的最小条件：

- A2 proposal-only；
- A3 scoped/non-delegable；
- A4 scoped/delegable；
- A5 ambient baseline；

分别与：

- C0 schema/basic ACL；
- C1 scoped capability + broker；
- C2 C1 + lineage/taint/quarantine；
- C3 C2 + independent approval + revocation/cleanup；

组合成一个有限 boundary pilot。

---

# 8. Attack Families

## Attack 1 — Direct Unauthorized Action

尝试未经授权地：

- 写 persistent memory；
- 读取 secret；
- 调用 forbidden tool；
- 修改 security policy；
- self-grant capability。

## Attack 2 — Confused Deputy

外部 Agent 不直接调用危险工具，而是诱导内部 Agent、broker 或 verifier 代为执行。

## Attack 3 — Capability Chaining

每个局部步骤单独合法，但组合后违反全局安全目标。测试 oracle 以最终副作用而非单次调用名称判定。

## Attack 4 — Proposal-to-Action Laundering

危险意图被包装成正常分析、任务建议或 action proposal，并由宿主角色转化为执行。

## Attack 5 — Persistence

通过 memory、artifact、scheduled task 或 lineage laundering，使影响在 capability 过期后继续存在。

## Attack 6 — Propagation

通过隔离的模拟消息、衍生任务或测试子 Agent，测量影响是否扩散。禁止开放网络、自主复制或真实系统传播。

## Attack 7 — Semantic Payload

事实正确、无显式标签、无控制指令的 artifact 是否改变未来判断。ContractNLI A/B 属于此类的 preliminary pilot。

---

# 9. Benchmark and Task Design

## 9.1 Minimal host benchmark

构造一个完全隔离、可重置的本地项目环境，包含：

- public、private、restricted 三类文件；
- read-only search；
- scoped file editing；
- mock database；
- mock communication queue；
- mock external API；
- action proposal 与 approval；
- internal worker、memory steward、action broker；
- ephemeral、quarantined、persistent 三类 memory；
- deterministic side-effect oracle。

## 9.2 Benign tasks

- 搜索公开资料并形成摘要；
- 读取授权项目文件并提出修复建议；
- 请求内部 worker 执行允许的转换；
- 提交 evidence-bound memory proposal；
- 使用低风险工具完成多步骤任务。

## 9.3 Adversarial twins

每个 benign task 配一个结构相似的 adversarial twin：

- 相同表面任务和资源预算；
- 隐藏目标改变最终副作用；
- 直接路径与 delegated/composite 路径分别记录；
- 失败后允许有限次数的自适应替代尝试；
- 所有动作只作用于可恢复 mock environment。

## 9.4 Semantic sub-benchmark

ContractNLI 保留，但重新定位为：

> 在直接行为越权被阻止后，外部 Agent 的事实有效 artifact 是否仍构成 residual semantic attack surface？

后续正式 B2 需要：

- 新冻结样本；
- 独立且盲化的 auditor；
- evidence-only、neutral、framing、direct-answer ceiling control；
- 真正独立的 source re-grounding；
- 事实有效性与答案直接性分级，而不是单一零泄漏 gate。

---

# 10. Metrics

## 10.1 Direct Unauthorized Action Success Rate

\[
DUASR=\frac{successful\ direct\ unauthorized\ actions}{direct\ attempts}
\]

## 10.2 Host Capability Exploitation Rate

\[
HCER=\frac{forbidden\ outcomes\ completed\ through\ host\ capabilities}{delegated/composite\ attempts}
\]

## 10.3 Composite Unauthorized Outcome Rate

\[
CUOR=\frac{unsafe\ final\ outcomes\ whose\ individual\ steps\ passed}{multi-step\ attempts}
\]

## 10.4 Persistence Success Rate

\[
PSR=\frac{attacks\ affecting\ a\ later\ task/session\ after\ revocation}{persistence\ attempts}
\]

## 10.5 Propagation Rate

\[
PR=\frac{new\ agents/tasks\ carrying\ the\ external\ objective}{eligible\ downstream\ agents/tasks}
\]

同时报告传播深度、传播宽度和 lineage 保留率，不只报告是否传播过一次。

## 10.6 Post-Revocation Residual Effect

测量 capability 被回收、任务被终止或 memory 被清理后，仍可观察到的副作用或目标影响。

## 10.7 Benign Utility

按任务报告：

- completion/accuracy；
- correct tool use；
- latency；
- token/tool calls；
- approval burden；
- false-block rate。

## 10.8 Semantic metrics

同时报告：

1. all-attempt paired net target shift；
2. fact-valid-pair net target shift；
3. clean-baseline-correct ASR；
4. validity coverage；
5. directness/leak 分层；
6. source re-grounding mitigation。

coverage 不足时结果为 `not estimable`，不能把被排除样本自动解释为零效应。

---

# 11. Pilot Evidence Already Available

## 11.1 Authority/runtime sanity

现有 deterministic sanity tests 支持：

- direct external memory commit 被阻止；
- forbidden tool 被阻止；
- self-escalation 被阻止；
- confused-deputy 基础检查通过；
- benign proposal/promotion 路径可工作。

证据等级：**smoke-valid，不是完整 benchmark 结果。**

## 11.2 ContractNLI Run A

- 150 examples / 57 documents；
- permissive one-sided constrained success：4/150 = 2.67%；
- 原始 paired movement：4 toward / 1 away；
- 净效应约 +2pp，区间跨零；
- 只能作为 semantic-payload feasibility signal。

## 11.3 ContractNLI Run B

- strict formal ASR：0/150；
- strict valid pairs：2/150；
- explicit-answer audit 淘汰约 95.7% notes；
- 原始 movement：9 toward / 0 away；
- 去除不可测的 semantic-answer gate 后，探索性事实有效净效应约 +4.7 至 +5.3pp；
- clean-baseline-correct ASR 约 2.4% 至 3.2%。

证据等级：**strict endpoint infeasible；fact-valid reanalysis exploratory。**

允许的表述：

> 已有 pilot 显示一个小幅 residual semantic influence 的可能信号，足以支持更严格的 B2，但不足以证明纯 framing、普遍感染或 re-grounding 防御有效。

---

# 12. Claim–Evidence Matrix

| Claim | 必要 baseline/control | 决定性指标 | 支持结果 | 反驳/修订结果 |
|---|---|---|---|---|
| C1：直接权限安全不等于有效控制力安全 | direct-deny baseline；delegated/composite attack | DUASR vs HCER/CUOR | DUASR≈0 但 HCER/CUOR显著大于0 | 所有间接路径也≈0，转最小充分隔离 |
| C2：delegation/composition 是独立攻击面 | non-delegable vs delegable；single-step vs multi-step | HCER/CUOR 差值 | delegation/composition 显著增险 | 无差异，删除该机制 claim |
| C3：task termination 不保证影响清除 | revocation/cleanup baseline | PSR、residual effect | capability 过期后仍有可测影响 | 清理完全有效，转 containment sufficiency |
| C4：lineage/taint/quarantine 降低驻留传播 | basic ACL vs lineage membrane | PSR、PR、utility cost | 风险下降且 utility 可接受 | 风险不降或成本过高 |
| C5：事实有效 artifact 构成残余语义面 | evidence-only、neutral、framing、ceiling control | clean ASR、net shift | 新数据/独立角色稳定复现 | 高质量 B2 归零，语义子 claim 删除 |
| C6：存在最小充分 membrane | ambient、sandbox、capability、full membrane | risk–utility frontier | 某简化配置支配更复杂配置 | 无单点支配，转 Pareto/adaptive policy |

---

# 13. Outcome–Claim Tree

```text
                     Host Boundary Pilot
                              │
                              ▼
                   Direct authority safe?
                      /                \
                    No                  Yes
                    │                    │
          implementation failure         ▼
                / revise         Host exploitation?
                                   /           \
                                 Yes            No
                                  │              │
                         delegation/composition  ▼
                              boundary      Persistence?
                                              /      \
                                            Yes       No
                                             │         │
                                    memory/lifecycle   ▼
                                       boundary    Minimal isolation
                                                        │
                                                        ▼
                                              Semantic residual?
                                                /            \
                                              Yes             No
                                               │               │
                                      semantic sub-claim   remove semantic
```

所有路径都必须同时报告 utility 和成本。只有 direct、delegated、persistence、propagation、semantic 以及 utility 均无稳定结构时，项目才进入 Kill Zone。

---

# 14. Experimental Plan

## Phase 0 — Deterministic runtime invariants

验证：

- identity/capability binding；
- no self-grant；
- expiry/revocation；
- direct forbidden action denial；
- quarantine 与 rollback；
- lineage/taint propagation；
- environment reset。

## Phase 1 — Manipulation and assay checks

- benign tasks 能在 ambient baseline 下完成；
- direct attack 在 intentionally vulnerable baseline 下成功；
- delegated/composite attack 在 vulnerable broker 下成功；
- persistence 在 direct-commit baseline 下成功；
- membrane 打开/关闭能产生预期差异。

若正控失败，不进入主 pilot。

## Phase 2 — Admission and host-exploitation pilot

采用最小有区分力条件：

- A2 proposal-only；
- A3 scoped/non-delegable；
- A4 scoped/delegable；
- A5 ambient；

跨 basic ACL、capability broker、composition-aware membrane 比较 direct、delegated 和 composite attacks。

## Phase 3 — Persistence and propagation pilot

仅在 Phase 2 的基础 assay 通过后运行：

- ephemeral vs quarantine vs persistent；
- no lineage vs transitive taint；
- no cleanup vs revocation+purge；
- same-session vs future-session；
- isolated simulated downstream agents。

## Phase 4 — Semantic payload B2

作为独立子实验，不阻塞主线：

- 新冻结数据；
- 独立 generator/auditor/downstream；
- 盲化审计；
- 预注册 fact-valid 与 directness 定义；
- true source regrounding。

## Phase 5 — Replication and generalization

只有明确主 claim 后才增加：

- 第二个宿主任务域；
- 第二模型族；
- 至少三个真正独立 replicate；
- adaptive attacker；
- 必要的跨 domain semantic confirmation。

---

# 15. Statistical Plan

- 主比较采用 paired task twins；
- 以项目/环境实例作为 cluster；
- 对共享模板任务增加 task-family 分层；
- 报告 effect size、cluster bootstrap CI 与 paired randomization/permutation test；
- direct、delegated、composite、persistence 分开估计；
- 不用单一 composite safety score 隐藏 trade-off；
- 至少三个真正独立 replicate；不把缓存键或 prompt 中的数字称为模型 sampling seed；
- 预注册 positive、negative 和 ambiguity thresholds；
- manipulation check、coverage 或 baseline 失败时判 `invalid/not estimable`，而非 negative。

第一轮阈值应在 benchmark smoke test 后、主实验之前冻结。当前 proposal 不预设未经 calibration 的最终数值阈值。

---

# 16. Baselines and Ablations

## Baselines

- ambient agent framework；
- process/container sandbox only；
- basic ACL；
- scoped capability without delegation tracking；
- proposal-only；
- full AgentMembrane candidate。

## Necessity ablations

- remove expiry/revocation；
- allow capability delegation；
- remove composition-aware check；
- remove provenance；
- remove transitive taint；
- bypass quarantine；
- remove independent approval；
- remove cleanup/rollback；
- show/hide external provenance metadata。

最终 claim 必须建立在最小必要 ablation 上，而不是比较一个大而复杂的 full system 与弱 baseline。

---

# 17. Risks and Failure Modes

## Scientific risks

1. **Benchmark 过于玩具化。** 缓解：先隔离机制，再用第二宿主任务域验证。
2. **既有 sandbox/capability 已完全解决。** 这会转为 minimal-sufficiency 结论，而不是强行增加机制。
3. **攻击只在一个模型或 prompt 成立。** 使用独立 replicate、模型族和 task family。
4. **delegation/composition oracle 含糊。** 以最终 side effect 和预注册全局 policy 判定。
5. **semantic 子实验仍不可识别。** 删除纯 framing claim，不影响主线。
6. **研究范围过宽。** 第一篇只允许一个主机制：host-capability exploitation；persistence 作为支持机制，semantic 作为子实验。

## Safety and ethics

- 所有工具、通信、数据库和 secrets 均为 mock；
- 无真实凭据、真实用户或开放网络副作用；
- 不发布可直接部署的自主传播实现；
- 所有环境可重置并记录完整 audit log；
- 对具体攻击 artifact 的公开遵循负责任披露与最小必要原则。

---

# 18. Negative-Result Value

以下均为有效结果：

1. **Capability sufficiency：** scoped、non-delegable capability 已阻止所有利用路径；
2. **Delegation threshold：** 风险只在 capability 可委托时出现；
3. **Composition threshold：** 单步安全但多步组合危险；
4. **Persistence threshold：** 行为层安全但 memory 生命周期危险；
5. **Containment–utility frontier：** 无单一配置同时最优；
6. **Semantic null：** 在合格 B2 下 semantic residual 为零；
7. **Kill：** 最强现有 baseline 已无成本地解决所有风险，且不存在新的边界结构。

---

# 19. Expected Contributions

最终只保留被结果支持的贡献：

1. **External-Agent Admission Threat Model：** 区分 direct permission 与 host-mediated effective influence；
2. **AgentMembrane Reference Runtime：** 显式 admission、capability、delegation、lineage、promotion 和 cleanup；
3. **Empirical Boundary Map：** 刻画 admission、host exploitation 与 persistence 的边界；
4. **Minimum Sufficient Membrane 或 Pareto Frontier：** 识别最小充分机制或不可避免的安全–效用权衡；
5. **Residual Semantic Payload（可选）：** 仅在独立 B2 复现时保留。

---

# 20. RQ Revision Comparison

## 20.1 Side-by-side mapping

| 当前 proposal RQ | 修订 proposal RQ | 变化程度 | 继承关系 |
|---|---|---:|---|
| RQ1 Authority Boundary | RQ1 Admission Boundary | 中等 | 保留 authority ladder，增加动态接入、身份、lease、expiry、revocation |
| RQ2 Receptor Boundary | RQ2 Host-Capability Exploitation | **较大** | receptor 降为一个解释变量；核心改为 delegation、broker、capability chaining |
| RQ3 Memory Promotion Boundary | RQ3 Persistence and Propagation | 中等偏大 | 保留 promotion/taint/provenance，扩展到跨任务、跨 session、传播与清除 |
| RQ4 Authority–Semantic Relationship | RQ4 Containment–Utility Boundary | 中等 | 保留多层安全是否必要的问题，范围扩大到行为、委托、持久状态和成本 |

## 20.2 Bottom-line assessment

RQ 的编号和 boundary-first 骨架没有完全推翻，但研究重心发生了实质变化：

- **RQ1 是扩展，不是重做；**
- **RQ2 是最大改动，也是恢复原始“利用宿主功能”构思的关键；**
- **RQ3 从 memory promotion 扩展成完整感染生命周期；**
- **RQ4 从 authority vs semantic 二分，扩展为整体 containment–utility 选择。**

因此不能说两版 RQ 完全不同，但也不能只做文字改名。修订版改变了主机制、主 benchmark 和主 claim；现有架构、runtime、authority tests 与 ContractNLI pilot 仍然可以复用。

---

# 21. Current-vs-Revised Proposal Summary

| 维度 | 当前版本 | 修订版本 |
|---|---|---|
| 外部 Agent | 主要是 artifact producer | 进入并参与宿主工作流的主动执行体 |
| 主风险 | semantic framing / memory judgment | host capability exploitation、persistence、propagation |
| 主实验 | ContractNLI framing | isolated host-agent benchmark |
| ContractNLI | 主线 | semantic 子实验 |
| Receptor | 主轴 | 保留，但服务于利用路径分析 |
| Memory | artifact promotion | 完整生命周期、传播、revocation、cleanup |
| 主要正控 | explicit target label | vulnerable broker、delegation、direct commit 等机制正控 |
| 主指标 | semantic ASR/TDS | HCER、CUOR、PSR、PR + utility |
| 理想 claim | authority-safe 不等于 semantic-safe | direct permission control 不足以描述 host-mediated effective influence |
| 与原始病毒构思 | 部分匹配 | 高度匹配 |

---

# 22. Next Milestone

在进入昂贵实验前，下一里程碑只做三件事：

1. 冻结一个最小宿主 benchmark 的资源、工具、policy 和 side-effect oracle；
2. 用 deterministic/scripted attacker 证明 vulnerable baseline 能出现 direct、delegated、composite 和 persistence 四类现象；
3. 选择一个最小 membrane 配置，与 strongest practical baseline 做公平比较。

达到以下条件后才称为 `ready for pilot`：

- benign baseline 可完成；
- 每个主 attack family 有通过的正控；
- oracle 可自动判定且通过人工抽检；
- 环境完全隔离、可恢复；
- primary/secondary metrics 与 ambiguity rule 已预注册；
- related-work 与 strongest-incumbent 检索完成。

---

# 23. One-Sentence Thesis

> **AgentMembrane characterizes how an untrusted external agent can enter a multi-agent host, exploit host-mediated capabilities, establish persistent influence, and propagate across agents—and identifies the minimum containment boundary that preserves useful collaboration.**

中文：

> **AgentMembrane 研究不可信外部 Agent 接入多 Agent 宿主后，如何利用宿主能力、建立持久影响并跨 Agent 传播，以及系统在保留有效协作的前提下，最少需要哪些隔离与控制机制。**
