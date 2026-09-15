# Week 4 Baseline Replication Matrix

**日期：2026-07-28**

本表专门回答三个问题：跑了什么、数字是否和论文一样、如果不一样究竟能不能比较。

## 1. 核心 released baselines

| Paper / baseline | 论文或官方公开值 | 本周值 | 规模与 actual route | 一致性判定 | 可以说什么 |
| --- | --- | --- | --- | --- | --- |
| **Lethe deterministic** | `244/385=63.4%` | `244/385=63.38%` | 385/385；local/offline deterministic pipeline + released scorer | **精确一致** | 可以说精确复现 released deterministic headline |
| **Engram released lean/full** | lean `83.6%`；full `73.2%`；差 `+10.4pp` | lean `418/500=83.6%`；full `366/500=73.2%` | 500题 shipped outputs；local/offline aggregation | **公开产物复算一致** | 可以说 released logs 与 README 数字一致；不能说重新跑通原 Doubao/DeepSeek 栈 |
| **TokenPilot continuous aggregate** | quality `79.2%→81.3%`；成本约 `$7.24→$2.79` | quality 相同；cost parser `$7.242375→$2.788575` | released aggregate；live probe 为 `gpt-5.4-mini-2026-03-17`，但 paired 0/5 | **公开聚合复算一致；live NO-GO** | 主模型账一致；完整 TCO 不可识别，不能称端到端复现 |
| **Supersede full vs bounded** | n=78，full `92%`，bounded-300 `77%`，差 `15pp` | n=25，full `76%`，bounded-300 `40%`，差 `36pp` | `gpt-5.4-mini-2026-03-17` substitute；25 paired | **方向一致，数字不可直接比较** | 支持 full>bounded 方向；不能声称论文数字复现 |
| **Engram live lean/full** | released headline lean 比 full 高 `10.4pp` | lean `26/30=86.67%`；full `30/30=100%`；差 `-13.33pp` | `gpt-5.4` answer/judge/extraction；released HashingEmbedder substitute | **方向反转，但非精确** | 只能说 headline 对替代模型/表示栈可能不稳健；不能据此推翻论文 |
| **LongMemEval-V2 released slice** | 论文为多系统/双 tier benchmark，headline 不对应本切片 | `3/30=10%` | reader `gpt-5.4-mini-2026-03-17`；judge `gpt-5.4`；hashed-TFIDF、text-only、context cap | **不可比较** | 只能诊断当前 substitute retrieval/packing chain 失败 |
| **Agent-Native BM25 vs no-memory** | 论文是 22 系统×多自建/重构子集横评，无此 10-case 对应 headline | memory EM `100%`、F1 `1.0`；no-memory EM `90%`、F1 `.9556` | 10 paired；`gpt-5.4`；BM25 diagnostic | **不可比较** | 说明这个切片 memory 有小幅质量增益但 token 代价巨大 |
| **Pi-CWL filterContext** | 论文 end-to-end agent headline，不等同 synthetic mechanism suite | clean CWL-recency `+2.17pp`；noise=.75 为 `-2.84pp` | 1,200 local/offline official function + 1,200 fresh-seed held-out | **机制测试，不是 headline 复现** | 可以说官方淘汰函数在等预算合成机制中出现 annotation-noise reversal |

## 2. 本周新增 trade-off 数据

### 2.1 Agent-Native

| Arm | EM | F1 | Input tokens | Total tokens |
| --- | ---: | ---: | ---: | ---: |
| BM25 memory | 1.0000 | 1.0000 | 289,845 | 290,572 |
| No memory | .9000 | .9556 | 5,557 | 9,756 |
| Memory − no memory | +10pp | +4.44pp | +284,288 | — |

解释：增益存在，但每例平均多约 28,429 input tokens。研究问题应是 selective invocation，而不是默认挂载 memory。

### 2.2 TokenPilot released aggregate

| Metric | Vanilla | TokenPilot / released LightMem2 | Change |
| --- | ---: | ---: | ---: |
| Overall score | 79.2% | 81.3% | +2.1pp |
| Cache-read tokens | 25,015,000 | 8,551,000 | -65.82% |
| Cache-miss tokens | 5,943,000 | 1,549,000 | -73.94% |
| Output tokens | 202,000 | 219,000 | +8.42% |
| Main-model cost | $7.242375 | $2.788575 | -61.50% |

边界：released 数据没有 estimator、distiller、embedding usage，因此 main-model cost 是完整 TCO 的下界。

### 2.3 Engram

| Surface | Lean | Full | Difference / ratio |
| --- | ---: | ---: | ---: |
| Released accuracy | 83.6% | 73.2% | lean +10.4pp |
| Substitute-stack accuracy | 86.67% | 100% | lean -13.33pp |
| Query context estimated tokens | 376,544 | 3,153,209 | full/lean 8.37× |
| Extraction preprocessing | 3,844,788 | 0 | lean-only setup cost |
| One-query end-to-end token ledger | 4,265,154 | 3,155,656 | lean/full 1.35× |

解析 break-even 为 `1.406 queries/history`。但 released 500/500 histories 全唯一，因此这个拐点尚未在真实多查询数据上得到确认。

### 2.4 Supersede

25-case baseline：

| Arm | Accuracy | Calls | Estimated cost |
| --- | ---: | ---: | ---: |
| Full context | 19/25=76% | 25 | $0.0616 |
| Bounded-300 | 10/25=40% | 75 | $0.1332 |

108-condition matrix：

| Horizon | Full | Bounded-150 | Bounded-300 |
| --- | ---: | ---: | ---: |
| Short | 75.0% | 33.3% | 33.3% |
| Medium | 83.3% | 0% | 16.7% |
| Long | 75.0% | 8.3% | 0% |

六个 bounded-vs-full accuracy difference 的 case-bootstrap 95% CI 全低于 0；observed-cache 与 all-cold 两种成本口径下，成本差 CI 全高于 0。对任何 `λ≥0`，`Uλ=accuracy−λ·cost` 都没有 bounded crossover。

### 2.5 Lethe selective forgetting

| Policy | External305 success | vs always | Calls saved | Tokens saved | Over-delete |
| --- | ---: | ---: | ---: | ---: | ---: |
| Never hook | 194/305=63.61% | -27.54pp | 100% | 100% | scorer-defined |
| Always hook | 278/305=91.15% | reference | 0 | 0 | — |
| Selective-50 | 266/305=87.21% | -3.93pp, CI [-6.23,-1.97] | 53.48% | 59.29% | 0 |
| Selective-75 | 271/305=88.85% | -2.30pp, CI [-4.26,-.66] | 23.96% | 26.19% | 0 |

最坏组：cross-lingual 上 selective-50 为 `21/30`，always 为 `29/30`，差 `-26.7pp`，CI `[-43.3,-13.3]`。

### 2.6 Pi-CWL equal-budget eviction

| Condition | CWL − recency required-evidence recall | Interpretation |
| --- | ---: | --- |
| Clean annotation | +2.17pp，CI [1.24,3.16] | structure helps when annotation is reliable |
| Noise=.75 | -2.84pp，CI [-3.85,-1.90] | conclusion reverses under high annotation noise |

Fresh-seed held-out 1,200：fallback recall `.9809` vs CWL `.9741`，差 `+.68pp`，CI `[+.45,+.94]`；closure violation 从 `0` 增至 `.0203`。

## 3. Phase D/E 论文线的证据等级

| Paper line | 本周/前序关键值 | Actual route | 与论文一致性 |
| --- | --- | --- | --- |
| MemPrivacy | GPT-5.5 typed vs label-swap attribute `+.5625 [.4167,.7083]`；typed vs cross-session-shuffle link `+.3958 [.25,.5417]` | `gpt-5.4` 与 `gpt-5.5` controls | 跨可用模型重复了结构通道；不是论文原协议数值复现 |
| Beyond Memory Leaderboards | held-out selector score `5.0` vs fixed-50k `5.4583`；token `-31.29%` | synth `gpt-5.4-mini`、judge `gpt-5.4` substitute | generic router utility 门失败；非论文 leaderboard 复现 |
| MemTrace | strict/lenient/placebo mean ΔF1 `+.1017/+.0760/-.0654` | `gpt-5.4` replay validation；small mechanical slice | 存在 compression/variance 混杂；不能称 paper-certified replay 复现 |
| MemSyco | raw `.90`；scaffold/sham-like arms `1.0`，但 raw failure 仅 2/20 | `gpt-5.5` substitute self-judge | boundary eligibility FAIL；不报 metadata 全局排名 |
| GateMem | Phase E 5 cases×3 attacks×stages；exposed recovery=0 | shadow adapter + substitute | native injection 缺失，严格 NO-GO |

## 4. 判定规则

只有满足以下条件才在本报告中写“精确复现”：

1. 相同 released data；
2. 相同 deterministic method 或可确认的原始 model route；
3. 相同 scorer；
4. 相同 headline denominator；
5. sample-level 结果可复算。

因此：

- Lethe deterministic：**exact reproduction**；
- Engram、TokenPilot：**released-output/aggregate recomputation**；
- Supersede：**same directional finding, non-exact**；
- 其他本地模型调用：**substitute validation / mechanism test / NO-GO**。

这一区分是本周报告最重要的可信度边界之一。
