# Week 17 · 代码与批次位置

本周的原始轨迹、运行环境和模型调用记录都不进 Git。下表给出它们在实验工作区里的位置,路径都相对于实验工作区根目录。

| 内容 | 位置 | 说明 |
|---|---|---|
| 只核对的各版实现 | `tau/compiled_auth.py`:`CompilerVerify`(V5)、`CompilerVerify2`(V5b)、`CompilerVerifyS`(V5S)、`CompilerVerifyS2`(V5S2)、`CompilerVerifyS3`(V5S3,K1 + 事实来源开关) | 各版由 `--compile-mode verify / verify2 / verifyS / verifyS2 / verifyS3` 选择 |
| 轨迹(状态链) | `tau/state_chain.py` | 只能追加,每条用 HMAC-SHA256 和前一条绑定。记录类型:事实、说法、写入、顾客要求、外发 |
| 运行器开关 | `tau/run_tau.py`:`--state-chain`、`--outbound-min`、`--compile-mode`、`--facts-from`、`--compile-assist`、`--h-context` | 默认全部关闭(`--facts-from` 默认 `trace`),旧批次行为不变 |
| 改前快照 | `snapshots_pre_v5/`(如 `compiled_auth_pre_verifyS3.py`、`run_tau_pre_verifyS3.py`) | 每次改核对规则之前先存快照 |
| 零 API 测试 | `tau/test_verifyS3.py`(8 项,本周新增)、`test_fact_conditions.py`(11 项)、`test_state_chain.py`(9 项)、`test_compiled_auth.py`(30 项)、`test_bl_switches.py`(27 项) | 全部通过 |
| 零 API 重放 | `analysis/replay_vS3.py` → `analysis/replay_vS3_out_bl13_V5S2.json` | 用 out_bl13 里 V5S2 的 357 局原始编译和轨迹,比较改前、改后的判决 |
| 干净对比批次 | `out_bl14/`(1,112 局) | `PREREG.md`、`HASHES.txt`(开跑前写定)、`make_jobs.py`(从 out_bl13 的 V5S2 作业行生成,每格只替换一个参数)、`jobs.txt`、`RESULT.md`;冒烟目录 `out_bl14_smoke/` 不计入 |
| 汇总脚本 | `analysis/summarize_bl14.py`、`analysis/summarize_bl13.py` | 判分与统计复用 `analysis/summarize_p0.py` 和 `proposal/memos/16_audit/scripts/audit_tau.py`,未改动 |
| 开发批次 | `out_bl7/` 至 `out_bl13/` | 每批有 `PREREG.md`、`HASHES.txt`、`RESULT.md` |
| 设计文档 | `proposal/memos/26_method_deepen/`(`DESIGN_v5.md`、`DESIGN_trace*.md`) | 只核对模式和轨迹的设计 |
