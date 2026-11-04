# Week 16 · 代码与批次位置

本周的原始轨迹、运行环境和模型调用记录不进 Git。下表给出它们在实验工作区里的位置,路径都相对实验工作区根目录。

| 内容 | 位置 | 说明 |
|---|---|---|
| 新方法实现 | `tau/compiled_auth.py` | `Compiler`(v1)、`CompilerV2`(v2)、`CompilerV3`(v3)、`CompilerV4`(v4);v1 冻结副本在 `proposal/memos/26_method_deepen/snapshots_pre_v2/` |
| 写入门与预检 | `tau/tau_membrane.py`:`_compiled_gate`、`check_change` | 只在 `--seal-source compiled` 下生效 |
| 运行器开关 | `tau/run_tau.py`:`--seal-source compiled`、`--compile-version v1 / v2 / v3 / v4`、`--compile-model`、`--compile-k`、`--compile-vote`、`--log-usage` | 默认全部关闭,旧批次行为逐字节不变 |
| 零 API 测试 | `tau/test_compiled_auth.py`(21 项) | tau 测试套件全部回归通过(`test_p0_switches` 162 项、`test_core_tau` 118 项等) |
| 正式批次 | `out_bl2/`(408 局)、`out_bl3/`(576 局)、`out_bl4/`(1,152 局)、`out_bl3n/`(96 局)、`out_bl5/`(240 局)、`out_bl6/`(576 局) | 每批有 `PREREG.md`、`HASHES.txt`(开跑前写定,跑后复核)、`make_jobs.py`、`jobs.txt`、`RESULT.md`;冒烟目录 `*_smoke*/` 不计入 |
| 汇总脚本 | `analysis/summarize_bl2.py`、`summarize_bl3.py`、`summarize_bl4.py`、`summarize_bl3n.py`、`summarize_bl56.py`、`cost_bl3.py` | 判分与统计复用 `analysis/summarize_p0.py` 与 `proposal/memos/16_audit/scripts/audit_tau.py`,未改动 |
| 诊断实验 | `out_cb/`、`out_e1/`、`out_eb/`、`out_e2/`、`out_e2r2/`;代码 `analysis/compile_bench.py`、`coda_e1.py`、`eb_invariance.py`、`evir_e2.py`、`evir_r2.py`、`audit_v2.py` | 每批有预注册与结果说明 |
| 设计讨论 | `proposal/memos/26_method_deepen/`(`ALGORITHM_v2.md`、`SYNTHESIS.md`、各轮 BRIEF 与复核记录) | 问题拆解 P1–P8、两个根因、各版设计的来由 |
| AI 顾客说明文件 | `tau/user_sim/simulation_guidelines.md` | 从 τ 仓库的 git 记录导出,未改动 |
