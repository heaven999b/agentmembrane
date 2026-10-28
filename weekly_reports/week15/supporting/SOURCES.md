# Week 15 · 代码与批次位置

本周的原始轨迹、运行环境和模型调用记录不进 Git;下表给出它们在实验工作区里的相对位置,便于对照。路径均相对实验工作区根目录。

| 内容 | 位置 | 说明 |
|---|---|---|
| 预注册 / 哈希 / 结果说明 | `out_bl/PREREG.md`、`out_bl/HASHES.txt`、`out_bl/RESULT.md` | 哈希分两部分:8 格开跑前;ToolGuard 格在守卫冻结后补跑前 |
| 作业清单 | `out_bl/make_jobs.py` → `out_bl/jobs_full.txt` | 17 题 × 9 格 × 6 = 918 行,种子 20261028 打乱 |
| 原始轨迹 | `out_bl/`(816 局)、`out_bl_tg/`(ToolGuard 格 102 局) | 每局一个 JSON;冒烟 `out_bl_smoke/` 不计入 |
| 汇总脚本 | `analysis/summarize_bl.py`、`analysis/bl_igac_hidden_tool.py` | 复用 `analysis/summarize_p0.py` 的判分与统计 |
| 外部方法移植 | `tau/igac_gate.py`、`tau/policyguard_gate.py`、`tau/baseline_gates.py`(实体绑定闸门)、`tau/toolguard_build.py` / `tau/toolguard_check.py` | 每个模块列出原文出处、照搬部分的 SHA-256 与全部改动 |
| ToolGuard 守卫 | `tau/toolguard_retail/`(MANIFEST.json 记 305 个文件的哈希) | 由 ToolGuard 0.2.21 用 gpt-5.6-luna 生成一次后冻结,未人工审阅 |
| 运行器开关 | `tau/run_tau.py`:`--call-gate igac / policyguard`、`--call-gate-preview`、`--monitor entity_binding`、`--toolguard` | 默认全部关闭,旧批次行为不变 |
| 零 API 测试 | `tau/test_igac_gate.py`(50)、`tau/test_policyguard_gate.py`(48)、`tau/test_baseline_gates.py`、`tau/test_bl_switches.py`(27 项整局测试) | 旧测试套件全部回归通过 |
| 文献调研 | `proposal/memos/25_baselines_survey/SYNTHESIS_20261026.md` | baseline 归类与选择理由 |
