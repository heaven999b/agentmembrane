# Week 2 汇报

主报告:[week2_report_20260713_zh.md](week2_report_20260713_zh.md)

## 内容骨架
- §0–4 原始 RQ1/RQ2 小样本判定(固化不放大不安全、不制造假记忆的负结论)
- §5 更硬的复测:换真实数据 + 金标 + 换 prompt(固化对安全信息忠实、不洗白)
- §6 复现并拆穿 MemEvoBench(90% 出事率里 ~55pt 是基线水位;真记忆效应 +30pt,换裁判仍守住)
- §7 桥实验(投毒记忆 → 固化 → 翻车率:不升反降)
- §8 全面复测(换更强检测器 + 修 bug + 开没测过的门):四个角度均确认固化不作恶
- §9 新研究构思:ConsolidationBench —— 把记忆漂移归因到固化算子本身(Δ_op = 固化开 − 固化关)

## 前身仓库中的支撑材料（本仓未纳入）

以下路径记录当时在[前身仓库](https://github.com/heaven999b/memory_consolidation_small_pilot)中的原始位置；本 AgentMembrane 归档只纳入本周主报告，这些反引号路径不是本仓内可打开的文件。

- MemEvoBench 复现详版:`state/memevobench_replication_pilot_20260712.md`
- RQ1/RQ2 修复方案:`state/rq1_rq2_fix_masterplan_20260712.md`
- RQ1 隐式风险物料:`state/rq1_implicit_materials_20260712.md`
- ConsolidationBench 构思文档:`state/consolidationbench_idea_{zh,en}_20260713.md`
- 分析脚本:`scripts/analysis/{rq2_stage_verdict_fixed,bridge_consolidate_asr,rq2_gpt4o_relation_sweep,rq1_implicit_sweep,aggregate,rejudge}.py`
