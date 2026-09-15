# Week 3 汇报

**Main report (English):** [week3_report_20260719_en.md](week3_report_20260719_en.md)
中文版:[week3_report_20260719_zh.md](week3_report_20260719_zh.md)

## 一句话
RT-02 的一次自我拆解、重建与确证启动:把上周的 GO/STOP 结论逐条审出"数字对、构念错"(6 个共性根因),重写一版修好构念的 v2 实验,过程中又现场抓修两个我自己犯的错(主测量结构性失效、检索挤出混杂),按公开 benchmark 逐条 git 实证可靠性,最后启动 30 例独立确证(运行中)。

## 内容骨架
- §0 一句话结论(数字对构念错;修好后 dev 预览方向性支持 CHIR;RT-02 现实是一篇不是两篇)
- §1 自我拆解:上周结论的 6 个共性根因(无真算子 / 无检索 / 全库稀释 / 未来≈现在 / 对照退化 / 分支不对齐)
- §2 v2 重建:逐条修好 6 根因,全程离线自证,主自测全绿
- §3 dev smoke + 两个"我自己的错"被现场抓到(主测量 source_only 结构性失效 → carrier_matched;检索挤出混杂 → 主终点改 semantic_residual)
- §4 两个执行/口径纠正("慢"的主因是笔记本睡眠非限流;benchmark 对齐 git 实证)
- §5 RQ 重构:RQ3 改写后主攻;RQ2/RQ4 退休、RQ5 缩到三轴;结论 RT-02 = 一篇论文
- §6 当前状态:30 例独立确证正在跑;三种结局(语义型 / 挤出型 / 判负)都会如实写
- §7 交付物清单

## 前身仓库中的支撑材料（本仓未纳入）

以下路径记录当时在[前身仓库](https://github.com/heaven999b/memory_consolidation_small_pilot)中的原始位置；本 AgentMembrane 归档只纳入本周主报告，这些反引号路径不是本仓内可打开的文件。

- v1 逐 RQ 批判评审:`state/rt02_v1_critical_review_20260719.md`
- v2 构念修复冻结设计:`state/rt02_v2_construct_validity_design_20260719.md`
- confirmatory 冻结配置(主终点 = semantic_residual):`state/rt02_confirmatory_config_20260719.md`
- dev smoke 报告(含两个构念错误的发现):`state/rt02_v2_dev_smoke_report_20260719.md`
- benchmark 对齐 git 实证审计:`state/rt02_v2_benchmark_alignment_20260719.md`
- 到论文的问题清单 + 限制框架/行动方案:`state/rt02_paper_gap_checklist_20260719.md`、`state/rt02_limitations_and_action_plan_20260719.md`
- 已退休研究线说明:`state/RETIRED_LINES.md`
- v2 全套代码:`scripts/run/rt02/rt02_v2_*.py`、`run_rt02_v2_*.py`、`rt02_v2_selftest.sh`

## 承接
- 上游 RT-02 topic / proposal：[Week 2 主报告 §10](../week2/week2_report_20260713_zh.md)
- 说明:本周未产出新阳性,主体是构念修复 + 独立确证启动;结果无论正负均按本报告框架如实回填。
