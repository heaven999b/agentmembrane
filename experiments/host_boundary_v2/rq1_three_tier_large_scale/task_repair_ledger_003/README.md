# RQ1 三档权限：86 道独立原题逐题修复账本

本账本由 fresh 离线 readiness 结果生成；‘接口可用’或诊断观察器不等于正式准入。

| 原题 | 技术策略 | 原题权限闭环 | 严格原题评分 | Q/I/D诊断草案 | 正式准入 | 主要阻塞 |
| --- | --- | --- | --- | --- | --- | --- |
| banking/user_task_0 | 是 | 否 | 否 | 否 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending, owner_workflow_not_executable_under_current_contract |
| banking/user_task_1 | 是 | 是 | 是 | 是 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending |
| banking/user_task_2 | 是 | 是 | 否 | 否 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending, strict_original_task_checker_not_ready |
| banking/user_task_3 | 是 | 是 | 是 | 是 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending |
| banking/user_task_4 | 是 | 是 | 是 | 是 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending |
| banking/user_task_5 | 是 | 是 | 否 | 否 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending, strict_original_task_checker_not_ready |
| banking/user_task_6 | 是 | 是 | 否 | 否 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending, strict_original_task_checker_not_ready |
| banking/user_task_7 | 是 | 是 | 是 | 是 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending |
| banking/user_task_8 | 是 | 是 | 否 | 否 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending, strict_original_task_checker_not_ready |
| banking/user_task_9 | 是 | 否 | 否 | 否 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending, owner_workflow_not_executable_under_current_contract |
| banking/user_task_10 | 是 | 否 | 否 | 否 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending, owner_workflow_not_executable_under_current_contract |
| banking/user_task_11 | 是 | 是 | 否 | 否 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending, strict_original_task_checker_not_ready |
| banking/user_task_12 | 否 | 否 | 否 | 否 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending, original_request_delegates_unspecified_document_instructions |
| banking/user_task_13 | 是 | 是 | 否 | 否 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending, strict_original_task_checker_not_ready |
| banking/user_task_14 | 是 | 否 | 否 | 否 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending, owner_workflow_not_executable_under_current_contract |
| banking/user_task_15 | 是 | 是 | 否 | 否 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending, strict_original_task_checker_not_ready |
| slack/user_task_0 | 是 | 是 | 是 | 是 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending |
| slack/user_task_1 | 是 | 是 | 否 | 否 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending, strict_original_task_checker_not_ready |
| slack/user_task_2 | 是 | 是 | 否 | 否 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending, strict_original_task_checker_not_ready |
| slack/user_task_3 | 是 | 是 | 否 | 否 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending, strict_original_task_checker_not_ready |
| slack/user_task_4 | 是 | 是 | 否 | 否 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending, strict_original_task_checker_not_ready |
| slack/user_task_5 | 是 | 是 | 是 | 是 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending |
| slack/user_task_6 | 是 | 是 | 否 | 否 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending, strict_original_task_checker_not_ready |
| slack/user_task_7 | 是 | 是 | 是 | 是 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending |
| slack/user_task_8 | 是 | 是 | 否 | 否 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending, strict_original_task_checker_not_ready |
| slack/user_task_9 | 是 | 是 | 否 | 否 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending, strict_original_task_checker_not_ready |
| slack/user_task_10 | 是 | 是 | 否 | 否 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending, strict_original_task_checker_not_ready |
| slack/user_task_11 | 是 | 是 | 否 | 否 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending, strict_original_task_checker_not_ready |
| slack/user_task_12 | 是 | 是 | 是 | 是 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending |
| slack/user_task_13 | 是 | 是 | 否 | 否 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending, strict_original_task_checker_not_ready |
| slack/user_task_14 | 是 | 是 | 否 | 否 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending, strict_original_task_checker_not_ready |
| slack/user_task_15 | 是 | 是 | 否 | 否 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending, strict_original_task_checker_not_ready |
| slack/user_task_16 | 是 | 是 | 否 | 否 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending, strict_original_task_checker_not_ready |
| travel/user_task_0 | 是 | 是 | 是 | 是 | 否 | formal_source_authorization_and_endpoint_gate_pending |
| travel/user_task_1 | 是 | 是 | 是 | 是 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending |
| travel/user_task_2 | 是 | 是 | 是 | 是 | 否 | formal_source_authorization_and_endpoint_gate_pending |
| travel/user_task_3 | 是 | 是 | 是 | 是 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending |
| travel/user_task_4 | 是 | 是 | 是 | 是 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending |
| travel/user_task_5 | 是 | 是 | 是 | 是 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending |
| travel/user_task_6 | 是 | 是 | 否 | 否 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending, strict_original_task_checker_not_ready |
| travel/user_task_7 | 是 | 是 | 是 | 是 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending |
| travel/user_task_8 | 是 | 是 | 是 | 是 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending |
| travel/user_task_9 | 是 | 是 | 是 | 是 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending |
| travel/user_task_10 | 是 | 是 | 是 | 是 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending |
| travel/user_task_11 | 是 | 是 | 是 | 是 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending |
| travel/user_task_12 | 是 | 是 | 是 | 是 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending |
| travel/user_task_13 | 是 | 是 | 是 | 是 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending |
| travel/user_task_14 | 是 | 是 | 是 | 是 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending |
| travel/user_task_15 | 是 | 是 | 是 | 是 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending |
| travel/user_task_16 | 是 | 是 | 否 | 否 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending, strict_original_task_checker_not_ready |
| travel/user_task_17 | 是 | 是 | 是 | 是 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending |
| travel/user_task_18 | 是 | 是 | 否 | 否 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending, strict_original_task_checker_not_ready |
| travel/user_task_19 | 是 | 是 | 否 | 否 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending, strict_original_task_checker_not_ready |
| workspace/user_task_0 | 是 | 是 | 是 | 是 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending |
| workspace/user_task_1 | 是 | 是 | 是 | 是 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending |
| workspace/user_task_2 | 是 | 是 | 是 | 是 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending |
| workspace/user_task_3 | 是 | 是 | 是 | 是 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending |
| workspace/user_task_5 | 是 | 是 | 是 | 是 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending |
| workspace/user_task_6 | 是 | 是 | 是 | 是 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending |
| workspace/user_task_7 | 否 | 否 | 否 | 否 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending, native_reference_pending_repair |
| workspace/user_task_8 | 是 | 是 | 是 | 是 | 否 | formal_source_authorization_and_endpoint_gate_pending |
| workspace/user_task_9 | 是 | 是 | 是 | 是 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending |
| workspace/user_task_10 | 是 | 是 | 是 | 是 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending |
| workspace/user_task_11 | 是 | 是 | 是 | 是 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending |
| workspace/user_task_12 | 是 | 是 | 是 | 是 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending |
| workspace/user_task_13 | 否 | 否 | 否 | 否 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending, original_request_delegates_unspecified_email_instructions |
| workspace/user_task_14 | 是 | 是 | 是 | 是 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending |
| workspace/user_task_15 | 是 | 是 | 否 | 否 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending, strict_original_task_checker_not_ready |
| workspace/user_task_16 | 是 | 是 | 是 | 是 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending |
| workspace/user_task_17 | 是 | 是 | 是 | 是 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending |
| workspace/user_task_18 | 是 | 是 | 否 | 否 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending, strict_original_task_checker_not_ready |
| workspace/user_task_20 | 是 | 是 | 否 | 否 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending, strict_original_task_checker_not_ready |
| workspace/user_task_21 | 是 | 是 | 是 | 是 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending |
| workspace/user_task_22 | 是 | 是 | 是 | 是 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending |
| workspace/user_task_24 | 是 | 是 | 是 | 是 | 否 | formal_source_authorization_and_endpoint_gate_pending |
| workspace/user_task_25 | 是 | 否 | 否 | 否 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending, owner_workflow_not_executable_under_current_contract |
| workspace/user_task_26 | 是 | 是 | 是 | 是 | 否 | formal_source_authorization_and_endpoint_gate_pending |
| workspace/user_task_27 | 是 | 是 | 是 | 是 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending |
| workspace/user_task_28 | 是 | 是 | 是 | 是 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending |
| workspace/user_task_29 | 是 | 是 | 否 | 否 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending, strict_original_task_checker_not_ready |
| workspace/user_task_30 | 是 | 是 | 是 | 是 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending |
| workspace/user_task_31 | 是 | 是 | 否 | 否 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending, strict_original_task_checker_not_ready |
| workspace/user_task_32 | 是 | 是 | 否 | 否 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending, strict_original_task_checker_not_ready |
| workspace/user_task_33 | 是 | 是 | 否 | 否 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending, strict_original_task_checker_not_ready |
| workspace/user_task_34 | 是 | 是 | 否 | 否 | 否 | Q_I_D_full_contract_not_reviewed, formal_source_authorization_and_endpoint_gate_pending, strict_original_task_checker_not_ready |
| workspace/user_task_35 | 是 | 是 | 是 | 是 | 否 | formal_source_authorization_and_endpoint_gate_pending |
