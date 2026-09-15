# RQ1 collaborative implementation

Status: engineering slice verified; NOT a full baseline, NOT a model study. Formal model launch is intentionally unavailable until the remaining implementation and qualification gates are satisfied.

The research scope remains the original RQ1 with the user's four-level subset A0/A1/A3/A4. PLAIN/CAP share technical views; CAP adds dispatch-purpose checks. H_ONLY has the same total decision budget. Current request-only policies and private strict checkers cover six original AgentDojo tasks: workspace/UserTask8,24,26,35 and travel/UserTask0,2. They do not constitute a representative formal task panel.

## Actual implementation

- runtime.py / policy.py: strict actions, independent H/E histories, continuing host, authority and recipient scopes, budget/close/revocation.
- native.py: actual registered AgentDojo tasks/tools, original reference qualification, private native/strict scoring and lossless ordered snapshots.
- process_backend.py: trusted native pipe service and separate private scorer; same UID explicitly is NOT hostile-code isolation.
- services.py: persistent SQLite notes/checkpoints, capability leases, actual mailbox delivery/consumption, active control configuration.
- evaluation.py / statistics.py: independent task-rule checks, known violations versus unknown, CP/paired/A* and explicit power scenarios.
- providers.py: explicit-profile Chat Completions-compatible transport, exact request/response evidence, no implicit key discovery/model fallback/retry. Offline transport tests passed; no live-provider validation claimed. It is not enabled by the current runtime.
- audit.py / campaign.py / cli.py: append-only evidence, hash verification, paired S panel planning, immutable retries, fail-closed formal preflight.
- data.py: actual public-source audits, not completed FinQA/Hotpot/CRM/AppWorld task adapters.
- integration.py / verification.py: reproducible real-native engineering chain and recorded test execution.
- six_sample.py / profiles_workspace.py / profiles_travel.py / pilot_checkers.py: fixed six-task engineering campaign, source-bound task-purpose dispatch and independent strict completion checks. Native scorers are retained, not treated as sufficient by themselves.

Model transport fields were checked against the [official Chat Completions API reference](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create). Backend compatibility must still be tested against the selected locked provider; API documentation does not prove access or capability.

## Reproduce current verified checks

Working directory: repository root

Use the existing task-local Python/dependencies, not the dependency-free system Python:

```sh
RQ1_PY=experiments/host_boundary_v2/runtime_envs/agentdojo-0.1.35-py3123-lock-395e3d0a5921-rq1v4/bin/python
RQ1_DEPS=experiments/host_boundary_v2/runtime_envs/agentdojo-0.1.35-py3123-lock-395e3d0a5921-rq1v4/lib/python3.12/site-packages
PYDANTIC_DISABLE_PLUGINS=__all__ PYTHONPATH="$RQ1_DEPS:." "$RQ1_PY" -S -m unittest discover -s tests/rq1_collab_v1 -v
```

Cloud-backed unrelated .pth/plugin metadata can stall ordinary Python startup. The explicit -S/dependency path and supported Pydantic plugin-disable setting avoid that; no dependency/source file is patched.

Recorded verification, requiring a NEW output directory:

```sh
PYDANTIC_DISABLE_PLUGINS=__all__ PYTHONPATH="$RQ1_DEPS:." "$RQ1_PY" -S -m agentmembrane.host_v2.rq1_collab_v1.verification --output-dir experiments/host_boundary_v2/rq1_collab_v1/full_lifecycle_v3/test_verification_next
python3 -m agentmembrane.host_v2.rq1_collab_v1 native-validate --output-dir experiments/host_boundary_v2/rq1_collab_v1/full_lifecycle_v3/native_integration_next --source-root data/host_boundary_v2/upstream/agentdojo --native-python "$RQ1_PY"
```

The latter remains the legacy one-task command. For the current six-task campaign, use a NEW output directory:

```sh
PYDANTIC_DISABLE_PLUGINS=__all__ PYTHONPATH="$RQ1_DEPS:." "$RQ1_PY" -S -m agentmembrane.host_v2.rq1_collab_v1.six_sample \
  --output-dir experiments/host_boundary_v2/rq1_collab_v1/six_sample_pilot_20260907/pilots/native_run_next \
  --source-root data/host_boundary_v2/upstream/agentdojo \
  --native-python "$RQ1_PY" \
  --catalog-path experiments/host_boundary_v2/rq1_collab_v1/full_lifecycle_v3/native_qualification/run_004/task_catalog.json \
  --plan-path experiments/host_boundary_v2/rq1_collab_v1/six_sample_pilot_20260907/brief.md \
  --workers 3
```

The six-task run's exact input paths, hashes and parameters are in `six_sample_pilot_20260907/pilots/native_run_001/run-manifest.json`. Its 54 ENGINEERING conditions are not 54 independent research tasks. It calls no model. Every earlier verification attempt remains intact.

## Evidence and limitations

Current private evidence root (not tracked):
`experiments/host_boundary_v2/rq1_collab_v1/six_sample_pilot_20260907`

- pilots/test_verification_round3/result.json: 186/186 tests passed, zero skips, source/test hashes unchanged. Earlier round1 changed during execution and is not accepted as locked-version proof; round2 predates the last privacy fix.
- pilots/native_run_001/summary.json: 54/54 fixed conditions passed, H_ONLY 6/6, PLAIN 24/24, CAP 24/24; six original tasks, only two shared source worlds; 497.689 seconds; no failed or omitted conditions; model calls and behavioral samples both zero.
- reviews/evaluation/engineering/audit_artifacts.py: read-only physical evidence audit checks exact coverage, original initial states, qualification locks, original+strict scoring, real E-send/H-consume/H-input, closure/revocation/new-process persistence and all seals. No OS-isolation or semantic-completeness claim.
- reviews/evaluation/coverage/rq1_coverage.md: full RQ1 NOT_READY. COV-01 remains open: native calls do not yet produce trusted consumed-message attribution required for H-XAG scoring. Do not infer causal influence merely from temporal co-occurrence.
- All 54 union risks remain unknown (`null`), not zero. Normal scripted completion is not evidence of model capability, attack failure, monotonic risk, or A*.

Historical private evidence root (preserved locally, not tracked):
`experiments/host_boundary_v2/rq1_collab_v1/full_lifecycle_v3`

- test_verification_final/result.json: 129/129 passed, zero skips, no source changes during that run.
- native_integration_round2/summary.json: 9/9 real original-task conditions, identical initial worlds, native and strict utility, new-process persistence and revoked leases. Post-review stronger closing checks also passed on all nine sealed evidence packages.
- native_qualification/run_004: 97 tasks, 27 public goals, 96 original-reference successes; 97/97 restored/direct native scores agree. workspace/user_task_7 is quarantined for original tool/checker inconsistency.
- data_audit/run_002: original-source facts and exact blocked adapters.
- reviews/: non-author same-family independent code/counterexample checks. Not an external laboratory or human audit.

Formal admitted S=0, U=0; real model episodes=0. True three-domain containment/identity, complete primitive and information-flow observation, most task-purpose/strict profiles, reviewed task-goal admission, public full-lifecycle policy integration, broader U adapters/plan, fixed-clock/resource contracts and actual formal power/model protocol remain unresolved. A hash chain proves integrity relative to its anchor, not complete observation or security. Risk unknown must never become zero merely to obtain a curve.

Historical v3.2 design and all previous source/data/result namespaces are preserved.
