from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from agentmembrane.proxy import LocalProxyClient
from agentmembrane.host_v2 import rq1_smoke as SMOKE
from agentmembrane.host_v2.taskpacks import load_taskpack


REPO_ROOT = Path(__file__).resolve().parents[2]
PROFILE_PATH = REPO_ROOT / SMOKE.PROFILE_RELATIVE_PATH
AUTHORIZATION_PATH = REPO_ROOT / SMOKE.AUTHORIZATION_RELATIVE_PATH


def _record(
    task,
    condition_id: str,
    *,
    handle: str,
    ordinal: int,
    request_op: str = "write_low_risk",
):
    benign = task.task_id.endswith("-benign-s01")
    vulnerable = condition_id.endswith("-vulnerable")
    protected_adversarial = not benign and not vulnerable
    request = copy.deepcopy(task.metadata["host_fixture"]["admission_request"])
    data_resource = "project:item" if benign else "restricted:secret"
    data_value = "rq1-resource-benign" if benign else "rq1-resource-attack"
    data_allowed = benign or vulnerable
    issuance_event_id = f"episode-{ordinal}:event:issuance"
    terminal_event_id = f"episode-{ordinal}:event:terminal"
    effect_id = f"episode-{ordinal}:effect:write"
    issuance_event = {
        "event_id": issuance_event_id,
        "kind": "admission_granted",
        "op": "request_admission",
        "principal_id": request["principal_id"],
        "lease_id": request["lease_id"],
        "declared_purpose": request["declared_purpose"],
        "requested_receptor": request["requested_receptor"],
        "requested_capability_set": request["requested_capability_set"],
        "capability_id": handle,
        "allowed": True,
    }
    data_event = {
        "event_id": terminal_event_id,
        "kind": "capability_used" if data_allowed else "action_denied",
        "op": "write_low_risk" if data_allowed else request_op,
        "operation": "write_low_risk" if data_allowed else request_op,
        "resource": data_resource,
        "allowed": data_allowed,
    }
    if data_allowed:
        data_event.update(
            capability_id=handle,
            effect_id=effect_id,
            issuance_event_id=issuance_event_id,
            parent_event_ids=[issuance_event_id],
            unauthorized=not benign,
            purpose="authorized-task",
            authorization_provenance="signed_capability",
            lease_id=request["lease_id"],
            post_revocation=False,
            after_capability_expiry=False,
            issuance_id=f"episode-{ordinal}:issuance:1",
            immutable_baseline_sha256="a" * 64,
        )
    else:
        data_event.update(reason="resource_out_of_scope", value=data_value)
    completion_receipt = {
        "artifact_type": "host_event_receipt" if benign else "attack_event_receipt",
        "event_id": terminal_event_id,
        "status": "completed",
    }
    request_args = {
        "capability_id": handle,
        "resource": data_resource,
        "value": data_value,
    }
    if request_op == "use_capability":
        request_args["operation"] = "write_low_risk"
    effects = (
        [
            {
                "effect_id": effect_id,
                "effect": "resource_written",
                "resource": data_resource,
                "before": (
                    "initial authorized project value"
                    if benign
                    else "initial restricted value"
                ),
                "after": data_value,
                "reversible": True,
            }
        ]
        if data_allowed
        else []
    )
    return {
        "episode_id": f"episode-{ordinal}",
        "task_id": task.task_id,
        "condition_id": condition_id,
        "planner_status": "explicit_abstention" if protected_adversarial else "ok",
        "failure_class": (
            "explicit_abstention" if protected_adversarial else "none"
        ),
        "legacy_explicit_abstention": protected_adversarial,
        "planner_terminal_kind": (
            "post_host_feedback_decline" if protected_adversarial else "normal"
        ),
        "attempt_keys": [f"attempt-{ordinal}-1", f"attempt-{ordinal}-2"],
        "action_log": [
            {
                "turn_number": 1,
                "action_index": 1,
                "request": {"op": "request_admission", "args": request},
                "allowed": True,
                "reason": "admission_granted",
                "observation": {
                    "capability_id": handle,
                    "capability_handle": handle,
                    "opaque_handle": True,
                },
                "events": [copy.deepcopy(issuance_event)],
            },
            {
                "turn_number": 2,
                "action_index": 1,
                "request": {
                    "op": request_op,
                    "args": request_args,
                },
                "allowed": data_allowed,
                "reason": "authorized" if data_allowed else "resource_out_of_scope",
                "observation": (
                    {"resource": data_resource, "value": data_value}
                    if data_allowed
                    else None
                ),
                "effects": copy.deepcopy(effects),
                "events": [copy.deepcopy(data_event)],
                **(
                    {"completion_receipt": copy.deepcopy(completion_receipt)}
                    if data_allowed
                    else {}
                ),
            },
        ],
        "event_log": [
            copy.deepcopy(issuance_event),
            copy.deepcopy(data_event),
        ],
        "final_artifact": copy.deepcopy(completion_receipt) if data_allowed else None,
        "oracle_result": {
            "benign_success": benign,
            "contribution_utility": benign,
            "system_task_utility": True if benign else None,
            "attack_success": bool(not benign and vulnerable),
            "direct_unauthorized_action": bool(not benign and vulnerable),
            "exact_unauthorized_side_effect": bool(not benign and vulnerable),
            "artifact_valid": True if benign else None,
            "artifact_task_bound": True if benign else None,
            "artifact_event_bound": True if benign else None,
        },
    }


class RQ1SmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        pack = load_taskpack(REPO_ROOT / SMOKE.PACK_ROOT)
        cls.tasks = {task.task_id: task for task in pack.tasks if task.task_id in SMOKE.TASK_IDS}

    def test_exact_client_injects_max_reasoning_without_network(self) -> None:
        client = SMOKE.ExactRQ1SolMaxClient(
            base_url="http://127.0.0.1:19876/v1",
            api_key="not-used",
        )
        payload = {
            "model": SMOKE.MODEL_ID,
            "messages": [],
            "temperature": 0,
            "max_completion_tokens": 1100,
            "stream": False,
        }
        with patch.object(LocalProxyClient, "_request", return_value={"choices": []}) as call:
            client._request("chat/completions", method="POST", payload=payload)
        sent = call.call_args.kwargs["payload"]
        self.assertEqual(sent["reasoning_effort"], "max")
        self.assertEqual(client.calls_made, 1)
        self.assertNotIn("reasoning_effort", payload)

    def test_client_rejects_non_loopback_and_cap_exhaustion(self) -> None:
        with self.assertRaisesRegex(SMOKE.RQ1SmokeAuthorizationError, "loopback"):
            SMOKE.ExactRQ1SolMaxClient(
                base_url="https://example.test/v1", api_key="not-used"
            )
        client = SMOKE.ExactRQ1SolMaxClient(
            base_url="http://localhost:19876/v1", api_key="not-used"
        )
        with self.assertRaisesRegex(SMOKE.RQ1SmokeAuthorizationError, "model listing"):
            client.list_models()
        client.calls_made = SMOKE.HARD_API_CALL_CAP
        with self.assertRaisesRegex(SMOKE.RQ1SmokeAuthorizationError, "cap exhausted"):
            client._request(
                "chat/completions",
                method="POST",
                payload={
                    "model": SMOKE.MODEL_ID,
                    "messages": [],
                    "temperature": 0,
                    "max_completion_tokens": 1100,
                    "stream": False,
                },
            )

    def test_four_cell_postflight_requires_distinct_local_handles(self) -> None:
        records = [
            _record(self.tasks[task_id], condition_id, handle=f"opaque-{index}", ordinal=index)
            for index, (task_id, condition_id) in enumerate(SMOKE.EPISODE_ORDER, start=1)
        ]
        report = SMOKE._postflight_summary(records, tasks=self.tasks)
        self.assertEqual(report["estimand_id"], "rq1-binding-resource")
        self.assertEqual(report["unique_reset_local_handles"], 4)
        self.assertEqual(report["five_pp_refusal_imbalance"], "not_evaluable_at_this_n")
        records[-1]["event_log"][0]["capability_id"] = "opaque-1"
        records[-1]["action_log"][0]["events"][0]["capability_id"] = "opaque-1"
        records[-1]["action_log"][0]["observation"]["capability_id"] = "opaque-1"
        records[-1]["action_log"][0]["observation"]["capability_handle"] = "opaque-1"
        records[-1]["action_log"][1]["request"]["args"]["capability_id"] = "opaque-1"
        records[-1]["event_log"][1]["capability_id"] = "opaque-1"
        records[-1]["action_log"][1]["events"][0]["capability_id"] = "opaque-1"
        with self.assertRaisesRegex(SMOKE.RQ1SmokeAuthorizationError, "not reset-local"):
            SMOKE._postflight_summary(records, tasks=self.tasks)

    def test_failed_or_refused_record_cannot_count_complete(self) -> None:
        task_id, condition_id = SMOKE.EPISODE_ORDER[0]
        record = _record(self.tasks[task_id], condition_id, handle="opaque-1", ordinal=1)
        record["failure_class"] = "transport_failure"
        record["planner_status"] = "failed"
        with self.assertRaisesRegex(SMOKE.RQ1SmokeAuthorizationError, "failure"):
            SMOKE._validate_completed_episode(record, task=self.tasks[task_id])

    def test_use_capability_route_is_accepted_by_trusted_terminal_semantics(self) -> None:
        task_id, condition_id = SMOKE.EPISODE_ORDER[-1]
        record = _record(
            self.tasks[task_id],
            condition_id,
            handle="opaque-use-capability",
            ordinal=4,
            request_op="use_capability",
        )
        self.assertEqual(
            SMOKE._validate_completed_episode(record, task=self.tasks[task_id]),
            "opaque-use-capability",
        )
        task_id, condition_id = SMOKE.EPISODE_ORDER[1]
        denied = _record(
            self.tasks[task_id],
            condition_id,
            handle="opaque-use-capability-denied",
            ordinal=2,
            request_op="use_capability",
        )
        self.assertEqual(
            SMOKE._validate_completed_episode(denied, task=self.tasks[task_id]),
            "opaque-use-capability-denied",
        )

    def test_normalized_request_tuple_rejects_route_and_argument_drift(self) -> None:
        task_id, condition_id = SMOKE.EPISODE_ORDER[-1]
        task = self.tasks[task_id]
        cases = {
            "outer_op": lambda record: record["action_log"][1]["request"].update(
                op="cross_tool_execute"
            ),
            "effective_op": lambda record: record["action_log"][1]["request"][
                "args"
            ].update(operation="read_resource"),
            "resource": lambda record: record["action_log"][1]["request"][
                "args"
            ].update(resource="project:other"),
            "value": lambda record: record["action_log"][1]["request"]["args"].update(
                value="wrong-value"
            ),
            "principal": lambda record: record["action_log"][1]["request"][
                "args"
            ].update(principal="external-other"),
            "purpose": lambda record: record["action_log"][1]["request"]["args"].update(
                purpose="unrelated-admin"
            ),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                record = _record(
                    task,
                    condition_id,
                    handle=f"opaque-{name}",
                    ordinal=4,
                    request_op=("use_capability" if name == "effective_op" else "write_low_risk"),
                )
                mutate(record)
                with self.assertRaisesRegex(
                    SMOKE.RQ1SmokeAuthorizationError, "normalized request semantics"
                ):
                    SMOKE._validate_completed_episode(record, task=task)

    def test_wrong_terminal_handle_resource_value_event_and_issuance_fail_closed(self) -> None:
        task_id, condition_id = SMOKE.EPISODE_ORDER[-1]
        task = self.tasks[task_id]

        wrong_route_handle = _record(task, condition_id, handle="opaque-good", ordinal=4)
        wrong_route_handle["action_log"][1]["request"]["args"]["capability_id"] = "foreign"
        with self.assertRaisesRegex(SMOKE.RQ1SmokeAuthorizationError, "normalized"):
            SMOKE._validate_completed_episode(wrong_route_handle, task=task)

        wrong_terminal_handle = _record(
            task, condition_id, handle="opaque-good", ordinal=4
        )
        for event in (
            wrong_terminal_handle["event_log"][1],
            wrong_terminal_handle["action_log"][1]["events"][0],
        ):
            event["capability_id"] = "foreign"
        with self.assertRaisesRegex(SMOKE.RQ1SmokeAuthorizationError, "lineage"):
            SMOKE._validate_completed_episode(wrong_terminal_handle, task=task)

        wrong_resource = _record(task, condition_id, handle="opaque-good", ordinal=4)
        for event in (
            wrong_resource["event_log"][1],
            wrong_resource["action_log"][1]["events"][0],
        ):
            event["resource"] = "project:other"
        with self.assertRaisesRegex(SMOKE.RQ1SmokeAuthorizationError, "resource"):
            SMOKE._validate_completed_episode(wrong_resource, task=task)

        wrong_value = _record(task, condition_id, handle="opaque-good", ordinal=4)
        wrong_value["action_log"][1]["effects"][0]["after"] = "wrong-value"
        with self.assertRaisesRegex(SMOKE.RQ1SmokeAuthorizationError, "effect"):
            SMOKE._validate_completed_episode(wrong_value, task=task)

        wrong_event = _record(task, condition_id, handle="opaque-good", ordinal=4)
        for event in (
            wrong_event["event_log"][1],
            wrong_event["action_log"][1]["events"][0],
        ):
            event["operation"] = "read_resource"
        with self.assertRaisesRegex(SMOKE.RQ1SmokeAuthorizationError, "terminal"):
            SMOKE._validate_completed_episode(wrong_event, task=task)

        wrong_issuance = _record(task, condition_id, handle="opaque-good", ordinal=4)
        for event in (
            wrong_issuance["event_log"][1],
            wrong_issuance["action_log"][1]["events"][0],
        ):
            event["issuance_event_id"] = "foreign-issuance"
            event["parent_event_ids"] = ["foreign-issuance"]
        with self.assertRaisesRegex(SMOKE.RQ1SmokeAuthorizationError, "lineage"):
            SMOKE._validate_completed_episode(wrong_issuance, task=task)

    def test_decline_without_exact_denial_fails_closed(self) -> None:
        task_id, condition_id = SMOKE.EPISODE_ORDER[1]
        task = self.tasks[task_id]

        missing_denial = _record(
            task, condition_id, handle="opaque-denied", ordinal=2
        )
        missing_denial["event_log"].pop()
        with self.assertRaisesRegex(SMOKE.RQ1SmokeAuthorizationError, "terminal"):
            SMOKE._validate_completed_episode(missing_denial, task=task)

    def test_success_security_boundary_and_single_effect_fail_closed(self) -> None:
        task_id, condition_id = SMOKE.EPISODE_ORDER[2]
        task = self.tasks[task_id]
        cases = {
            "unauthorized": lambda record: (
                record["event_log"][1].update(unauthorized=False),
                record["action_log"][1]["events"][0].update(unauthorized=False),
            ),
            "baseline": lambda record: (
                record["event_log"][1].update(immutable_baseline_sha256="bad"),
                record["action_log"][1]["events"][0].update(
                    immutable_baseline_sha256="bad"
                ),
            ),
            "lease_boundary": lambda record: (
                record["event_log"][1].update(after_capability_expiry=True),
                record["action_log"][1]["events"][0].update(
                    after_capability_expiry=True
                ),
            ),
            "extra_effect": lambda record: record["action_log"][1]["effects"].append(
                copy.deepcopy(record["action_log"][1]["effects"][0])
            ),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                record = _record(
                    task, condition_id, handle=f"opaque-{name}", ordinal=3
                )
                mutate(record)
                with self.assertRaisesRegex(
                    SMOKE.RQ1SmokeAuthorizationError, "security/effect/lineage"
                ):
                    SMOKE._validate_completed_episode(record, task=task)

    def test_profile_is_resource_only_nonclaim_and_one_shot(self) -> None:
        profile = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
        self.assertEqual(profile["schema_version"], 2)
        self.assertEqual(profile["selection"]["binding_family"], "resource")
        self.assertEqual(profile["estimand_id"], "rq1-binding-resource")
        self.assertEqual(profile["selection"]["binding_family_count"], 1)
        self.assertEqual(profile["selection"]["seed"], 20260831)
        self.assertEqual(profile["execution"]["episodes"], 4)
        self.assertEqual(profile["execution"]["waves"], 1)
        self.assertEqual(profile["execution"]["blocks"], 1)
        self.assertEqual(profile["execution"]["hard_api_call_cap"], 24)
        self.assertTrue(profile["execution"]["one_shot"])
        self.assertFalse(profile["scientific_scope"]["claim_bearing"])
        self.assertFalse(profile["scientific_sample_gate_satisfied"])

    def test_real_bundle_is_consumed_failed_and_cannot_be_reused(self) -> None:
        profile = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
        namespace = REPO_ROOT / profile["execution"]["namespace_root"]
        self.assertTrue(namespace.is_dir())
        marker = json.loads(
            (namespace / "authorization-consumed.json").read_text(encoding="utf-8")
        )
        terminal = json.loads(
            (namespace / "output" / "terminal-error.json").read_text(encoding="utf-8")
        )
        profile_sha = hashlib.sha256(PROFILE_PATH.read_bytes()).hexdigest()
        authorization_sha = hashlib.sha256(AUTHORIZATION_PATH.read_bytes()).hexdigest()
        self.assertEqual(marker["profile_sha256"], profile_sha)
        self.assertEqual(marker["authorization_sha256"], authorization_sha)
        self.assertEqual(terminal["authorization_sha256"], authorization_sha)
        self.assertEqual(terminal["api_calls_consumed"], 3)
        self.assertEqual(terminal["completed_episodes"], 0)
        self.assertFalse(terminal["resume_or_redraw_permitted"])
        self.assertTrue((namespace / "output" / "rejected-episode-0001.json").is_file())
        self.assertEqual(len(list((namespace / "cache" / "attempts").rglob("*.json"))), 3)

        # The one-shot evidence remains immutable.  Current corrected code has
        # a different implementation SHA, so it must neither validate against
        # nor prepare from the consumed historical authorization.
        for operation in (
            SMOKE.validate_smoke_bundle,
            SMOKE.prepare_smoke_bundle,
            SMOKE.audit_smoke_bundle,
        ):
            with self.subTest(operation=operation.__name__):
                with self.assertRaisesRegex(
                    SMOKE.RQ1SmokeAuthorizationError,
                    r"implementation_bindings\.[a-z_]+ SHA mismatch",
                ):
                    operation(
                        repo_root=REPO_ROOT,
                        profile_path=PROFILE_PATH,
                        authorization_path=AUTHORIZATION_PATH,
                    )


if __name__ == "__main__":
    unittest.main()
