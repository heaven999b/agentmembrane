"""Regression tests for the narrowly scoped v5 finalization ref sanitizer."""

import copy
import json
from pathlib import Path
import tempfile
import unittest

from agentmembrane.host_v2.rq1_collab_v1.admission import TaskBundle
from agentmembrane.host_v2.rq1_collab_v1.audit import (
    EventCollector,
    canonical,
    strict_loads,
    verify,
)
from agentmembrane.host_v2.rq1_collab_v1.policy import compile_task_policy
from agentmembrane.host_v2.rq1_collab_v5.attack_spec import WORKSPACE_DELETE_GOAL
from agentmembrane.host_v2.rq1_collab_v5.contract import (
    NATIVE_PROFILE,
    clone,
    digest,
    make_config,
)
from agentmembrane.host_v2.rq1_collab_v5.evaluation import (
    read_evidence,
    validate_evidence,
)
from agentmembrane.host_v2.rq1_collab_v5.runtime import run_episode
from tests.rq1_collab_v1.test_runtime import NativeFixture, final, tool
from tests.rq1_collab_v3.test_runtime_evaluation import Script, delegate


INVALID_ACTION = "not a JSON action object"
SANITIZATION_POLICY = "host_finalization_drop_unauthorized_source_refs_v1"
ATTRIBUTION_STATUS = "dropped_refs_not_used_for_origin_attribution"


def send_message(content="continue", recipient="S"):
    return {"type": "send_message", "recipient": recipient, "content": content}


def with_invisible_ref(action):
    """Cite the real E authority snapshot, which is never delivered to actors."""

    def build(observation):
        value = copy.deepcopy(action)
        value["source_refs"] = [observation["episode_id"] + ":3"]
        return value

    return build


class RawAction(str):
    """A test-only marker for an exact, already serialized model response."""


class RawScript(Script):
    def next_action(self, actor, observation):
        self.seen[actor].append(clone(observation))
        value = self.steps[actor].pop(0) if self.steps[actor] else final(
            "No further action."
        )
        value = value(observation) if callable(value) else value
        return str(value) if isinstance(value, RawAction) else json.dumps(value)


class V5FinalizationReferenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rq1-v5-final-refs-")
        self.addCleanup(self.temp.cleanup)
        self.counter = 0

    def run_case(self, script, *, topology="H_E"):
        native = NativeFixture()
        native.state["calendar"]["events"]["unrelated"]["private_canary"] = (
            "NOT_PUBLIC_GOLD"
        )
        native.record.update(
            prompt_sha256=digest(native.prompt),
            tool_schema_sha256=digest(native.tool_specs),
            initial_state_sha256=digest(native.snapshot()),
        )
        payload = {
            "schema_version": "rq1-task-bundle/2",
            "protocol_version": "rq1-multifactor/2",
            "suite": "workspace",
            "original_id": "user_task_8",
            "source_record": clone(native.record),
            "task_policy": compile_task_policy(
                "workspace", "user_task_8", native.prompt
            ),
            "goal_admission": {"initial_goal_value": False},
            "public": {
                "user_request": native.prompt,
                "goal": {
                    "goal_id": "injection_task_1",
                    "goal": WORKSPACE_DELETE_GOAL,
                },
            },
        }
        bundle = TaskBundle(canonical(payload), digest(payload))
        cfg = make_config(
            bundle.sha256,
            "v5-final-ref-unit",
            topology,
            "high",
            "malicious",
            repeat=self.counter,
        )
        root = Path(self.temp.name) / str(self.counter)
        self.counter += 1
        collector = EventCollector(root, cfg["episode_id"])
        self.addCleanup(collector.abort)

        result = run_episode(
            cfg,
            bundle,
            native,
            script,
            collector,
            system_profile=NATIVE_PROFILE,
        )
        integrity = verify(
            collector.run_dir,
            expected_seal_hash=result["seal"]["seal_hash"],
        )
        self.assertTrue(integrity["ok"], integrity["errors"])
        data = read_evidence(collector.run_dir, result["seal"]["seal_hash"])
        return data, native, collector

    def test_finalization_final_drops_only_invisible_refs_and_keeps_content(self):
        submitted = {}
        final_content = "Host answer survives reference sanitization exactly."

        def final_with_mixed_refs(observation):
            self.assertTrue(observation["finalization_only"])
            visible_ref = observation["history"][-1]["event_id"]
            invisible_ref = observation["episode_id"] + ":3"
            self.assertNotIn(
                invisible_ref,
                [item.get("event_id") for item in observation["history"]],
            )
            submitted.update(
                visible_ref=visible_ref,
                invisible_ref=invisible_ref,
                action={
                    "type": "final",
                    "content": final_content,
                    "source_refs": [visible_ref, invisible_ref],
                },
            )
            return submitted["action"]

        script = Script(
            E=[INVALID_ACTION] * 3,
            H=[with_invisible_ref(final(final_content)) for _ in range(8)]
            + [final_with_mixed_refs],
        )
        data, native, collector = self.run_case(script)

        self.assertEqual(data["terminal_reason"], "host_final")
        self.assertEqual(data["closure_class"], "host_final")
        self.assertEqual(data["final_text"], final_content)
        self.assertTrue(data["phase_control"]["host_finalization_entered"])
        self.assertEqual(native.calls, [])
        self.assertEqual(data["native_calls"], [])
        self.assertEqual(data["messages"], [])
        self.assertEqual(data["delegations"], [])
        self.assertEqual(data["initial_snapshot"], data["terminal_snapshot"])

        decision = [row for row in data["decisions"] if row["actor"] == "H"][-1]
        host_decisions = [row for row in data["decisions"] if row["actor"] == "H"]
        self.assertEqual(
            [row["status"] for row in host_decisions],
            ["invalid_action"] * 8 + ["parsed"],
        )
        self.assertEqual(data["budget"]["actor_decisions_used"]["H"], 9)
        effective_action = {
            "type": "final",
            "content": final_content,
            "source_refs": [submitted["visible_ref"]],
        }
        self.assertEqual(decision["status"], "parsed")
        self.assertEqual(decision["submitted_action"], submitted["action"])
        self.assertEqual(decision["action"], effective_action)
        self.assertEqual(decision["source_refs"], [submitted["visible_ref"]])
        self.assertNotIn(submitted["invisible_ref"], decision["source_refs"])
        self.assertNotIn("E", decision["origin_actors"])

        sanitizations = data["runtime_trace"][
            "finalization_reference_sanitizations"
        ]
        self.assertEqual(len(sanitizations), 1)
        sanitized = sanitizations[0]
        self.assertEqual(
            set(sanitized),
            {
                "schema_version",
                "decision_event_id",
                "actor",
                "phase",
                "policy",
                "attribution_status",
                "original_source_refs",
                "effective_source_refs",
                "dropped_source_refs",
                "content_sha256",
                "event_id",
            },
        )
        self.assertEqual(sanitized["schema_version"], "rq1-finalization-reference-sanitization/1")
        self.assertEqual(sanitized["decision_event_id"], decision["event_id"])
        self.assertEqual(sanitized["actor"], "H")
        self.assertEqual(sanitized["phase"], "host_finalization")
        self.assertEqual(sanitized["policy"], SANITIZATION_POLICY)
        self.assertEqual(sanitized["attribution_status"], ATTRIBUTION_STATUS)
        self.assertEqual(
            sanitized["original_source_refs"],
            [submitted["visible_ref"], submitted["invisible_ref"]],
        )
        self.assertEqual(
            sanitized["effective_source_refs"], [submitted["visible_ref"]]
        )
        self.assertEqual(
            sanitized["dropped_source_refs"], [submitted["invisible_ref"]]
        )
        self.assertEqual(sanitized["content_sha256"], digest(final_content))
        self.assertEqual(
            decision["finalization_reference_sanitization"], sanitized
        )

        events = [
            strict_loads(line)
            for line in (collector.run_dir / "events.jsonl").read_bytes().splitlines()
        ]
        invisible_event = next(
            event
            for event in events
            if event["event_id"] == submitted["invisible_ref"]
        )
        self.assertEqual(invisible_event["actor"], "E")
        raw_sanitizations = [
            event
            for event in events
            if event["kind"] == "finalization_reference_sanitized"
        ]
        self.assertEqual(len(raw_sanitizations), 1)
        event = raw_sanitizations[0]
        self.assertEqual(event["event_id"], sanitized["event_id"])
        self.assertEqual(event["actor"], "H")
        self.assertEqual(event["parent_ids"], [decision["event_id"]])
        self.assertNotIn(submitted["invisible_ref"], event["parent_ids"])
        self.assertEqual(
            event["data"],
            {key: value for key, value in sanitized.items() if key != "event_id"},
        )
        validate_evidence(data)

        tampered_trace = copy.deepcopy(data)
        tampered_trace["runtime_trace"]["finalization_reference_sanitizations"][0][
            "content_sha256"
        ] = digest("different content")
        with self.assertRaises(ValueError):
            validate_evidence(tampered_trace)

        tampered_decision = copy.deepcopy(data)
        tampered_decision["decisions"][-1]["action"]["source_refs"].append(
            submitted["invisible_ref"]
        )
        with self.assertRaises(ValueError):
            validate_evidence(tampered_decision)

        for field in ("unexpected", "tool", "arguments"):
            with self.subTest(tampered_effective_action_field=field):
                forged = copy.deepcopy(data)
                forged["decisions"][-1]["action"][field] = (
                    {} if field == "arguments" else "forged"
                )
                with self.assertRaises(ValueError):
                    validate_evidence(forged)
            with self.subTest(tampered_submitted_action_field=field):
                forged = copy.deepcopy(data)
                forged["decisions"][-1]["submitted_action"][field] = (
                    {} if field == "arguments" else "forged"
                )
                with self.assertRaises(ValueError):
                    validate_evidence(forged)

        forged_post_final_decision = copy.deepcopy(data)
        trailing = copy.deepcopy(forged_post_final_decision["decisions"][0])
        trailing["event_id"] = data["episode_id"] + ":999991"
        forged_post_final_decision["decisions"].append(trailing)
        with self.assertRaises(ValueError):
            validate_evidence(forged_post_final_decision)

        forged_multiple_sanitizations = copy.deepcopy(data)
        extra_receipt = copy.deepcopy(
            forged_multiple_sanitizations["runtime_trace"]
            ["finalization_reference_sanitizations"][0]
        )
        extra_decision = copy.deepcopy(forged_multiple_sanitizations["decisions"][-1])
        extra_decision_id = data["episode_id"] + ":999992"
        extra_receipt["decision_event_id"] = extra_decision_id
        extra_receipt["event_id"] = data["episode_id"] + ":999993"
        extra_decision["event_id"] = extra_decision_id
        extra_decision["finalization_reference_sanitization"] = copy.deepcopy(
            extra_receipt
        )
        forged_multiple_sanitizations["decisions"].append(extra_decision)
        forged_multiple_sanitizations["runtime_trace"][
            "finalization_reference_sanitizations"
        ].append(extra_receipt)
        with self.assertRaises(ValueError):
            validate_evidence(forged_multiple_sanitizations)

        def tamper_receipt(mutator):
            forged = copy.deepcopy(data)
            receipt = forged["runtime_trace"][
                "finalization_reference_sanitizations"
            ][0]
            mutator(receipt)
            marked = next(
                row
                for row in forged["decisions"]
                if row.get("event_id") == receipt["decision_event_id"]
            )
            marked["finalization_reference_sanitization"] = copy.deepcopy(
                receipt
            )
            return forged

        receipt_tampers = {
            "wrong_actor": lambda receipt: receipt.update(actor="E"),
            "wrong_phase": lambda receipt: receipt.update(phase="host_work"),
            "wrong_schema": lambda receipt: receipt.update(
                schema_version="rq1-finalization-reference-sanitization/999"
            ),
            "empty_dropped_partition": lambda receipt: receipt.update(
                dropped_source_refs=[]
            ),
            "overlapping_partition": lambda receipt: receipt.update(
                effective_source_refs=receipt["original_source_refs"]
            ),
            "wrong_attribution_status": lambda receipt: receipt.update(
                attribution_status="dropped_refs_used"
            ),
        }
        for label, mutator in receipt_tampers.items():
            with self.subTest(tamper=label), self.assertRaises(ValueError):
                validate_evidence(tamper_receipt(mutator))

        wrong_final_text = copy.deepcopy(data)
        wrong_final_text["final_text"] = "different controller final text"
        with self.assertRaises(ValueError):
            validate_evidence(wrong_final_text)

        forged_null_final = copy.deepcopy(data)
        forged_null_final["decisions"][-1]["action"] = None
        forged_null_final["decisions"][-1]["submitted_action"] = None
        forged_null_final["final_text"] = None
        null_receipt = forged_null_final["runtime_trace"][
            "finalization_reference_sanitizations"
        ][0]
        null_receipt["content_sha256"] = digest(None)
        forged_null_final["decisions"][-1][
            "finalization_reference_sanitization"
        ] = copy.deepcopy(null_receipt)
        with self.assertRaises(ValueError):
            validate_evidence(forged_null_final)

        forged_too_many_refs = copy.deepcopy(data)
        too_many_refs = [f"forged-ref-{index}" for index in range(65)]
        many_receipt = forged_too_many_refs["runtime_trace"][
            "finalization_reference_sanitizations"
        ][0]
        many_receipt["original_source_refs"] = too_many_refs
        many_receipt["effective_source_refs"] = []
        many_receipt["dropped_source_refs"] = too_many_refs
        many_decision = forged_too_many_refs["decisions"][-1]
        many_decision["action"].pop("source_refs")
        many_decision["source_refs"] = []
        many_decision["submitted_action"]["source_refs"] = too_many_refs
        many_decision["finalization_reference_sanitization"] = copy.deepcopy(
            many_receipt
        )
        with self.assertRaises(ValueError):
            validate_evidence(forged_too_many_refs)

        forged_oversized_content = copy.deepcopy(data)
        oversized_content = "x" * 32001
        oversized_decision = forged_oversized_content["decisions"][-1]
        oversized_decision["action"]["content"] = oversized_content
        oversized_decision["submitted_action"]["content"] = oversized_content
        forged_oversized_content["final_text"] = oversized_content
        oversized_receipt = forged_oversized_content["runtime_trace"][
            "finalization_reference_sanitizations"
        ][0]
        oversized_receipt["content_sha256"] = digest(oversized_content)
        oversized_decision["finalization_reference_sanitization"] = copy.deepcopy(
            oversized_receipt
        )
        with self.assertRaises(ValueError):
            validate_evidence(forged_oversized_content)

    def test_bad_refs_remain_invalid_for_every_action_outside_finalization(self):
        bad_actions = [
            final("premature final must not be accepted"),
            tool("get_current_day"),
            send_message("must not be delivered"),
            delegate(to="S", tools=("get_current_day",)),
        ]
        script = Script(
            E=[INVALID_ACTION] * 3,
            H=[with_invisible_ref(action) for action in bad_actions]
            + [final("ordinary host final")],
        )
        data, native, _ = self.run_case(script, topology="H_S_E")

        host_decisions = [row for row in data["decisions"] if row["actor"] == "H"]
        self.assertEqual(
            [row["status"] for row in host_decisions],
            ["invalid_action"] * 4 + ["parsed"],
        )
        self.assertEqual(data["terminal_reason"], "host_final")
        self.assertFalse(data["phase_control"]["host_finalization_entered"])
        self.assertEqual(data["final_text"], "ordinary host final")
        self.assertEqual(native.calls, [])
        self.assertEqual(data["native_calls"], [])
        self.assertEqual(data["messages"], [])
        self.assertEqual(data["delegations"], [])
        self.assertFalse(data["internal_worker_used"])
        self.assertEqual(
            data["runtime_trace"].get("finalization_reference_sanitizations", []),
            [],
        )

    def test_finalization_does_not_sanitize_bad_refs_on_nonfinal_actions(self):
        actions = {
            "tool": tool("get_current_day"),
            "send_message": send_message("must not be delivered"),
            "delegate": delegate(to="S", tools=("get_current_day",)),
        }
        for label, action in actions.items():
            with self.subTest(action_type=label):
                script = Script(
                    E=[INVALID_ACTION] * 3,
                    H=[INVALID_ACTION] * 8 + [with_invisible_ref(action)],
                )
                data, native, _ = self.run_case(script, topology="H_S_E")

                final_observation = script.seen["H"][-1]
                self.assertTrue(final_observation["finalization_only"])
                decision = [
                    row for row in data["decisions"] if row["actor"] == "H"
                ][-1]
                self.assertEqual(decision["status"], "invalid_action")
                self.assertNotIn("submitted_action", decision)
                self.assertEqual(
                    data["terminal_reason"], "host_finalization_exhausted"
                )
                self.assertEqual(data["closure_class"], "sealed_incomplete")
                self.assertEqual(native.calls, [])
                self.assertEqual(data["native_calls"], [])
                self.assertEqual(data["messages"], [])
                self.assertEqual(data["delegations"], [])
                self.assertEqual(
                    data["runtime_trace"].get(
                        "finalization_reference_sanitizations", []
                    ),
                    [],
                )

    def test_external_and_internal_workers_never_receive_final_sanitization(self):
        external = Script(
            E=[with_invisible_ref(final("external bad-ref final"))]
            + [INVALID_ACTION] * 2,
            H=[final("host completed after E rejection")],
        )
        external_data, _, _ = self.run_case(external)
        external_decision = next(
            row for row in external_data["decisions"] if row["actor"] == "E"
        )
        self.assertEqual(external_decision["status"], "invalid_action")
        self.assertEqual(external_data["terminal_reason"], "host_final")
        self.assertEqual(
            external_data["runtime_trace"].get(
                "finalization_reference_sanitizations", []
            ),
            [],
        )

        internal = Script(
            E=[INVALID_ACTION] * 3,
            H=[
                delegate(to="S", tools=()),
                final("host completed after S rejection"),
            ],
            S=[
                with_invisible_ref(final("internal bad-ref final")),
                final("internal worker handed back normally"),
            ],
        )
        internal_data, _, _ = self.run_case(internal, topology="H_S_E")
        internal_decision = next(
            row for row in internal_data["decisions"] if row["actor"] == "S"
        )
        self.assertEqual(internal_decision["status"], "invalid_action")
        self.assertEqual(internal_data["terminal_reason"], "host_final")
        self.assertEqual(
            internal_data["runtime_trace"].get(
                "finalization_reference_sanitizations", []
            ),
            [],
        )

    def test_malformed_finalization_actions_are_not_repaired_by_sanitizer(self):
        malformed = {
            "malformed_json": RawAction(
                '{"type":"final","content":"unterminated","source_refs":['
            ),
            "extra_field": {
                "type": "final",
                "content": "extra field",
                "source_refs": ["invisible"],
                "unexpected": True,
            },
            "duplicate_refs": {
                "type": "final",
                "content": "duplicate refs",
                "source_refs": ["same", "same"],
            },
            "non_string_ref": {
                "type": "final",
                "content": "non-string ref",
                "source_refs": [7],
            },
            "too_many_refs": {
                "type": "final",
                "content": "too many refs",
                "source_refs": [f"ref-{index}" for index in range(65)],
            },
        }
        for label, bad_action in malformed.items():
            with self.subTest(malformed=label):
                script = RawScript(
                    E=[INVALID_ACTION] * 3,
                    H=[INVALID_ACTION] * 8 + [bad_action],
                )
                data, native, _ = self.run_case(script)

                final_observation = script.seen["H"][-1]
                self.assertTrue(final_observation["finalization_only"])
                decision = [
                    row for row in data["decisions"] if row["actor"] == "H"
                ][-1]
                self.assertEqual(decision["status"], "invalid_action")
                self.assertNotIn("submitted_action", decision)
                self.assertEqual(
                    data["terminal_reason"], "host_finalization_exhausted"
                )
                self.assertEqual(native.calls, [])
                self.assertEqual(
                    data["runtime_trace"].get(
                        "finalization_reference_sanitizations", []
                    ),
                    [],
                )

    def test_visible_finalization_refs_need_no_sanitization_record(self):
        submitted = {}

        def final_with_visible_ref(observation):
            visible_ref = observation["history"][-1]["event_id"]
            submitted["action"] = {
                "type": "final",
                "content": "final with an already visible reference",
                "source_refs": [visible_ref],
            }
            return submitted["action"]

        script = Script(
            E=[INVALID_ACTION] * 3,
            H=[INVALID_ACTION] * 8 + [final_with_visible_ref],
        )
        data, _, _ = self.run_case(script)

        decision = [row for row in data["decisions"] if row["actor"] == "H"][-1]
        self.assertEqual(data["terminal_reason"], "host_final")
        self.assertEqual(decision["action"], submitted["action"])
        self.assertEqual(
            decision["source_refs"], submitted["action"]["source_refs"]
        )
        self.assertNotIn("submitted_action", decision)
        self.assertEqual(
            data["runtime_trace"].get("finalization_reference_sanitizations", []),
            [],
        )


if __name__ == "__main__":
    unittest.main()
