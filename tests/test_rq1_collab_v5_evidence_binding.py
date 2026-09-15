"""Regression coverage for v5 decision replay and raw-event bindings."""

import copy
import tempfile
import unittest

from agentmembrane.host_v2.rq1_collab_v1.audit import canonical, strict_loads
from agentmembrane.host_v2.rq1_collab_v5.contract import digest
from agentmembrane.host_v2.rq1_collab_v5.evaluation import validate_evidence
from agentmembrane.host_v2.rq1_collab_v5.runtime import parse_action
from tests.rq1_collab_v1.test_runtime import final
from tests.rq1_collab_v3.test_runtime_evaluation import Script
from tests import test_rq1_collab_v5_finalization_refs as final_ref_fixture


INVALID_ACTION = final_ref_fixture.INVALID_ACTION


def _events(collector):
    return [
        strict_loads(line)
        for line in (collector.run_dir / "events.jsonl").read_bytes().splitlines()
    ]


def _event(events, event_id):
    return next(row for row in events if row["event_id"] == event_id)


class V5EvidenceBindingTests(unittest.TestCase):
    """Use the finalization fixture without inheriting its test methods."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rq1-v5-evidence-binding-")
        self.addCleanup(self.temp.cleanup)
        self.counter = 0

    def run_case(self, script, *, topology="H_E"):
        return final_ref_fixture.V5FinalizationReferenceTests.run_case(
            self, script, topology=topology
        )

    def test_every_new_runtime_decision_has_replay_binding(self):
        script = Script(
            E=[INVALID_ACTION] * 3,
            H=[INVALID_ACTION, final("bound host answer")],
        )
        data, _, collector = self.run_case(script)
        events = _events(collector)

        self.assertGreaterEqual(len(data["decisions"]), 5)
        for decision in data["decisions"]:
            with self.subTest(event_id=decision["event_id"]):
                self.assertIs(type(decision.get("raw_action")), str)
                self.assertIs(type(decision.get("observation_sha256")), str)
                self.assertIs(type(decision.get("delivery_event_id")), str)
                self.assertEqual(
                    decision["raw_action"],
                    _event(events, decision["event_id"])["data"]["raw_action"],
                )
        validate_evidence(data, events=events)

    def test_raw_action_must_match_effective_or_submitted_action(self):
        ordinary, _, ordinary_collector = self.run_case(
            Script(E=[INVALID_ACTION] * 3, H=[final("ordinary")])
        )
        ordinary_events = _events(ordinary_collector)
        ordinary_final = ordinary["decisions"][-1]
        ordinary_final["raw_action"] = canonical(final("different")).decode("utf-8")
        with self.assertRaises(ValueError):
            validate_evidence(ordinary, events=ordinary_events)

        def hallucinated_ref(_observation):
            return {
                "type": "final",
                "content": "sanitized",
                "source_refs": ["hallucinated-ref-that-does-not-exist"],
            }

        sanitized, _, sanitized_collector = self.run_case(
            Script(
                E=[INVALID_ACTION] * 3,
                H=[INVALID_ACTION] * 8 + [hallucinated_ref],
            )
        )
        sanitized_events = _events(sanitized_collector)
        sanitized_final = sanitized["decisions"][-1]
        sanitized_final["submitted_action"]["content"] = "forged submitted"
        with self.assertRaises(ValueError):
            validate_evidence(sanitized, events=sanitized_events)

    def test_non_sanitized_action_schema_and_visibility_are_replayed(self):
        data, _, collector = self.run_case(
            Script(E=[INVALID_ACTION] * 3, H=[final("ordinary")])
        )
        events = _events(collector)

        extra = copy.deepcopy(data)
        final_decision = extra["decisions"][-1]
        final_decision["action"]["unexpected"] = True
        final_decision["raw_action"] = canonical(final_decision["action"]).decode(
            "utf-8"
        )
        with self.assertRaises(ValueError):
            validate_evidence(extra, events=events)

        nonexistent = copy.deepcopy(data)
        final_decision = nonexistent["decisions"][-1]
        final_decision["action"]["source_refs"] = ["never-delivered-ref"]
        final_decision["source_refs"] = ["never-delivered-ref"]
        final_decision["raw_action"] = canonical(final_decision["action"]).decode(
            "utf-8"
        )
        with self.assertRaises(ValueError):
            validate_evidence(nonexistent, events=events)

    def test_decision_delivery_visibility_swap_is_rejected(self):
        data, _, collector = self.run_case(
            Script(E=[INVALID_ACTION] * 3, H=[INVALID_ACTION, final("ordinary")])
        )
        events = _events(collector)
        host_decisions = [row for row in data["decisions"] if row["actor"] == "H"]
        self.assertEqual(len(host_decisions), 2)

        swapped = copy.deepcopy(data)
        swapped_host = [
            row for row in swapped["decisions"] if row["actor"] == "H"
        ]
        swapped_host[1]["delivery_event_id"] = swapped_host[0]["delivery_event_id"]
        swapped_host[1]["observation_sha256"] = swapped_host[0][
            "observation_sha256"
        ]
        with self.assertRaises(ValueError):
            validate_evidence(swapped, events=events)

    def _sanitized_evidence(self):
        def hallucinated_ref(_observation):
            return {
                "type": "final",
                "content": "safe answer from content only",
                "source_refs": ["hallucinated-ref-that-does-not-exist"],
            }

        data, native, collector = self.run_case(
            Script(
                E=[INVALID_ACTION] * 3,
                H=[INVALID_ACTION] * 8 + [hallucinated_ref],
            )
        )
        return data, native, _events(collector)

    def test_nonexistent_dropped_ref_is_safely_sanitized(self):
        data, native, events = self._sanitized_evidence()
        decision = data["decisions"][-1]
        receipt = decision["finalization_reference_sanitization"]

        self.assertEqual(data["terminal_reason"], "host_final")
        self.assertEqual(data["final_text"], "safe answer from content only")
        self.assertEqual(decision["action"], final("safe answer from content only"))
        self.assertEqual(decision["source_refs"], [])
        self.assertEqual(
            receipt["dropped_source_refs"],
            ["hallucinated-ref-that-does-not-exist"],
        )
        self.assertEqual(native.calls, [])
        validate_evidence(data, events=events)

    def test_sanitizer_raw_event_identity_and_payload_are_bound(self):
        data, _, events = self._sanitized_evidence()
        receipt = data["runtime_trace"]["finalization_reference_sanitizations"][0]
        sanitizer_index = next(
            index
            for index, row in enumerate(events)
            if row["event_id"] == receipt["event_id"]
        )
        decision_id = receipt["decision_event_id"]

        mutations = {
            "event_id_conflict": lambda rows: rows[sanitizer_index].update(
                event_id=decision_id
            ),
            "parent": lambda rows: rows[sanitizer_index].update(parent_ids=[]),
            "kind": lambda rows: rows[sanitizer_index].update(
                kind="actor_decision"
            ),
            "data": lambda rows: rows[sanitizer_index]["data"].update(
                policy="forged-policy"
            ),
            "sequence": lambda rows: rows[sanitizer_index].update(
                seq=rows[sanitizer_index]["seq"] + 1
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(tamper=label):
                forged_events = copy.deepcopy(events)
                mutate(forged_events)
                with self.assertRaises(ValueError):
                    validate_evidence(copy.deepcopy(data), events=forged_events)

    def test_finalization_observation_phase_and_tools_are_bound(self):
        data, _, events = self._sanitized_evidence()
        final_decision = data["decisions"][-1]
        delivery_id = final_decision["delivery_event_id"]

        for label, mutate_payload in {
            "phase": lambda payload: payload.update(controller_phase="host_work"),
            "tools": lambda payload: payload.update(available_tools=["delete_file"]),
        }.items():
            with self.subTest(tamper=label):
                forged = copy.deepcopy(data)
                forged_events = copy.deepcopy(events)
                delivery = next(
                    row for row in forged["deliveries"]
                    if row["event_id"] == delivery_id
                )
                mutate_payload(delivery["payload"])
                rebound_digest = digest(delivery["payload"])
                forged_final = next(
                    row for row in forged["decisions"]
                    if row["event_id"] == final_decision["event_id"]
                )
                forged_final["observation_sha256"] = rebound_digest
                raw_delivery = _event(forged_events, delivery_id)
                raw_delivery["data"]["payload"] = copy.deepcopy(delivery["payload"])
                raw_decision = _event(forged_events, final_decision["event_id"])
                raw_decision["data"]["observation_sha256"] = rebound_digest
                with self.assertRaises(ValueError):
                    validate_evidence(forged, events=forged_events)

    def test_history_visibility_requires_matching_raw_source_event(self):
        """A coordinated delivery rewrite cannot turn an arbitrary event visible."""
        data, _, collector = self.run_case(
            Script(E=[INVALID_ACTION] * 3, H=[final("ordinary")])
        )
        events = _events(collector)
        forged = copy.deepcopy(data)
        forged_events = copy.deepcopy(events)
        decision = forged["decisions"][-1]
        delivery = next(
            row for row in forged["deliveries"]
            if row["event_id"] == decision["delivery_event_id"]
        )
        unrelated = next(
            row for row in forged_events if row["kind"] == "episode_started"
        )
        fake_history_item = {
            "role": "observation",
            "event_id": unrelated["event_id"],
            "content": {"forged": True},
            "origin_actors": ["E"],
        }
        delivery["payload"]["history"].append(fake_history_item)
        raw_delivery = _event(forged_events, delivery["event_id"])
        raw_delivery["data"]["payload"] = copy.deepcopy(delivery["payload"])
        rebound_observation = digest(delivery["payload"])
        decision["observation_sha256"] = rebound_observation
        raw_decision = _event(forged_events, decision["event_id"])
        raw_decision["data"]["observation_sha256"] = rebound_observation
        forged_action = {
            "type": "final",
            "content": decision["action"]["content"],
            "source_refs": [unrelated["event_id"]],
        }
        forged_raw = canonical(forged_action).decode("utf-8")
        decision.update(
            action=forged_action,
            source_refs=[unrelated["event_id"]],
            origin_actors=["E"],
            raw_action=forged_raw,
        )
        raw_decision["data"]["raw_action"] = forged_raw

        with self.assertRaises(ValueError):
            validate_evidence(forged, events=forged_events)

    def test_true_external_origin_cannot_be_erased_across_bound_ledgers(self):
        """A real E handoff remains externally attributed after replay."""
        def host_final_from_external_handoff(observation):
            external_ref = next(
                item["event_id"] for item in observation["history"]
                if "E" in item.get("origin_actors", [])
            )
            return {
                "type": "final",
                "content": "host answer using the external handoff",
                "source_refs": [external_ref],
            }

        data, _, collector = self.run_case(
            Script(
                E=[final("external handoff")],
                H=[host_final_from_external_handoff],
            )
        )
        events = _events(collector)
        forged = copy.deepcopy(data)
        forged_events = copy.deepcopy(events)
        decision = next(
            row for row in forged["decisions"] if row["actor"] == "H"
        )
        self.assertEqual(decision["origin_actors"], ["E"])
        external_ref = decision["source_refs"][0]

        raw_source = _event(forged_events, external_ref)
        self.assertEqual(raw_source["kind"], "observation_queued")
        self.assertEqual(raw_source["data"]["origin_actors"], ["E"])
        raw_source["data"]["origin_actors"] = []

        delivery = next(
            row for row in forged["deliveries"]
            if row["event_id"] == decision["delivery_event_id"]
        )
        history_item = next(
            item for item in delivery["payload"]["history"]
            if item.get("event_id") == external_ref
        )
        history_item["origin_actors"] = []
        raw_delivery = _event(forged_events, delivery["event_id"])
        raw_delivery["data"]["payload"] = copy.deepcopy(delivery["payload"])
        rebound_observation = digest(delivery["payload"])
        decision["observation_sha256"] = rebound_observation
        _event(forged_events, decision["event_id"])["data"][
            "observation_sha256"
        ] = rebound_observation
        decision["origin_actors"] = []

        with self.assertRaises(ValueError):
            validate_evidence(forged, events=forged_events)

    def test_host_final_must_be_the_last_raw_decision(self):
        """A forged early host final cannot coexist with a later actor decision."""
        data, _, collector = self.run_case(
            Script(E=[INVALID_ACTION] * 3, H=[INVALID_ACTION, final("real")])
        )
        events = _events(collector)
        forged = copy.deepcopy(data)
        forged_events = copy.deepcopy(events)
        first, last = [row for row in forged["decisions"] if row["actor"] == "H"]

        forged_content = "forged premature terminal answer"
        forged_action = final(forged_content)
        forged_raw = canonical(forged_action).decode("utf-8")
        first.update(
            status="parsed",
            action=forged_action,
            source_refs=[],
            origin_actors=[],
            raw_action=forged_raw,
        )
        _event(forged_events, first["event_id"])["data"]["raw_action"] = forged_raw

        invalid_last = {
            key: last[key]
            for key in (
                "event_id", "actor", "observation_sha256", "delivery_event_id"
            )
        }
        invalid_last.update(status="invalid_action", raw_action=INVALID_ACTION)
        last.clear()
        last.update(invalid_last)
        _event(forged_events, last["event_id"])["data"][
            "raw_action"
        ] = INVALID_ACTION
        forged["final_text"] = forged_content

        with self.assertRaises(ValueError):
            validate_evidence(forged, events=forged_events)

    def test_all_three_valid_host_final_paths_remain_accepted(self):
        host_work, _, host_work_collector = self.run_case(
            Script(E=[INVALID_ACTION] * 3, H=[final("host-work final")])
        )
        self.assertFalse(host_work["phase_control"]["host_finalization_entered"])
        validate_evidence(host_work, events=_events(host_work_collector))

        finalization, _, finalization_collector = self.run_case(
            Script(
                E=[INVALID_ACTION] * 3,
                H=[INVALID_ACTION] * 8 + [final("unsanitized finalization final")],
            )
        )
        self.assertTrue(finalization["phase_control"]["host_finalization_entered"])
        self.assertEqual(
            finalization["runtime_trace"][
                "finalization_reference_sanitizations"
            ],
            [],
        )
        validate_evidence(finalization, events=_events(finalization_collector))

        sanitized, _, sanitized_events = self._sanitized_evidence()
        self.assertTrue(
            sanitized["runtime_trace"]["finalization_reference_sanitizations"]
        )
        validate_evidence(sanitized, events=sanitized_events)


class V5ActionParserHardeningTests(unittest.TestCase):
    def test_source_refs_reject_empty_and_overlong_values(self):
        for ref in ("", "r" * 257):
            with self.subTest(length=len(ref)), self.assertRaises(ValueError):
                parse_action(
                    canonical(
                        {
                            "type": "final",
                            "content": "answer",
                            "source_refs": [ref],
                        }
                    )
                )

    def test_malformed_argument_refs_are_rejected(self):
        read_event_id = "episode:7"
        valid_ref = {
            "record_id": "record-1",
            "version": 1,
            "field_pointer": "/email",
            "read_event_id": read_event_id,
            "projected_value_sha256": "a" * 64,
        }
        base = {
            "type": "tool_action",
            "tool": "send_email",
            "arguments": {"subject": "hello"},
            "source_refs": [read_event_id],
            "argument_refs": {"/email": valid_ref},
        }
        malformed = {
            "array_not_mapping": [valid_ref],
            "destination_not_pointer": {"email": valid_ref},
            "destination_already_literal": {
                "/subject": {**valid_ref, "field_pointer": "/subject"}
            },
            "read_not_visible": {
                "/email": {**valid_ref, "read_event_id": "episode:99"}
            },
            "bad_digest": {
                "/email": {**valid_ref, "projected_value_sha256": "not-a-digest"}
            },
            "malformed_pointer_escape": {
                "/email": {**valid_ref, "field_pointer": "/bad~2pointer"}
            },
            "missing_field": {
                "/email": {
                    key: value
                    for key, value in valid_ref.items()
                    if key != "record_id"
                }
            },
        }
        for label, argument_refs in malformed.items():
            with self.subTest(malformed=label), self.assertRaises(ValueError):
                action = copy.deepcopy(base)
                action["argument_refs"] = argument_refs
                parse_action(canonical(action))

    def test_valid_argument_refs_are_accepted_exactly(self):
        action = {
            "type": "tool_action",
            "tool": "send_email",
            "arguments": {"subject": "hello"},
            "source_refs": ["episode:7"],
            "argument_refs": {
                "/email": {
                    "record_id": "record-1",
                    "version": 1,
                    "field_pointer": "/email",
                    "read_event_id": "episode:7",
                    "projected_value_sha256": "a" * 64,
                }
            },
        }
        self.assertEqual(parse_action(canonical(action)), action)


if __name__ == "__main__":
    unittest.main()
