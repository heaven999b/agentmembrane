from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest
from typing import Any

from agentmembrane.host_v2.cache import CacheIdentity, RunCache
from agentmembrane.host_v2.conditions import build_admission_ladder
from agentmembrane.host_v2.host import ActionRequest
from agentmembrane.host_v2.planner import (
    ModelPlanner,
    PlannerParseError,
    PlannerSchemaError,
    PlannerTurn,
    ScriptedPlanner,
    _resolve_profile_ref,
    classify_provider_error,
    parse_planner_response,
)
from agentmembrane.host_v2.profiles import ResolvedProfile
from agentmembrane.host_v2.schema import (
    FailureClass,
    IntegrityError,
    SchemaError,
    TaskOrigin,
)
from agentmembrane.host_v2.taskpacks import TaskSpec
from agentmembrane.proxy import Completion, ProxyError


_IMPLEMENTATION = "1" * 64
_PROTOCOL = "2" * 64
_MODEL = "gpt-exact-test"
_ROUTE = "local-cli-proxy"
_SCHEDULE_EPISODE = "e" * 64
_VALID_RESPONSE = json.dumps(
    {
        "strategy": "use the public operation once",
        "actions": [{"op": "read_resource", "args": {"resource": "public"}}],
        "final_artifact": None,
    }
)
_COMPLETE_RESPONSE = json.dumps(
    {
        "strategy": "complete with a task receipt",
        "actions": [],
        "final_artifact": {"status": "done", "receipt": "event-1"},
    }
)


def _runtime() -> dict[str, Any]:
    return {
        "schema_version": 2,
        "operations": [
            {
                "name": "read_resource",
                "argument_schema": {
                    "type": "object",
                    "required": ["resource"],
                    "properties": {"resource": {"type": "string"}},
                    "additionalProperties": False,
                },
            }
        ],
        "resource_handles": ["public"],
        "capability_handles": [],
        "record_handles": [],
        "proposal_handles": [],
        "message_handles": [],
        "scheduled_task_handles": [],
        "child_handles": [],
    }


def _completion(text: str, *, model: str = _MODEL) -> Completion:
    return Completion(
        text=text,
        model=model,
        latency_ms=17,
        input_tokens=11,
        output_tokens=7,
        total_tokens=18,
    )


class FakeProxyClient:
    """Strict fake: every call consumes exactly one predeclared result."""

    def __init__(self, outcomes: list[Completion | BaseException]) -> None:
        self.outcomes = list(outcomes)
        self.calls: list[dict[str, Any]] = []

    def complete(
        self,
        *,
        model: str,
        system: str,
        user: str,
        max_completion_tokens: int,
        retries: int,
        reasoning_effort: str | None = None,
    ) -> Completion:
        self.calls.append(
            {
                "model": model,
                "system": system,
                "user": user,
                "max_completion_tokens": max_completion_tokens,
                "retries": retries,
                "reasoning_effort": reasoning_effort,
            }
        )
        if not self.outcomes:
            raise AssertionError("unexpected provider call")
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def _task(*, role: str = "adversarial", metadata: dict[str, Any] | None = None) -> TaskSpec:
    task_metadata: dict[str, Any] = {"schedule_episode_id": _SCHEDULE_EPISODE}
    task_metadata.update(metadata or {})
    return TaskSpec(
        task_id=f"task-{role}",
        cluster_id="cluster-1",
        domain_id="test-domain",
        origin=TaskOrigin.AUTHORED_SYNTHETIC,
        split="gate",
        pair_id="pair-1",
        pair_role=role,
        family="test-family",
        surface_task="Read the public test resource.",
        authorized_test_objective=(
            "Exercise the resettable mock boundary." if role == "adversarial" else None
        ),
        fixture_ref="fixture.json",
        oracle_ref="hidden-oracle",
        metadata=task_metadata,
    )


class PlannerParserTests(unittest.TestCase):
    def test_accepts_one_exact_object_or_one_complete_fence(self) -> None:
        expected = json.loads(_VALID_RESPONSE)
        self.assertEqual(parse_planner_response(_VALID_RESPONSE), expected)
        self.assertEqual(
            parse_planner_response(f"```json\n{_VALID_RESPONSE}\n```"),
            expected,
        )

    def test_rejects_non_single_or_nonstandard_json(self) -> None:
        malformed = (
            "",
            "not json",
            f"prose {_VALID_RESPONSE}",
            f"{_VALID_RESPONSE} trailing",
            f"{_VALID_RESPONSE} {_VALID_RESPONSE}",
            f"```json\n{_VALID_RESPONSE}\n```\nprose",
            '{"strategy":null,"strategy":"again","actions":[],"final_artifact":null}',
            '{"strategy":null,"actions":[],"final_artifact":{"number":NaN}}',
        )
        for response in malformed:
            with self.subTest(response=response):
                with self.assertRaises(PlannerParseError):
                    parse_planner_response(response)

    def test_rejects_schema_drift_and_never_truncates_actions(self) -> None:
        invalid_values = (
            [],
            {"strategy": None, "actions": []},
            {
                "strategy": None,
                "actions": [],
                "final_artifact": None,
                "extra": True,
            },
            {"strategy": "", "actions": [], "final_artifact": None},
            {"strategy": None, "actions": {}, "final_artifact": None},
            {
                "strategy": None,
                "actions": [
                    {"op": "first", "args": {}},
                    {"op": "second", "args": {}},
                ],
                "final_artifact": None,
            },
            {
                "strategy": None,
                "actions": [{"op": "", "args": {}}],
                "final_artifact": None,
            },
            {
                "strategy": "act and finish",
                "actions": [{"op": "read", "args": {}}],
                "final_artifact": {"status": "done"},
            },
            {
                "strategy": None,
                "actions": [{"op": "read", "args": [], "extra": 1}],
                "final_artifact": None,
            },
            {"strategy": None, "actions": [], "final_artifact": []},
            {
                "strategy": "declined:",
                "actions": [],
                "final_artifact": None,
            },
            {
                "strategy": "declined: reason",
                "actions": [{"op": "read", "args": {}}],
                "final_artifact": None,
            },
        )
        for value in invalid_values:
            with self.subTest(value=value):
                with self.assertRaises(PlannerSchemaError):
                    parse_planner_response(json.dumps(value))

    def test_rejects_json_that_cannot_be_frozen_as_utf8(self) -> None:
        response = '{"strategy":null,"actions":[],"final_artifact":{"bad":"\\ud800"}}'
        with self.assertRaises(PlannerSchemaError):
            parse_planner_response(response)


class PlannerValueTests(unittest.TestCase):
    def test_prompt_ref_resolution_allows_contained_parent_and_rejects_symlink_escape(self) -> None:
        source = Path(
            "experiments/host_boundary_v2/config/profiles/rq2-g0-gate.template.json"
        ).resolve()
        self.assertEqual(
            _resolve_profile_ref(
                source,
                "../prompts/attacker-primary.txt",
                label="attacker",
            ),
            Path("experiments/host_boundary_v2/config/prompts/attacker-primary.txt").resolve(),
        )
        with self.assertRaisesRegex(IntegrityError, "escapes"):
            _resolve_profile_ref(
                source,
                "../../../../../../../../etc/passwd",
                label="attacker",
            )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = root / "profile.json"
            profile.write_text("{}", encoding="utf-8")
            (root / "outside").symlink_to(root.parent, target_is_directory=True)
            with self.assertRaisesRegex(IntegrityError, "escapes"):
                _resolve_profile_ref(
                    profile, "outside/prompt.txt", label="attacker"
                )

    def test_turn_enforces_one_action_and_distinct_abstention_state(self) -> None:
        action = ActionRequest(op="read_resource", args={})
        with self.assertRaises(SchemaError):
            PlannerTurn(
                request_key="request",
                actions=(action, action),
                final_artifact=None,
                strategy=None,
                status="ok",
                explicit_abstention=False,
                failure_class=FailureClass.NONE,
                terminal_error=None,
                attempt_keys=(),
            )
        with self.assertRaises(SchemaError):
            ScriptedPlanner({}).plan_turn(
                task=_task(),
                condition=build_admission_ladder()[0],
                turn_number=1,
                feedback=(),
                runtime_interface=_runtime(),
                max_actions=1.0,  # type: ignore[arg-type]
            )
        with self.assertRaises(SchemaError):
            PlannerTurn(
                request_key="request",
                actions=(),
                final_artifact=None,
                strategy="declined: no",
                status="ok",
                explicit_abstention=True,
                failure_class=FailureClass.NONE,
                terminal_error=None,
                attempt_keys=(),
            )

    def test_error_classification_is_stable_and_separate(self) -> None:
        cases = (
            (ProxyError("proxy_http_503"), FailureClass.TRANSPORT),
            (
                ProxyError("proxy_http_400", upstream_code="content_filter"),
                FailureClass.PROVIDER_POLICY,
            ),
            (ProxyError("empty_completion"), FailureClass.PARSE),
            (PlannerParseError("bad json"), FailureClass.PARSE),
            (PlannerSchemaError("bad fields"), FailureClass.SCHEMA),
            (SchemaError("bad schema"), FailureClass.SCHEMA),
            (ProxyError("proxy_http_400"), FailureClass.OTHER),
            (RuntimeError("unexpected"), FailureClass.OTHER),
        )
        for error, expected in cases:
            with self.subTest(error=error):
                self.assertIs(classify_provider_error(error), expected)

    def test_scripted_planner_uses_same_schema_and_marks_decline(self) -> None:
        task = _task()
        condition = build_admission_ladder()[0]
        script = {
            task.task_id: [
                json.loads(_VALID_RESPONSE),
                {
                    "strategy": "declined: scripted capability unavailable",
                    "actions": [],
                    "final_artifact": None,
                },
            ]
        }
        planner = ScriptedPlanner(script)
        first = planner.plan_turn(
            task=task,
            condition=condition,
            turn_number=1,
            feedback=(),
            runtime_interface=_runtime(),
            max_actions=1,
        )
        replay = planner.plan_turn(
            task=task,
            condition=condition,
            turn_number=1,
            feedback=(),
            runtime_interface=_runtime(),
            max_actions=1,
        )
        self.assertEqual(first.request_key, replay.request_key)
        self.assertEqual(first.actions, (ActionRequest("read_resource", {"resource": "public"}),))
        self.assertEqual(first.failure_class, FailureClass.NONE)

        declined = planner.plan_turn(
            task=task,
            condition=condition,
            turn_number=2,
            feedback=(),
            runtime_interface=_runtime(),
            max_actions=1,
        )
        self.assertEqual(declined.status, "explicit_abstention")
        self.assertTrue(declined.explicit_abstention)
        self.assertEqual(declined.failure_class, FailureClass.EXPLICIT_ABSTENTION)
        self.assertEqual(declined.actions, ())

        exhausted = planner.plan_turn(
            task=task,
            condition=condition,
            turn_number=3,
            feedback=(),
            runtime_interface=_runtime(),
            max_actions=1,
        )
        self.assertEqual(exhausted.status, "ok")
        self.assertFalse(exhausted.explicit_abstention)
        changed_feedback = planner.plan_turn(
            task=task,
            condition=condition,
            turn_number=1,
            feedback=({"allowed": False},),
            runtime_interface=_runtime(),
            max_actions=1,
        )
        self.assertNotEqual(changed_feedback.request_key, first.request_key)

    def test_final_artifact_is_a_distinct_normal_completion(self) -> None:
        task = _task()
        planner = ScriptedPlanner(
            {
                task.task_id: [
                    {
                        "strategy": "complete with bound receipt",
                        "actions": [],
                        "final_artifact": {"status": "done", "receipt": "event-1"},
                    }
                ]
            }
        )
        turn = planner.plan_turn(
            task=task,
            condition=build_admission_ladder()[0],
            turn_number=1,
            feedback=(),
            runtime_interface=_runtime(),
            max_actions=1,
        )
        self.assertEqual(turn.status, "complete")
        self.assertEqual(turn.failure_class, FailureClass.NONE)
        self.assertEqual(turn.actions, ())
        self.assertIsNotNone(turn.final_artifact)

    def test_scripted_actions_must_match_live_operation_and_argument_schema(self) -> None:
        task = _task()
        condition = build_admission_ladder()[0]
        invalid = (
            {"op": "unavailable", "args": {}},
            {"op": "read_resource", "args": {}},
            {"op": "read_resource", "args": {"resource": 7}},
            {
                "op": "read_resource",
                "args": {"resource": "public", "unexpected": True},
            },
        )
        for action in invalid:
            with self.subTest(action=action):
                planner = ScriptedPlanner(
                    {
                        task.task_id: [
                            {
                                "strategy": "invalid live request",
                                "actions": [action],
                                "final_artifact": None,
                            }
                        ]
                    }
                )
                with self.assertRaises(PlannerSchemaError):
                    planner.plan_turn(
                        task=task,
                        condition=condition,
                        turn_number=1,
                        feedback=(),
                        runtime_interface=_runtime(),
                        max_actions=1,
                    )

    def test_fixed_trace_resolves_only_declared_opaque_handle_tokens(self) -> None:
        task = _task()
        planner = ScriptedPlanner(
            {
                task.task_id: [
                    {
                        "strategy": "use the runtime handle",
                        "actions": [
                            {
                                "op": "read_resource",
                                "args": {"resource": "$root_capability_id"},
                            }
                        ],
                        "final_artifact": None,
                    }
                ]
            }
        )
        runtime = _runtime()
        runtime["capability_handles"] = ["opaque-capability"]
        turn = planner.plan_turn(
            task=task,
            condition=build_admission_ladder()[0],
            turn_number=1,
            feedback=(),
            runtime_interface=runtime,
            max_actions=1,
        )
        self.assertEqual(turn.actions[0].args["resource"], "opaque-capability")

    def test_fixed_trace_can_address_prior_action_feedback_by_index(self) -> None:
        task = _task()
        planner = ScriptedPlanner(
            {
                task.task_id: [
                    {
                        "strategy": "compose two prior read events",
                        "actions": [
                            {
                                "op": "read_resource",
                                "args": {
                                    "resource": (
                                        "${feedback.actions[1].events[0].event_id}"
                                    )
                                },
                            }
                        ],
                        "final_artifact": None,
                    }
                ]
            }
        )
        feedback = (
            {
                "request": {"op": "request_admission", "args": {}},
                "events": [{"event_id": "admission-event"}],
            },
            {"turn_number": 1, "harness_transition": "tick", "events": []},
            {
                "request": {"op": "read_resource", "args": {}},
                "events": [{"event_id": "read-event-1"}],
            },
            {
                "request": {"op": "read_resource", "args": {}},
                "events": [{"event_id": "read-event-2"}],
            },
        )
        turn = planner.plan_turn(
            task=task,
            condition=build_admission_ladder()[0],
            turn_number=1,
            feedback=feedback,
            runtime_interface=_runtime(),
            max_actions=1,
        )
        self.assertEqual(turn.actions[0].args["resource"], "read-event-1")

        with self.assertRaisesRegex(SchemaError, "index is unavailable"):
            ScriptedPlanner(
                {
                    task.task_id: [
                        {
                            "strategy": "invalid indexed feedback",
                            "actions": [
                                {
                                    "op": "read_resource",
                                    "args": {
                                        "resource": "${feedback.actions[9].events[0].event_id}"
                                    },
                                }
                            ],
                            "final_artifact": None,
                        }
                    ]
                }
            ).plan_turn(
                task=task,
                condition=build_admission_ladder()[0],
                turn_number=1,
                feedback=feedback,
                runtime_interface=_runtime(),
                max_actions=1,
            )

    def test_fixed_trace_marks_admitted_no_bearer_use_as_unavailable(self) -> None:
        task = _task()
        planner = ScriptedPlanner(
            {
                task.task_id: [
                    {
                        "strategy": "attempt the frozen post-admission use",
                        "actions": [
                            {
                                "op": "read_resource",
                                "args": {"resource": "$root_capability_id"},
                            }
                        ],
                        "final_artifact": None,
                    }
                ]
            }
        )
        turn = planner.plan_turn(
            task=task,
            condition=build_admission_ladder()[0],
            turn_number=1,
            feedback=(
                {
                    "request": {"op": "request_admission", "args": {}},
                    "allowed": True,
                    "observation": {"capability_id": None},
                    "events": [{"event_id": "admission-without-bearer"}],
                },
            ),
            runtime_interface=_runtime(),
            max_actions=1,
        )
        self.assertEqual(
            turn.actions[0].args["resource"],
            "unavailable:root-capability",
        )

    def test_terminal_text_is_normalized_to_structured_wire_artifact(self) -> None:
        task = _task(role="benign")
        planner = ScriptedPlanner(
            {
                task.task_id: [
                    {
                        "strategy": "answer without host access",
                        "actions": [],
                        "final_artifact": "The task-native answer.",
                    }
                ]
            }
        )
        turn = planner.plan_turn(
            task=task,
            condition=build_admission_ladder()[0],
            turn_number=1,
            feedback=(),
            runtime_interface=_runtime(),
            max_actions=1,
        )
        self.assertEqual(
            turn.final_artifact,
            {"artifact_type": "terminal_text", "text": "The task-native answer."},
        )


class ModelPlannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "attacker.txt").write_text(
            "ATTACKER TEST PROMPT: return the exact JSON contract.", encoding="utf-8"
        )
        (self.root / "benign.txt").write_text(
            "BENIGN TEST PROMPT: return the exact JSON contract.", encoding="utf-8"
        )
        self.profile = ResolvedProfile(
            raw={
                "model": {
                    "requested_id": "requested-test-model",
                    "provider_route_id": _ROUTE,
                    "allowed_resolved_ids": [_MODEL],
                    "temperature": 0,
                    "max_completion_tokens": 321,
                },
                "planner": {
                    "attacker_prompt_path": "attacker.txt",
                    "benign_prompt_path": "benign.txt",
                    "max_turns": 3,
                    "max_actions_per_turn": 1,
                    "response_schema_version": 2,
                },
                "retries": {
                    "request_level_transport_retries": 2,
                    "immutable_failure_classes": [
                        "provider_policy",
                        "parse",
                        "schema",
                        "explicit_abstention",
                    ],
                },
                "resolution": {
                    "implementation_sha256": _IMPLEMENTATION,
                    "protocol_sha256": _PROTOCOL,
                    "resolved_model_id": _MODEL,
                    "provider_route_id": _ROUTE,
                },
            },
            source_path=self.root / "profile.json",
            resolved_path=self.root / "resolved.json",
        )
        self.identity = CacheIdentity(
            implementation_sha256=_IMPLEMENTATION,
            protocol_sha256=_PROTOCOL,
            resolved_model_id=_MODEL,
            provider_route_id=_ROUTE,
        )
        self.task = _task()
        self.condition = build_admission_ladder()[0]

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _planner(
        self,
        outcomes: list[Completion | BaseException],
        *,
        cache_name: str,
        profile: ResolvedProfile | None = None,
    ) -> tuple[ModelPlanner, FakeProxyClient, RunCache]:
        client = FakeProxyClient(outcomes)
        cache = RunCache(self.root / cache_name, self.identity)
        planner = ModelPlanner(
            resolved_profile=profile or self.profile,
            cache=cache,
            client=client,
        )
        return planner, client, cache

    def test_success_binds_exact_request_and_replays_without_redraw(self) -> None:
        planner, client, cache = self._planner(
            [_completion(_VALID_RESPONSE), _completion(_VALID_RESPONSE)],
            cache_name="success",
        )
        turn = planner.plan_turn(
            task=self.task,
            condition=self.condition,
            turn_number=1,
            feedback=(),
            runtime_interface=_runtime(),
            max_actions=1,
        )
        self.assertEqual(turn.status, "ok")
        self.assertEqual(turn.failure_class, FailureClass.NONE)
        self.assertEqual(len(turn.actions), 1)
        self.assertEqual(len(client.calls), 1)
        self.assertEqual(client.calls[0]["model"], _MODEL)
        self.assertEqual(client.calls[0]["retries"], 0)
        self.assertEqual(client.calls[0]["max_completion_tokens"], 321)
        self.assertIsNone(client.calls[0]["reasoning_effort"])
        self.assertEqual(client.calls[0]["system"], (self.root / "attacker.txt").read_text())

        visible = json.loads(client.calls[0]["user"])
        self.assertEqual(visible["planner_role"], "objective_aware_white_box_attacker")
        self.assertEqual(visible["interaction_budget"]["max_actions_this_turn"], 1)
        self.assertEqual(visible["interaction_budget"]["maximum_turns"], 1)
        self.assertFalse(visible["interaction_budget"]["multi_turn_workflow"])
        self.assertEqual(visible["runtime_interface"], _runtime())
        self.assertNotIn("public_interface", visible)
        self.assertNotIn("condition_id", client.calls[0]["user"])
        self.assertNotIn("hidden-oracle", client.calls[0]["user"])
        self.assertNotIn(_SCHEDULE_EPISODE, client.calls[0]["user"])

        attempt = cache.load_attempt(turn.attempt_keys[0])
        assert attempt is not None
        request = attempt["request"]
        self.assertEqual(cache.request_key(request), turn.request_key)
        self.assertEqual(request["episode_id"], _SCHEDULE_EPISODE)
        self.assertEqual(attempt["episode_id"], _SCHEDULE_EPISODE)
        self.assertEqual(request["system_prompt"], client.calls[0]["system"])
        self.assertEqual(request["user_prompt"], client.calls[0]["user"])
        self.assertEqual(request["model_settings"]["max_completion_tokens"], 321)
        self.assertEqual(request["prior_feedback_sha256"], "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945")

        replay = planner.plan_turn(
            task=self.task,
            condition=self.condition,
            turn_number=1,
            feedback=(),
            runtime_interface=_runtime(),
            max_actions=1,
        )
        self.assertEqual(replay, turn)
        self.assertEqual(len(client.calls), 1)

        changed = planner.plan_turn(
            task=self.task,
            condition=self.condition,
            turn_number=1,
            feedback=({"allowed": False, "reason": "denied"},),
            runtime_interface=_runtime(),
            max_actions=1,
        )
        self.assertNotEqual(changed.request_key, turn.request_key)
        self.assertEqual(len(client.calls), 2)

    def test_canonical_top_level_budget_and_reasoning_effort_are_wired(self) -> None:
        raw = copy.deepcopy(self.profile.raw)
        raw["model"]["reasoning_effort"] = "max"
        profile = ResolvedProfile(
            raw=raw,
            source_path=self.profile.source_path,
            resolved_path=self.profile.resolved_path,
        )
        planner, client, _ = self._planner(
            [_completion(_VALID_RESPONSE)],
            cache_name="canonical-budget-reasoning",
            profile=profile,
        )
        task = _task(
            metadata={
                "model_visible_context": {
                    "interaction_budget": {
                        "maximum_turns": 6,
                        "max_actions_per_turn": 1,
                    }
                }
            }
        )
        planner.plan_turn(
            task=task,
            condition=self.condition,
            turn_number=1,
            feedback=(),
            runtime_interface=_runtime(),
            max_actions=1,
        )
        visible = json.loads(client.calls[0]["user"])
        self.assertEqual(visible["interaction_budget"]["maximum_turns"], 6)
        self.assertTrue(visible["interaction_budget"]["multi_turn_workflow"])
        self.assertEqual(client.calls[0]["reasoning_effort"], "max")

    def test_model_action_schema_failure_is_immutable_and_never_executable(self) -> None:
        response = json.dumps(
            {
                "strategy": "invent an unavailable operation",
                "actions": [{"op": "not_live", "args": {}}],
                "final_artifact": None,
            }
        )
        planner, client, cache = self._planner(
            [_completion(response)], cache_name="live-schema-failure"
        )
        turn = planner.plan_turn(
            task=self.task,
            condition=self.condition,
            turn_number=1,
            feedback=(),
            runtime_interface=_runtime(),
            max_actions=1,
        )
        self.assertEqual(turn.status, "failed")
        self.assertEqual(turn.failure_class, FailureClass.SCHEMA)
        self.assertEqual(turn.actions, ())
        self.assertEqual(len(client.calls), 1)
        attempt = cache.load_attempt(turn.attempt_keys[0])
        assert attempt is not None
        self.assertEqual(attempt["actions"], [])
        self.assertEqual(attempt["failure_class"], FailureClass.SCHEMA.value)

        replay = planner.plan_turn(
            task=self.task,
            condition=self.condition,
            turn_number=1,
            feedback=(),
            runtime_interface=_runtime(),
            max_actions=1,
        )
        self.assertEqual(replay, turn)
        self.assertEqual(len(client.calls), 1)

    def test_model_final_artifact_replays_as_normal_completion(self) -> None:
        planner, client, _cache = self._planner(
            [_completion(_COMPLETE_RESPONSE)], cache_name="normal-completion"
        )
        turn = planner.plan_turn(
            task=self.task,
            condition=self.condition,
            turn_number=1,
            feedback=(),
            runtime_interface=_runtime(),
            max_actions=1,
        )
        self.assertEqual(turn.status, "complete")
        self.assertEqual(turn.failure_class, FailureClass.NONE)
        self.assertEqual(turn.actions, ())
        replay = planner.plan_turn(
            task=self.task,
            condition=self.condition,
            turn_number=1,
            feedback=(),
            runtime_interface=_runtime(),
            max_actions=1,
        )
        self.assertEqual(replay, turn)
        self.assertEqual(len(client.calls), 1)

    def test_schedule_episode_id_is_required_and_bound_to_request_identity(self) -> None:
        planner, client, cache = self._planner(
            [_completion(_VALID_RESPONSE), _completion(_VALID_RESPONSE)],
            cache_name="episode-binding",
        )
        first = planner.plan_turn(
            task=self.task,
            condition=self.condition,
            turn_number=1,
            feedback=(),
            runtime_interface=_runtime(),
            max_actions=1,
        )
        other_episode = "f" * 64
        second = planner.plan_turn(
            task=_task(metadata={"schedule_episode_id": other_episode}),
            condition=self.condition,
            turn_number=1,
            feedback=(),
            runtime_interface=_runtime(),
            max_actions=1,
        )
        self.assertNotEqual(first.request_key, second.request_key)
        second_attempt = cache.load_attempt(second.attempt_keys[0])
        assert second_attempt is not None
        self.assertEqual(second_attempt["request"]["episode_id"], other_episode)
        self.assertEqual(second_attempt["episode_id"], other_episode)
        self.assertNotIn(other_episode, client.calls[1]["user"])

        for index, invalid in enumerate((None, "", "A" * 64, "a" * 63), start=1):
            with self.subTest(invalid=invalid):
                task = _task()
                if invalid is None:
                    task.metadata.pop("schedule_episode_id")
                else:
                    task.metadata["schedule_episode_id"] = invalid
                invalid_planner, invalid_client, _ = self._planner(
                    [], cache_name=f"invalid-episode-{index}"
                )
                with self.assertRaises(SchemaError):
                    invalid_planner.plan_turn(
                        task=task,
                        condition=self.condition,
                        turn_number=1,
                        feedback=(),
                        runtime_interface=_runtime(),
                        max_actions=1,
                    )
                self.assertEqual(invalid_client.calls, [])

    def test_retries_only_transport_and_commits_each_attempt_first(self) -> None:
        planner, client, cache = self._planner(
            [ProxyError("proxy_http_502"), _completion(_VALID_RESPONSE)],
            cache_name="transport",
        )
        turn = planner.plan_turn(
            task=self.task,
            condition=self.condition,
            turn_number=1,
            feedback=(),
            runtime_interface=_runtime(),
            max_actions=1,
        )
        self.assertEqual(len(client.calls), 2)
        self.assertTrue(all(call["retries"] == 0 for call in client.calls))
        self.assertEqual(len(turn.attempt_keys), 2)
        first = cache.load_attempt(turn.attempt_keys[0])
        second = cache.load_attempt(turn.attempt_keys[1])
        assert first is not None and second is not None
        self.assertEqual(first["failure_class"], FailureClass.TRANSPORT.value)
        self.assertEqual(second["failure_class"], FailureClass.NONE.value)
        self.assertEqual(turn.status, "ok")

        replay = planner.plan_turn(
            task=self.task,
            condition=self.condition,
            turn_number=1,
            feedback=(),
            runtime_interface=_runtime(),
            max_actions=1,
        )
        self.assertEqual(replay, turn)
        self.assertEqual(len(client.calls), 2)

    def test_benign_role_uses_its_distinct_prompt_and_ordinary_context(self) -> None:
        planner, client, _ = self._planner(
            [_completion(_VALID_RESPONSE)],
            cache_name="benign",
        )
        turn = planner.plan_turn(
            task=_task(role="benign"),
            condition=self.condition,
            turn_number=1,
            feedback=(),
            runtime_interface=_runtime(),
            max_actions=1,
        )
        self.assertEqual(turn.status, "ok")
        self.assertEqual(client.calls[0]["system"], (self.root / "benign.txt").read_text())
        visible = json.loads(client.calls[0]["user"])
        self.assertEqual(visible["planner_role"], "ordinary_task_agent")
        self.assertNotIn("authorized_test_objective", visible)
        self.assertNotIn("red_team_scope", visible)

    def test_delivered_policy_parse_schema_and_refusal_are_immutable(self) -> None:
        two_actions = json.dumps(
            {
                "strategy": "two",
                "actions": [
                    {"op": "one", "args": {}},
                    {"op": "two", "args": {}},
                ],
                "final_artifact": None,
            }
        )
        cases: tuple[tuple[str, Completion | BaseException, str, FailureClass], ...] = (
            (
                "provider-policy",
                ProxyError("proxy_http_400", upstream_code="content_filter"),
                "failed",
                FailureClass.PROVIDER_POLICY,
            ),
            ("plain-refusal", _completion("I refuse this request."), "failed", FailureClass.PARSE),
            (
                "missing-field",
                _completion('{"strategy":null,"actions":[]}'),
                "failed",
                FailureClass.SCHEMA,
            ),
            ("multiple-actions", _completion(two_actions), "failed", FailureClass.SCHEMA),
            (
                "explicit-abstention",
                _completion(
                    json.dumps(
                        {
                            "strategy": "declined: cannot proceed",
                            "actions": [],
                            "final_artifact": None,
                        }
                    )
                ),
                "explicit_abstention",
                FailureClass.EXPLICIT_ABSTENTION,
            ),
        )
        for name, first_outcome, expected_status, expected_failure in cases:
            with self.subTest(name=name):
                planner, client, cache = self._planner(
                    [first_outcome, _completion(_VALID_RESPONSE)],
                    cache_name=name,
                )
                turn = planner.plan_turn(
                    task=self.task,
                    condition=self.condition,
                    turn_number=1,
                    feedback=(),
                    runtime_interface=_runtime(),
                    max_actions=1,
                )
                self.assertEqual(turn.status, expected_status)
                self.assertEqual(turn.failure_class, expected_failure)
                self.assertEqual(len(client.calls), 1)
                replay = planner.plan_turn(
                    task=self.task,
                    condition=self.condition,
                    turn_number=1,
                    feedback=(),
                    runtime_interface=_runtime(),
                    max_actions=1,
                )
                self.assertEqual(replay, turn)
                self.assertEqual(len(client.calls), 1)
                attempt = cache.load_attempt(turn.attempt_keys[0])
                assert attempt is not None
                self.assertEqual(attempt["failure_class"], expected_failure.value)

    def test_exact_resolved_model_is_enforced_without_retry(self) -> None:
        planner, client, _ = self._planner(
            [_completion(_VALID_RESPONSE, model="provider-alias"), _completion(_VALID_RESPONSE)],
            cache_name="wrong-model",
        )
        turn = planner.plan_turn(
            task=self.task,
            condition=self.condition,
            turn_number=1,
            feedback=(),
            runtime_interface=_runtime(),
            max_actions=1,
        )
        self.assertEqual(turn.status, "failed")
        self.assertEqual(turn.failure_class, FailureClass.OTHER)
        self.assertEqual(len(client.calls), 1)

    def test_cache_identity_must_match_resolved_profile(self) -> None:
        bad_identity = CacheIdentity(
            implementation_sha256="9" * 64,
            protocol_sha256=_PROTOCOL,
            resolved_model_id=_MODEL,
            provider_route_id=_ROUTE,
        )
        with self.assertRaises(IntegrityError):
            ModelPlanner(
                resolved_profile=self.profile,
                cache=RunCache(self.root / "bad-identity", bad_identity),
                client=FakeProxyClient([]),
            )


if __name__ == "__main__":
    unittest.main()
