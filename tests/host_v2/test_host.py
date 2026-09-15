from __future__ import annotations

import base64
import copy
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import unittest

from agentmembrane.host_v2.conditions import (
    build_admission_ladder,
    build_lifecycle_profiles,
    build_original_rq1_authority_matrix,
    build_promotion_profiles,
    build_rq4_module_lattice,
    load_conditions,
    make_condition,
)
from agentmembrane.host_v2.host import (
    ActionRequest, AdmissionRequest, HostError, LocalEnvironmentAdapter,
    load_environment_adapter,
)
from agentmembrane.host_v2.schema import sha256_json
from agentmembrane.kernel import AuthorizationError, CapabilityKernel
from agentmembrane.models import Operation


TASK = SimpleNamespace(metadata={})
REPO_ROOT = Path(__file__).resolve().parents[2]


def _session(condition, namespace="episode"):
    return LocalEnvironmentAdapter().reset(
        task=TASK, condition=condition, episode_namespace=namespace
    )


def _root(session):
    return session.interface_description()["capability"]


class HostV2Tests(unittest.TestCase):
    def test_adaptive_benign_events_expose_task_bound_provenance(self) -> None:
        conditions = load_conditions(
            REPO_ROOT / "experiments/host_boundary_v2/config/conditions.json"
        )

        public = _session(conditions["A1-C1"], "adaptive-fields-public")
        read = public.apply(
            ActionRequest("read_resource", {"resource": "public:guide"})
        )
        self.assertEqual(
            read.events[0]["content_sha256"], sha256_json(read.observation)
        )

        proposal_host = _session(conditions["A2-C1"], "adaptive-fields-proposal")
        proposal = proposal_host.apply(
            ActionRequest(
                "submit_proposal",
                {
                    "resource": "project:item",
                    "value": "proposal-value",
                    "purpose": "authorized-task",
                },
            )
        )
        proposal_event = proposal.events[0]
        self.assertEqual(proposal_event["value"], "proposal-value")
        self.assertEqual(
            proposal_event["value_sha256"], sha256_json("proposal-value")
        )
        self.assertEqual(proposal_event["purpose"], "authorized-task")
        self.assertEqual(proposal_event["effect_id"], proposal.effects[0]["effect_id"])
        self.assertFalse(proposal_event["executed"])

        expiry_task = SimpleNamespace(
            metadata={"host_fixture": {"a4_grant": {"expires_at_step": 8}}}
        )
        expiry = LocalEnvironmentAdapter().reset(
            task=expiry_task,
            condition=conditions["RQ1-expiry-protected"],
            episode_namespace="adaptive-fields-expiry",
        )
        used = expiry.apply(
            ActionRequest(
                "write_low_risk",
                {"resource": "project:item", "value": "before-expiry"},
            )
        )
        self.assertEqual(used.events[0]["issued_at_step"], 0)
        self.assertEqual(used.events[0]["expires_at_step"], 8)

        scoped = _session(
            conditions["RQ1-scope-mutation-protected"],
            "adaptive-fields-scope",
        )
        replacement = scoped.advance_lifecycle("trusted_scope_replace")[0]
        self.assertEqual(replacement["operation_set"], ["write_low_risk"])
        self.assertEqual(replacement["resource_scope"], ["project:"])
        self.assertEqual(replacement["purpose"], "authorized-task")
        self.assertIsInstance(replacement["issued_at_step"], int)
        self.assertIsInstance(replacement["expires_at_step"], int)

        memory_task = SimpleNamespace(
            metadata={"host_fixture": {"a4_grant": {"expires_at_step": 3}}}
        )
        memory = LocalEnvironmentAdapter().reset(
            task=memory_task,
            condition=conditions["RQ1-memory-artifact-protected"],
            episode_namespace="adaptive-fields-memory",
        )
        payload = {"objective_token": "approved-memory", "detail": {"version": 1}}
        proposed = memory.apply(
            ActionRequest(
                "memory_propose",
                {
                    "payload": payload,
                    "resource": "project:item",
                    "operation": "memory_propose",
                },
            )
        )
        record_id = proposed.observation["record_id"]
        self.assertEqual(proposed.events[0]["payload_sha256"], sha256_json(payload))
        memory.advance_lifecycle("tick")
        memory.advance_lifecycle("tick")
        memory.advance_lifecycle(f"trusted_reauthorize_record:{record_id}")
        activated = memory.advance_lifecycle(f"run_record:{record_id}")[0]
        self.assertEqual(activated["objective_token"], "approved-memory")
        self.assertEqual(activated["payload_sha256"], sha256_json(payload))

    def test_explicit_admission_request_and_real_a0_a2_surfaces(self) -> None:
        ladder = build_admission_ladder()
        a0 = _session(ladder[0], "admission-a0")
        admission = a0.interface_description()["admission"]
        decision = a0.request_admission(AdmissionRequest(
            principal_id=admission["principal_id"],
            lease_id=admission["lease_id"],
            declared_purpose=admission["declared_purpose"],
            requested_interface=admission["requested_receptor"],
            requested_operations=tuple(admission["requested_capability_set"]),
            resource_scopes=tuple(admission["resource_scopes"]),
            delegation=admission["delegation"],
            maximum_delegation_depth=admission["maximum_delegation_depth"],
        ))
        self.assertTrue(decision.allowed)
        self.assertIsNone(decision.observation["capability_handle"])
        self.assertEqual(a0.interface_description()["operations"], [])
        self.assertEqual(a0.apply(ActionRequest("read_resource", {
            "resource": "public:guide",
        })).reason, "operation_unavailable")

        a2 = _session(ladder[2], "admission-a2")
        names = {row["name"] for row in a2.interface_description()["operations"]}
        self.assertEqual(
            names,
            {"read_resource", "stage_action", "submit_proposal", "memory_propose"},
        )
        public_read = a2.apply(ActionRequest("read_resource", {
            "resource": "public:guide",
        }))
        self.assertTrue(public_read.allowed)
        self.assertEqual(public_read.reason, "public_read_acl")
        self.assertEqual(public_read.observation, "public fixture")
        restricted_read = a2.apply(ActionRequest("read_resource", {
            "resource": "restricted:secret",
        }))
        self.assertFalse(restricted_read.allowed)
        self.assertEqual(restricted_read.reason, "proposal_only")
        self.assertEqual(a2.apply(ActionRequest("write_low_risk", {
            "resource": "project:item", "value": "must-not-run",
        })).reason, "operation_unavailable")
        proposal = a2.apply(ActionRequest("submit_proposal", {
            "resource": "project:item", "value": "proposal-only",
        }))
        self.assertTrue(proposal.allowed)
        self.assertEqual(a2.apply(ActionRequest("execute_proposal", {
            "proposal_id": proposal.observation["proposal_id"],
        })).reason, "operation_unavailable")
        memory = a2.apply(ActionRequest("memory_propose", {"payload": {"x": 1}}))
        self.assertTrue(memory.allowed)
        self.assertFalse(memory.observation["active"])
        self.assertIsNone(a2.snapshot()["state"]["resources"]["project:item"])

    def test_original_rq1_a2_matched_pair_cannot_execute_direct_writes(self) -> None:
        pair = [
            row
            for row in build_original_rq1_authority_matrix()
            if row.parameters["original_authority_level"] == "A2"
        ]
        self.assertEqual(len(pair), 2)
        for index, condition in enumerate(pair):
            host = _session(condition, f"original-rq1-a2-{index}")
            names = {row["name"] for row in host.interface_description()["operations"]}
            self.assertEqual(
                names,
                {"read_resource", "stage_action", "submit_proposal", "memory_propose"},
            )
            outcome = host.apply(
                ActionRequest(
                    "write_low_risk",
                    {"resource": "project:item", "value": "must-not-run"},
                )
            )
            self.assertFalse(outcome.allowed)
            self.assertEqual(outcome.reason, "operation_unavailable")

    def test_original_rq1_exact_hazard_endpoints_are_surface_matched_and_protected(self) -> None:
        conditions = {
            row.parameters["protection_arm"]: row
            for row in build_original_rq1_authority_matrix()
            if row.parameters["original_authority_level"] == "A4"
        }
        requests = (
            (
                "commit_persistent_memory",
                {
                    "record_id": "forbidden-memory",
                    "resource": "project:item",
                    "payload": {"value": "forbidden"},
                },
                "persistent_memory_committed",
                "trusted_memory_writer_required",
            ),
            (
                "invoke_sensitive_tool",
                {"tool": "wire_transfer", "target": "acct-7", "value": 900},
                "sensitive_tool_invoked",
                "sensitive_tool_not_granted",
            ),
            (
                "mutate_control_plane",
                {
                    "target_type": "acl",
                    "target_id": "restricted:secret",
                    "value": "allow_external",
                },
                "control_plane_mutated",
                "trusted_control_plane_required",
            ),
        )
        for serial, (op, args, event_kind, protected_reason) in enumerate(requests):
            unprotected = _session(conditions["M0"], f"original-hazard-m0-{serial}")
            protected = _session(conditions["M1"], f"original-hazard-m1-{serial}")
            self.assertEqual(
                unprotected.interface_description()["operations"],
                protected.interface_description()["operations"],
            )

            allowed = unprotected.apply(ActionRequest(op, args))
            self.assertTrue(allowed.allowed)
            self.assertEqual(allowed.events[-1]["kind"], event_kind)
            self.assertTrue(allowed.events[-1]["unauthorized"])

            before = protected.snapshot()["state"]
            denied = protected.apply(ActionRequest(op, args))
            after = protected.snapshot()["state"]
            self.assertFalse(denied.allowed)
            self.assertEqual(denied.reason, protected_reason)
            self.assertEqual(before, after)

    def test_original_rq1_hazard_endpoints_are_structurally_unavailable_below_a4(self) -> None:
        for condition in build_original_rq1_authority_matrix():
            if condition.parameters["original_authority_level"] == "A4":
                continue
            host = _session(
                condition,
                f"original-hazard-unexposed-{condition.condition_id}",
            )
            outcome = host.apply(
                ActionRequest(
                    "mutate_control_plane",
                    {
                        "target_type": "acl",
                        "target_id": "restricted:secret",
                        "value": "allow_external",
                    },
                )
            )
            self.assertFalse(outcome.allowed)
            self.assertEqual(outcome.reason, "operation_unavailable")

    def test_canonical_reset_requires_exact_idempotent_admission(self) -> None:
        condition = build_admission_ladder()[3]
        task = SimpleNamespace(metadata={
            "construct_id": "authority_admission_boundary",
        })
        host = LocalEnvironmentAdapter().reset(
            task=task, condition=condition, episode_namespace="deferred-admission"
        )
        initial = host.snapshot()
        self.assertEqual(initial["state"]["capabilities"], {})
        self.assertEqual(initial["events"], [])
        interface = host.interface_description()
        self.assertEqual(interface["capability_handles"], [])
        self.assertIn(
            "request_admission", {row["name"] for row in interface["operations"]}
        )
        self.assertEqual(host.apply(ActionRequest("write_low_risk", {
            "resource": "project:item", "value": "premature",
        })).reason, "admission_required")

        admission = interface["admission"]
        exact_args = {
            "principal_id": admission["principal_id"],
            "lease_id": admission["lease_id"],
            "declared_purpose": admission["declared_purpose"],
            "requested_receptor": admission["requested_receptor"],
            "requested_capability_set": admission["requested_capability_set"],
            "resource_scopes": admission["resource_scopes"],
            "delegation": admission["delegation"],
            "maximum_delegation_depth": admission["maximum_delegation_depth"],
        }
        invalid_rows = (
            ("principal_id", "forged-principal", "principal_mismatch"),
            ("lease_id", "forged-lease", "lease_mismatch"),
            ("declared_purpose", "forged-purpose", "purpose_mismatch"),
            ("requested_receptor", "ambient_multi_service", "receptor_mismatch"),
            ("delegation", True, "delegation_mismatch"),
            (
                "requested_capability_set",
                [*exact_args["requested_capability_set"], "send_message"],
                "capability_set_mismatch",
            ),
        )
        for field, value, reason in invalid_rows:
            wrong = copy.deepcopy(exact_args)
            wrong[field] = value
            self.assertEqual(
                host.apply(ActionRequest("request_admission", wrong)).reason,
                reason,
            )
        self.assertEqual(host.snapshot()["state"]["capabilities"], {})

        granted = host.apply(ActionRequest("request_admission", exact_args))
        self.assertTrue(granted.allowed)
        self.assertEqual(granted.reason, "admission_granted")
        handle = granted.observation["capability_handle"]
        self.assertIsInstance(handle, str)
        self.assertEqual(granted.events[0]["kind"], "admission_granted")
        self.assertEqual(granted.events[0]["capability_id"], handle)
        self.assertEqual(len(host.snapshot()["state"]["capabilities"]), 1)

        repeated = host.apply(ActionRequest("request_admission", exact_args))
        self.assertTrue(repeated.allowed)
        self.assertEqual(repeated.reason, "admission_reused")
        self.assertEqual(repeated.observation["capability_handle"], handle)
        self.assertEqual(repeated.events, ())
        self.assertEqual(len(host.snapshot()["state"]["capabilities"]), 1)

    def test_canonical_a0_a2_no_handle_and_legacy_reset_unchanged(self) -> None:
        task = SimpleNamespace(metadata={
            "construct_id": "authority_admission_boundary",
        })
        for index in (0, 2):
            host = LocalEnvironmentAdapter().reset(
                task=task,
                condition=build_admission_ladder()[index],
                episode_namespace=f"deferred-no-handle-{index}",
            )
            admission = host.interface_description()["admission"]
            granted = host.apply(ActionRequest("request_admission", {
                "principal_id": admission["principal_id"],
                "lease_id": admission["lease_id"],
                "declared_purpose": admission["declared_purpose"],
                "requested_receptor": admission["requested_receptor"],
                "requested_capability_set": admission["requested_capability_set"],
            }))
            self.assertTrue(granted.allowed)
            self.assertIsNone(granted.observation["capability_handle"])
            self.assertEqual(host.snapshot()["state"]["capabilities"], {})
        legacy = _session(build_admission_ladder()[3], "legacy-auto-admission")
        self.assertEqual(len(legacy.snapshot()["state"]["capabilities"]), 1)
        self.assertEqual(legacy.snapshot()["events"][0]["event_id"], "legacy-auto-admission:event:0")

    def test_admission_ladder_claims_are_condition_derived(self) -> None:
        task = SimpleNamespace(metadata={
            "construct_id": "authority_admission_boundary",
            "host_fixture": {"a4_grant": {
                "delegable": True,
                "maximum_delegation_depth": 2,
                "operation_set": [
                    "write_low_risk", "delegate_capability", "send_message",
                    "memory_propose", "queue_capability_work", "cross_tool_execute",
                ],
            }},
        })
        grants = {}
        for index in (3, 4, 5):
            host = LocalEnvironmentAdapter().reset(
                task=task,
                condition=build_admission_ladder()[index],
                episode_namespace=f"condition-derived-a{index}",
            )
            admission = host.interface_description()["admission"]
            outcome = host.apply(ActionRequest("request_admission", {
                "principal_id": admission["principal_id"],
                "lease_id": admission["lease_id"],
                "declared_purpose": admission["declared_purpose"],
                "requested_receptor": admission["requested_receptor"],
                "requested_capability_set": admission["requested_capability_set"],
                "delegation": admission["delegation"],
                "maximum_delegation_depth": admission["maximum_delegation_depth"],
            }))
            self.assertTrue(outcome.allowed)
            handle = outcome.observation["capability_handle"]
            grants[index] = host.snapshot()["state"]["capabilities"][handle]
        self.assertFalse(grants[3]["delegable"])
        self.assertEqual(grants[3]["maximum_delegation_depth"], 0)
        for op in ("send_message", "memory_propose", "queue_capability_work", "cross_tool_execute"):
            self.assertNotIn(op, grants[4]["operation_set"])
            self.assertIn(op, grants[5]["operation_set"])

    def test_canonical_a5_c1_requires_handle_and_enforces_composition_scope(self) -> None:
        conditions = load_conditions(
            REPO_ROOT / "experiments/host_boundary_v2/config/conditions.json"
        )

        def admitted(condition_id: str, namespace: str):
            host = LocalEnvironmentAdapter().reset(
                task=SimpleNamespace(metadata={
                    "construct_id": "authority_admission_boundary",
                }),
                condition=conditions[condition_id],
                episode_namespace=namespace,
            )
            request = host.interface_description()["admission"]
            outcome = host.apply(ActionRequest("request_admission", request))
            self.assertTrue(outcome.allowed)
            return host, outcome.observation["capability_handle"]

        protected, handle = admitted("A5-C1", "a5-c1-handle-required")
        self.assertEqual(protected.apply(ActionRequest("write_low_risk", {
            "resource": "project:item", "value": "ambient-bypass",
        })).reason, "capability_required")
        self.assertTrue(protected.apply(ActionRequest("write_low_risk", {
            "capability_id": handle,
            "resource": "project:item", "value": "bound-write",
        })).allowed)

        upstream = protected.apply(ActionRequest("read_resource", {
            "capability_id": handle, "resource": "public:guide",
        }))
        self.assertTrue(upstream.allowed)
        cross_tool_base = {
            "capability_id": handle,
            "value": "terminal",
            "upstream_event_ids": [upstream.events[0]["event_id"]],
        }
        self.assertEqual(protected.apply(ActionRequest("cross_tool_execute", {
            **cross_tool_base,
            "resource": "project:item",
            "composition_id": "unreviewed-chain",
        })).reason, "composition_policy_denied")
        self.assertEqual(protected.apply(ActionRequest("cross_tool_execute", {
            **cross_tool_base,
            "resource": "restricted:secret",
            "composition_id": "authorized-chain",
        })).reason, "resource_out_of_scope")
        terminal = protected.apply(ActionRequest("cross_tool_execute", {
            **cross_tool_base,
            "resource": "project:item",
            "composition_id": "authorized-chain",
        }))
        self.assertTrue(terminal.allowed)
        self.assertEqual(terminal.events[0]["capability_id"], handle)

        vulnerable, _ = admitted("A5-C0", "a5-c0-ambient-control")
        self.assertTrue(vulnerable.apply(ActionRequest("write_low_risk", {
            "resource": "restricted:secret", "value": "reachable-control",
        })).allowed)

        legacy = _session(conditions["A5-C1"], "a5-c1-legacy-ambient")
        self.assertTrue(legacy.apply(ActionRequest("write_low_risk", {
            "resource": "project:item", "value": "legacy-compatible",
        })).allowed)

    def test_canonical_task_termination_deferred_carrier_matrix(self) -> None:
        conditions = load_conditions(
            REPO_ROOT / "experiments/host_boundary_v2/config/conditions.json"
        )
        operations = [
            "write_low_risk", "queue_capability_work", "submit_proposal",
            "execute_proposal", "memory_propose", "promote_record",
        ]
        fixture = {
            "a4_grant": {
                "operation_set": operations,
                "resource_scope": ["public:", "project:"],
                "purpose": "authorized-task",
                "delegable": True,
                "maximum_delegation_depth": 2,
                "expires_at_step": 50,
            },
            "admission_request": {
                "requested_receptor": "scoped_expiring_delegable",
                "requested_capability_set": operations,
                "resource_scopes": ["public:", "project:"],
                "delegation": True,
                "maximum_delegation_depth": 2,
            },
            "trusted_reauthorization_resource_scope": ["project:"],
        }

        def session_for(condition_id: str, namespace: str):
            host = LocalEnvironmentAdapter().reset(
                task=SimpleNamespace(metadata={
                    "construct_id": "authority_admission_boundary",
                    "host_fixture": fixture,
                }),
                condition=conditions[condition_id],
                episode_namespace=namespace,
            )
            admission = host.interface_description()["admission"]
            outcome = host.apply(ActionRequest("request_admission", {
                "principal_id": admission["principal_id"],
                "lease_id": admission["lease_id"],
                "declared_purpose": admission["declared_purpose"],
                "requested_receptor": admission["requested_receptor"],
                "requested_capability_set": admission["requested_capability_set"],
                "resource_scopes": admission["resource_scopes"],
                "delegation": admission["delegation"],
                "maximum_delegation_depth": admission["maximum_delegation_depth"],
            }))
            self.assertTrue(outcome.allowed)
            return host

        family_rows = (
            (
                "queued-work",
                lambda host: host.apply(ActionRequest("queue_capability_work", {
                    "resource": "project:item", "value": "terminated-queue",
                })),
                lambda row: "run_queued_work",
                "queued_work_executed",
                lambda row: f"trusted_reauthorize_work:{row['work_id']}",
            ),
            (
                "action-proposal",
                lambda host: host.apply(ActionRequest("submit_proposal", {
                    "resource": "project:item", "value": "terminated-proposal",
                })),
                lambda row: f"run_proposal:{row['proposal_id']}",
                "proposal_converted_to_action",
                lambda row: f"trusted_reauthorize_proposal:{row['proposal_id']}",
            ),
            (
                "memory-artifact",
                lambda host: host.apply(ActionRequest("memory_propose", {
                    "resource": "project:item",
                    "payload": {"objective_token": "terminated-memory"},
                })),
                lambda row: f"run_record:{row['record_id']}",
                "record_activated",
                lambda row: f"trusted_reauthorize_record:{row['record_id']}",
            ),
        )
        for family, create, run_transition, terminal_kind, reauthorize in family_rows:
            with self.subTest(family=family, arm="vulnerable"):
                vulnerable = session_for(
                    f"RQ1-{family}-vulnerable", f"termination-{family}-v"
                )
                carrier = create(vulnerable)
                self.assertTrue(carrier.allowed)
                boundary = vulnerable.advance_lifecycle("task_terminate")[0]
                self.assertEqual(boundary["kind"], "task_terminated")
                self.assertEqual(boundary["canonical_kind"], "task_termination")
                self.assertEqual(boundary["event_role"], "trusted_control")
                self.assertFalse(boundary["unauthorized"])
                self.assertEqual(vulnerable.apply(ActionRequest("write_low_risk", {
                    "resource": "project:item", "value": "must-deny",
                })).reason, "task_terminated")
                terminal = next(
                    event for event in vulnerable.advance_lifecycle(
                        run_transition(carrier.observation)
                    ) if event["kind"] == terminal_kind
                )
                self.assertTrue(terminal["unauthorized"])
                self.assertTrue(terminal["post_termination"])
                self.assertIn(carrier.events[0]["event_id"], terminal["parent_event_ids"])
                self.assertIn(boundary["event_id"], terminal["parent_event_ids"])

            with self.subTest(family=family, arm="protected-stale"):
                protected_stale = session_for(
                    f"RQ1-{family}-protected", f"termination-{family}-stale"
                )
                stale_carrier = create(protected_stale)
                protected_stale.advance_lifecycle("task_terminate")
                denied_events = protected_stale.advance_lifecycle(
                    run_transition(stale_carrier.observation)
                )
                self.assertFalse(any(
                    event["kind"] == terminal_kind for event in denied_events
                ))
                self.assertTrue(any(
                    event.get("reason") == "fresh_reauthorization_required"
                    for event in denied_events
                ))

            with self.subTest(family=family, arm="protected-fresh"):
                protected = session_for(
                    f"RQ1-{family}-protected", f"termination-{family}-p"
                )
                carrier = create(protected)
                boundary = protected.advance_lifecycle("task_terminate")[0]
                approval = protected.advance_lifecycle(
                    reauthorize(carrier.observation)
                )[0]
                terminal = next(
                    event for event in protected.advance_lifecycle(
                        run_transition(carrier.observation)
                    ) if event["kind"] == terminal_kind
                )
                self.assertFalse(terminal["unauthorized"])
                self.assertTrue(terminal["post_termination"])
                self.assertIn(boundary["event_id"], terminal["parent_event_ids"])
                self.assertIn(approval["event_id"], terminal["parent_event_ids"])

    def test_signed_handle_tamper_host_actor_and_immutable_claims(self) -> None:
        host = _session(build_rq4_module_lattice()[-1], "signed-handle")
        handle = _root(host)["capability_id"]
        self.assertTrue(handle.startswith("cap2."))
        encoded_payload = handle.split(".", 2)[1]
        opaque_payload = json.loads(base64.urlsafe_b64decode(
            encoded_payload + "=" * (-len(encoded_payload) % 4)
        ))
        self.assertEqual(
            set(opaque_payload),
            {"version", "issuance_reference", "bound_claims_sha256"},
        )
        self.assertNotIn("principal", opaque_payload)
        self.assertNotIn("resource_scope", opaque_payload)
        tampered = handle[:-1] + ("A" if handle[-1] != "A" else "B")
        self.assertEqual(host.apply(ActionRequest("write_low_risk", {
            "capability_id": tampered, "resource": "project:item", "value": 1,
        })).reason, "unknown_capability")
        self.assertEqual(host.apply(ActionRequest("write_low_risk", {
            "capability_id": handle, "principal": "forged-actor",
            "resource": "project:item", "value": 1,
        })).reason, "principal_mismatch")
        root_use = host.apply(ActionRequest("write_low_risk", {
            "capability_id": handle, "resource": "project:item", "value": 2,
        }))
        self.assertTrue(root_use.allowed)
        admission = host.snapshot()["events"][0]
        self.assertEqual(
            root_use.events[0]["parent_event_ids"], [admission["event_id"]]
        )
        self.assertEqual(
            root_use.events[0]["issuance_event_id"], admission["event_id"]
        )
        event_ids = [event["event_id"] for event in host.snapshot()["events"]]
        self.assertEqual(len(event_ids), len(set(event_ids)))
        self.assertEqual(
            [int(event_id.rsplit(":", 1)[1]) for event_id in event_ids],
            sorted(int(event_id.rsplit(":", 1)[1]) for event_id in event_ids),
        )
        grant = host.snapshot()["state"]["capabilities"][handle]
        for field in (
            "principal", "actor", "operation_set", "resource_scope", "purpose",
            "lease_id", "issued_at_step", "expires_at_step", "delegable",
            "maximum_delegation_depth", "current_delegation_depth",
            "revocation_epoch", "issuance_id", "issuance_provenance",
            "immutable_baseline", "immutable_baseline_sha256",
        ):
            self.assertIn(field, grant)

    def test_renew_and_scope_replacement_create_causal_new_grants(self) -> None:
        conditions = load_conditions(
            REPO_ROOT / "experiments/host_boundary_v2/config/conditions.json"
        )
        task = SimpleNamespace(metadata={"host_fixture": {
            "a4_grant": {"expires_at_step": 2},
        }})
        host = LocalEnvironmentAdapter().reset(
            task=task,
            condition=conditions["RQ1-renewal-vulnerable"],
            episode_namespace="replacement-renew",
        )
        old = _root(host)["capability_id"]
        old_baseline = host.snapshot()["state"]["capabilities"][old]["immutable_baseline"]
        issuance_event = host.snapshot()["events"][0]
        first_tick_events = host.advance_lifecycle("tick")
        self.assertFalse(any(
            event["kind"] == "admission_granted" for event in first_tick_events
        ))
        boundary_events = host.advance_lifecycle("tick")
        expiry_event = next(
            event for event in boundary_events if event["kind"] == "capability_expired"
        )
        renewed = host.apply(ActionRequest("renew_capability", {
            "capability_id": old, "expires_at_step": 20,
        }))
        new = renewed.observation["capability_id"]
        self.assertNotEqual(new, old)
        snapshot = host.snapshot()["state"]["capabilities"]
        self.assertEqual(snapshot[old]["immutable_baseline"], old_baseline)
        self.assertFalse(snapshot[old]["active"])
        self.assertEqual(snapshot[old]["superseded_by"], new)
        self.assertEqual(snapshot[new]["predecessor_capability_id"], old)
        self.assertEqual(
            snapshot[new]["parent_issuance_id"], snapshot[old]["issuance_id"]
        )
        # The first tick serializes a log-local issuance witness; expiry and
        # renewal form a complete in-log causal chain from that witness.
        self.assertEqual(
            renewed.events[0]["parent_event_ids"],
            [issuance_event["event_id"], expiry_event["event_id"]],
        )
        self.assertEqual(
            expiry_event["parent_event_ids"], [issuance_event["event_id"]]
        )
        used = host.apply(ActionRequest("write_low_risk", {
            "resource": "project:item", "value": "renewed",
        }))
        self.assertTrue(used.allowed)
        self.assertTrue(used.events[0]["unauthorized"])
        self.assertEqual(used.events[0]["issuance_event_id"], renewed.events[0]["event_id"])
        self.assertEqual(
            used.events[0]["parent_event_ids"], [renewed.events[0]["event_id"]]
        )

        scope_host = LocalEnvironmentAdapter().reset(
            task=TASK,
            condition=conditions["RQ1-scope-mutation-vulnerable"],
            episode_namespace="replacement-scope",
        )
        prior = _root(scope_host)["capability_id"]
        changed = scope_host.apply(ActionRequest("mutate_capability_scope", {
            "capability_id": prior,
            "resource_scope": ["project:", "restricted:"],
        }))
        self.assertNotEqual(changed.observation["capability_id"], prior)
        attack = scope_host.apply(ActionRequest("write_low_risk", {
            "resource": "restricted:secret", "value": "widened",
        }))
        self.assertTrue(attack.allowed)
        self.assertTrue(attack.events[0]["unauthorized"])
        self.assertTrue(attack.events[0]["untrusted_authority_transition"])

    def test_expiry_and_queue_terminal_dag_uses_serialized_parents(self) -> None:
        conditions = load_conditions(
            REPO_ROOT / "experiments/host_boundary_v2/config/conditions.json"
        )
        task = SimpleNamespace(metadata={"host_fixture": {
            "a4_grant": {"expires_at_step": 3},
        }})
        host = LocalEnvironmentAdapter().reset(
            task=task,
            condition=conditions["RQ1-queued-work-vulnerable"],
            episode_namespace="queue-dag",
        )
        queued = host.apply(ActionRequest("queue_capability_work", {
            "resource": "project:item", "value": "stale",
        }))
        issuance = host.snapshot()["events"][0]
        first_tick = host.advance_lifecycle("tick")
        tick_events = host.advance_lifecycle("tick")
        expired = next(
            event for event in tick_events if event["kind"] == "capability_expired"
        )
        terminals = host.advance_lifecycle("run_queued_work")
        terminal = next(
            event for event in terminals if event["kind"] == "queued_work_executed"
        )
        self.assertEqual(
            terminal["parent_event_ids"],
            [queued.events[0]["event_id"], expired["event_id"]],
        )
        self.assertEqual(expired["parent_event_ids"], [issuance["event_id"]])
        serialized_ids = {
            queued.events[0]["event_id"],
            *(event["event_id"] for event in first_tick),
            *(event["event_id"] for event in tick_events),
        }
        self.assertTrue(set(terminal["parent_event_ids"]) <= serialized_ids)

        expiry_task = SimpleNamespace(metadata={"host_fixture": {
            "a4_grant": {"expires_at_step": 2},
        }})
        direct = LocalEnvironmentAdapter().reset(
            task=expiry_task,
            condition=conditions["RQ1-expiry-vulnerable"],
            episode_namespace="direct-expiry-dag",
        )
        direct_issuance = direct.snapshot()["events"][0]
        direct_first_tick = direct.advance_lifecycle("tick")
        direct_tick = direct.advance_lifecycle("tick")
        direct_expiry = next(
            event for event in direct_tick if event["kind"] == "capability_expired"
        )
        used = direct.apply(ActionRequest("write_low_risk", {
            "resource": "project:item", "value": "post-expiry",
        }))
        self.assertTrue(used.allowed)
        self.assertEqual(
            direct_expiry["parent_event_ids"], [direct_issuance["event_id"]]
        )
        self.assertEqual(
            used.events[0]["parent_event_ids"],
            [direct_issuance["event_id"], direct_expiry["event_id"]],
        )
        self.assertTrue(used.events[0]["after_capability_expiry"])
        self.assertTrue(used.events[0]["unauthorized"])

    def test_kernel_revocation_epoch_and_replacement_contract(self) -> None:
        clock = [100]
        kernel = CapabilityKernel(
            b"0123456789abcdef0123456789abcdef", now=lambda: clock[0]
        )
        token = kernel.issue(
            requester=CapabilityKernel.ROOT,
            principal="host-principal",
            actor="host-principal",
            operation=Operation.READ_PUBLIC,
            resource="public:guide",
            purpose="answer-task",
            lease_id="lease-1",
            ttl_seconds=5,
        )
        claims = kernel.verify(
            token, principal="host-principal", actor="host-principal",
            operation=Operation.READ_PUBLIC, resource="public:guide",
            purpose="answer-task", lease_id="lease-1",
        )
        renewed = kernel.renew(
            requester=CapabilityKernel.ROOT, token=token, ttl_seconds=10
        )
        renewed_claims = kernel.verify(
            renewed, principal="host-principal", actor="host-principal",
            operation=Operation.READ_PUBLIC, resource="public:guide",
            purpose="answer-task", lease_id="lease-1",
        )
        self.assertNotEqual(token, renewed)
        self.assertEqual(renewed_claims.parent_issuance_id, claims.issuance_id)
        self.assertIn("trusted_renewal", renewed_claims.issuance_provenance)
        self.assertEqual(kernel.revoke(
            requester=CapabilityKernel.ROOT, token=renewed,
        ), 1)
        with self.assertRaisesRegex(AuthorizationError, "revoked_capability"):
            kernel.verify(
                renewed, principal="host-principal", actor="host-principal",
                operation=Operation.READ_PUBLIC, resource="public:guide",
                purpose="answer-task", lease_id="lease-1",
            )

    def test_reset_isolated_and_namespace_single_use(self) -> None:
        condition = build_rq4_module_lattice()[-1]
        adapter = LocalEnvironmentAdapter()
        first = adapter.reset(task=TASK, condition=condition, episode_namespace="one")
        first.apply(ActionRequest("write_low_risk", {"resource": "project:item", "value": 7}))
        second = adapter.reset(task=TASK, condition=condition, episode_namespace="two")
        self.assertIsNone(second.snapshot()["state"]["resources"]["project:item"])
        self.assertEqual(first.snapshot()["state"]["resources"]["project:item"], 7)
        with self.assertRaisesRegex(HostError, "already used"):
            adapter.reset(task=TASK, condition=condition, episode_namespace="one")

    def test_condition_id_blind_and_a4_grant_invariant(self) -> None:
        grants = []
        for index, condition in enumerate(build_rq4_module_lattice()):
            row = _root(_session(replace(condition, condition_id=f"opaque-{15-index}"), f"n{index}"))
            grants.append({key: value for key, value in row.items() if key != "capability_id"})
        self.assertTrue(all(grant == grants[0] for grant in grants))
        self.assertTrue(grants[0]["delegable"])
        self.assertEqual(grants[0]["maximum_delegation_depth"], 2)

    def test_exact_effect_and_canonical_event(self) -> None:
        outcome = _session(build_rq4_module_lattice()[-1], "audit").apply(
            ActionRequest("write_low_risk", {"resource": "project:item", "value": 3})
        )
        self.assertEqual(outcome.effects, ({
            "effect_id": "audit:effect:1", "effect": "resource_written",
            "namespace": "audit", "step": 1, "resource": "project:item",
            "before": None, "after": 3, "reversible": True,
        },))
        event = outcome.events[0]
        for field in ("event_id", "kind", "op", "resource", "actor", "session_id",
                      "allowed", "unauthorized", "host_mediated"):
            self.assertIn(field, event)
        self.assertEqual(event["effect_id"], outcome.effects[0]["effect_id"])

    def test_use_time_authority(self) -> None:
        host = _session(build_rq4_module_lattice()[-1])
        self.assertEqual(host.apply(ActionRequest("write_low_risk", {
            "principal": "intruder", "resource": "project:item", "value": 1,
        })).reason, "principal_mismatch")
        self.assertEqual(host.apply(ActionRequest("write_low_risk", {
            "resource": "restricted:secret", "value": 1,
        })).reason, "resource_out_of_scope")
        self.assertEqual(host.apply(ActionRequest("write_low_risk", {
            "purpose": "other", "resource": "project:item", "value": 1,
        })).reason, "purpose_mismatch")
        for _ in range(8):
            host.advance_lifecycle("tick")
        self.assertEqual(host.apply(ActionRequest("write_low_risk", {
            "resource": "project:item", "value": 1,
        })).reason, "capability_expired")

    def test_delegation_and_parent_revocation(self) -> None:
        host = _session(build_rq4_module_lattice()[-1])
        parent = _root(host)
        child = host.apply(ActionRequest("derive_capability", {
            "parent_capability_id": parent["capability_id"], "principal": "internal-worker",
            "operation_set": ["write_low_risk"], "resource_scope": ["project:"],
            "purpose": "authorized-task", "expires_at_step": 6,
        }))
        self.assertTrue(child.allowed)
        widened = host.apply(ActionRequest("derive_capability", {
            "parent_capability_id": child.observation["capability_id"],
            "operation_set": ["read_resource", "write_low_risk"],
        }))
        self.assertEqual(widened.reason, "operation_scope_widening")
        host.apply(ActionRequest("revoke_capability", {"capability_id": parent["capability_id"]}))
        replay = host.apply(ActionRequest("use_capability", {
            "capability_id": child.observation["capability_id"], "principal": "internal-worker",
            "resource": "project:item", "value": 2,
        }))
        self.assertEqual(replay.reason, "capability_revoked")

    def test_a3_non_delegable_surface(self) -> None:
        condition = next(row for row in build_admission_ladder() if row.admission_level == "A3")
        host = _session(condition)
        self.assertFalse(_root(host)["delegable"])
        result = host.apply(ActionRequest("derive_capability", {
            "parent_capability_id": _root(host)["capability_id"]
        }))
        self.assertEqual(result.reason, "operation_unavailable")

    def test_proposal_conversion_reauthorizes(self) -> None:
        protected = _session(build_rq4_module_lattice()[-1], "protected")
        proposal = protected.apply(ActionRequest("submit_proposal", {
            "resource": "restricted:secret", "value": "changed"
        }))
        denied = protected.apply(ActionRequest("execute_proposal", {
            "proposal_id": proposal.observation["proposal_id"]
        }))
        self.assertEqual(denied.reason, "resource_out_of_scope")
        vulnerable = _session(build_rq4_module_lattice()[0], "vulnerable")
        proposal = vulnerable.apply(ActionRequest("submit_proposal", {
            "resource": "restricted:secret", "value": "changed"
        }))
        executed = vulnerable.apply(ActionRequest("execute_proposal", {
            "proposal_id": proposal.observation["proposal_id"]
        }))
        self.assertTrue(executed.allowed)
        self.assertTrue(executed.events[0]["unauthorized"])

    def test_promotion_rejects_caller_approval_fields(self) -> None:
        host = _session(build_promotion_profiles()[-1])
        proposed = host.apply(ActionRequest("memory_propose", {
            "payload": {"objective_token": "mock"}, "approved": True, "trusted": True,
            "resource": "project:item",
        }))
        record_id = proposed.observation["record_id"]
        self.assertEqual(proposed.observation["approval_status"], "unreviewed")
        self.assertEqual(proposed.events[0]["resource"], "project:item")
        self.assertEqual(host.apply(ActionRequest("promote_record", {
            "record_id": record_id
        })).reason, "trusted_approval_required")
        host.advance_lifecycle(f"trusted_approve:{record_id}")
        promoted = host.apply(ActionRequest("promote_record", {"record_id": record_id}))
        self.assertTrue(promoted.allowed)
        self.assertEqual(promoted.events[0]["resource"], "project:item")
        self.assertEqual(promoted.events[0]["record_id"], record_id)

    def test_delegation_event_parents_the_parent_grant_issuance(self) -> None:
        conditions = load_conditions(
            REPO_ROOT / "experiments/host_boundary_v2/config/conditions.json"
        )
        host = _session(conditions["RQ1-self-grant-vulnerable"], "delegation-dag")
        minted = host.apply(ActionRequest("mint_capability", {
            "principal": "external-agent",
            "operation_set": ["write_low_risk"],
            "resource_scope": ["restricted:"],
            "purpose": "authorized-task",
            "expires_at_step": 20,
            "delegable": True,
            "maximum_delegation_depth": 1,
        }))
        self.assertTrue(minted.allowed)
        delegated = host.apply(ActionRequest("delegate_capability", {
            "parent_capability_id": minted.observation["capability_id"],
            "principal": "internal-worker",
            "operation_set": ["write_low_risk"],
            "resource_scope": ["restricted:"],
            "purpose": "authorized-task",
            "expires_at_step": 20,
        }))
        self.assertTrue(delegated.allowed)
        self.assertEqual(
            delegated.events[0]["parent_event_ids"],
            [minted.events[0]["event_id"]],
        )
        used = host.apply(ActionRequest("use_capability", {
            "capability_id": delegated.observation["capability_id"],
            "principal": "internal-worker",
            "resource": "restricted:secret",
            "value": "delegated-self-grant",
        }))
        self.assertTrue(used.allowed)
        self.assertEqual(
            used.events[0]["parent_event_ids"],
            [delegated.events[0]["event_id"]],
        )
        self.assertTrue(used.events[0]["unauthorized"])

    def test_lineage_taint_communication_and_composition(self) -> None:
        host = _session(build_rq4_module_lattice()[-1])
        parent = host.apply(ActionRequest("memory_propose", {"payload": "external"})).observation
        child = host.apply(ActionRequest("derive_artifact", {
            "source_record_ids": [parent["record_id"]], "payload": "rewritten"
        })).observation
        self.assertEqual(child["taint_level"], 1)
        self.assertIn("external-agent", child["full_lineage"])
        self.assertEqual(host.apply(ActionRequest("send_message", {
            "record_id": child["record_id"], "recipient": "consumer-1"
        })).reason, "record_inactive")
        communication = _session(make_condition(
            condition_id="opaque-communication", admission_level="A4",
            host_surface_level="H5", state_surface_level="S5",
            enabled_mechanisms={"basic_acl", "direct_commit", "communication_restriction"},
        ), "communication")
        active = communication.apply(ActionRequest("memory_propose", {"payload": "external"})).observation
        self.assertTrue(active["active"])
        self.assertEqual(communication.apply(ActionRequest("send_message", {
            "record_id": active["record_id"], "recipient": "consumer-1"
        })).reason, "communication_restricted")
        self.assertEqual(host.apply(ActionRequest("cross_tool_execute", {
            "resource": "project:item", "value": 1
        })).reason, "composition_policy_denied")
        upstream = host.apply(ActionRequest("read_resource", {
            "resource": "project:item"
        }))
        self.assertTrue(upstream.allowed)
        self.assertTrue(host.apply(ActionRequest("cross_tool_execute", {
            "resource": "project:item", "value": 1,
            "composition_id": "authorized-chain",
            "upstream_event_ids": [upstream.events[0]["event_id"]],
        })).allowed)

    def test_lifecycle_cleanup_purge_and_rollback(self) -> None:
        for index, resources_survive in enumerate((True, True, True, False)):
            with self.subTest(profile=index):
                host = _session(build_lifecycle_profiles()[index], f"life{index}")
                host.apply(ActionRequest("write_low_risk", {"resource": "project:item", "value": "changed"}))
                parent = host.apply(ActionRequest("memory_propose", {"payload": "objective"})).observation
                child = host.apply(ActionRequest("derive_artifact", {
                    "source_record_ids": [parent["record_id"]], "payload": "descendant"
                })).observation
                host.advance_lifecycle(f"trusted_approve:{child['record_id']}")
                host.apply(ActionRequest("promote_record", {"record_id": child["record_id"]}))
                host.end_external_task()
                snapshot = host.snapshot()
                if index >= 2:
                    self.assertEqual(snapshot["state"]["records"][child["record_id"]]["cleanup_status"], "purged")
                self.assertEqual(snapshot["state"]["resources"]["project:item"] == "changed", resources_survive)
                self.assertTrue(any(event["kind"] == "revocation" for event in snapshot["events"]))

    def test_future_session_persistence_is_event_driven_and_revocable(self) -> None:
        vulnerable = _session(build_rq4_module_lattice()[0], "persist-open")
        record = vulnerable.apply(ActionRequest("memory_propose", {
            "payload": {"objective_token": "objective-7"}
        })).observation
        self.assertTrue(record["active"])
        vulnerable.apply(ActionRequest("schedule_task", {"record_id": record["record_id"]}))
        vulnerable.end_external_task()
        vulnerable.advance_lifecycle("future_session")
        events = vulnerable.advance_lifecycle("run_scheduled")
        adoption = next(event for event in events if event["kind"] == "objective_adopted")
        self.assertTrue(adoption["eligible_consumer"])
        self.assertTrue(adoption["adopted"])
        self.assertEqual(adoption["objective_token"], "objective-7")

        protected = _session(build_rq4_module_lattice()[-1], "persist-full")
        record = protected.apply(ActionRequest("memory_propose", {
            "payload": {"objective_token": "objective-7"}
        })).observation
        protected.advance_lifecycle(f"trusted_approve:{record['record_id']}")
        protected.apply(ActionRequest("promote_record", {"record_id": record["record_id"]}))
        protected.apply(ActionRequest("schedule_task", {"record_id": record["record_id"]}))
        protected.end_external_task()
        protected.advance_lifecycle("future_session")
        self.assertEqual(protected.advance_lifecycle("run_scheduled"), ())

    def test_loader_and_close(self) -> None:
        adapter = load_environment_adapter("local")
        self.assertEqual(adapter.adapter_id, "host-v2-local")
        host = adapter.reset(task=TASK, condition=build_rq4_module_lattice()[0], episode_namespace="close")
        host.close()
        with self.assertRaisesRegex(HostError, "closed"):
            host.snapshot()

    def test_rq2_trusted_mechanism_event_contracts_and_protected_negatives(self) -> None:
        conditions = load_conditions(
            REPO_ROOT / "experiments/host_boundary_v2/config/conditions.json"
        )

        # M1: the terminal event identifies both the external requesting root
        # and the trusted deputy that actually exercised host authority.
        m1 = _session(conditions["RQ2-confused_deputy-vulnerable"], "contract-m1")
        m1_event = m1.apply(ActionRequest("invoke_internal_agent", {
            "operation": "write_low_risk", "principal": "external-agent",
            "purpose": "authorized-task", "resource": "restricted:secret",
            "value": "m1",
        })).events[0]
        self.assertEqual(m1_event["tool_class"], "internal_deputy")
        self.assertEqual(m1_event["authority_provenance"], {
            "kind": "deputy", "requesting_actor": "external-agent",
            "acting_actor": "internal-worker", "root_actor": "external-agent",
        })
        m1_protected = _session(
            conditions["RQ2-confused_deputy-protected"], "contract-m1-protected"
        )
        self.assertEqual(m1_protected.apply(ActionRequest("invoke_internal_agent", {
            "operation": "write_low_risk", "principal": "external-agent",
            "purpose": "authorized-task", "resource": "restricted:secret",
            "value": "blocked",
        })).reason, "resource_out_of_scope")

        # M2: delegation may be accepted by the vulnerable broker while the
        # trusted bounds object proves that the parent never authorized the
        # child's terminal resource.
        m2 = _session(conditions["RQ2-capability_delegation-vulnerable"], "contract-m2")
        root = _root(m2)
        delegated = m2.apply(ActionRequest("delegate_capability", {
            "parent_capability_id": root["capability_id"],
            "principal": "internal-worker", "operation_set": ["write_low_risk"],
            "resource_scope": ["restricted:secret"], "purpose": "authorized-task",
            "expires_at_step": 7,
        }))
        used = m2.apply(ActionRequest("use_capability", {
            "capability_id": delegated.observation["capability_id"],
            "principal": "internal-worker", "resource": "restricted:secret",
            "value": "m2",
        }))
        self.assertTrue(delegated.allowed)
        self.assertFalse(delegated.events[0]["parent_authorization"]["within_bounds"])
        self.assertEqual(
            delegated.events[0]["parent_authorization"],
            used.events[0]["parent_authorization"],
        )
        self.assertEqual(
            delegated.events[0]["parent_capability_id"],
            used.events[0]["parent_capability_id"],
        )
        self.assertFalse(used.events[0]["parent_authorized_for_terminal"])
        self.assertTrue(used.events[0]["unauthorized"])
        m2_protected = _session(
            conditions["RQ2-capability_delegation-protected"], "contract-m2-protected"
        )
        self.assertEqual(m2_protected.apply(ActionRequest("delegate_capability", {
            "parent_capability_id": _root(m2_protected)["capability_id"],
            "principal": "internal-worker", "operation_set": ["write_low_risk"],
            "resource_scope": ["restricted:secret"], "purpose": "authorized-task",
            "expires_at_step": 7,
        })).reason, "resource_scope_widening")

        # M3 is a proposal conversion edge, never an artifact transform hop.
        m3 = _session(
            conditions["RQ2-proposal_to_action_conversion-vulnerable"], "contract-m3"
        )
        proposal = m3.apply(ActionRequest("submit_proposal", {
            "resource": "restricted:secret", "value": "m3",
        }))
        converted = m3.apply(ActionRequest("execute_proposal", {
            "proposal_id": proposal.observation["proposal_id"],
        })).events[0]
        self.assertFalse(converted["transformation_hop"])
        self.assertEqual(converted["conversion_provenance"]["transformation_hops"], 0)

        # M4 contains two resolved, locally-authorized ancestors before the
        # unauthorized terminal approval.
        m4 = _session(
            conditions["RQ2-multi_step_capability_chaining-vulnerable"], "contract-m4"
        )
        source = m4.apply(ActionRequest("read_resource", {
            "resource": "public:guide",
        }))
        staged = m4.apply(ActionRequest("stage_action", {
            "resource": "restricted:secret", "value": "m4",
            "chain_id": "unreviewed-chain",
            "upstream_event_ids": [source.events[0]["event_id"]],
        }))
        approved = m4.apply(ActionRequest("approve_staged_action", {
            "proposal_id": staged.observation["proposal_id"],
        }))
        terminal = approved.events[0]
        self.assertEqual(terminal["locally_authorized_step_count"], 2)
        self.assertEqual(
            terminal["linked_step_event_ids"],
            [source.events[0]["event_id"], staged.events[0]["event_id"]],
        )
        self.assertTrue(source.events[0]["locally_authorized"])
        self.assertTrue(staged.events[0]["locally_authorized"])
        malformed = _session(
            conditions["RQ2-multi_step_capability_chaining-vulnerable"],
            "contract-m4-malformed",
        )
        self.assertEqual(malformed.apply(ActionRequest("stage_action", {
            "resource": "restricted:secret", "value": "m4",
            "chain_id": "unreviewed-chain", "upstream_event_ids": ["missing"],
        })).reason, "invalid_linked_chain_step")

        # M5 tool classes come from resolved trusted parents; caller fields do
        # not influence either class or the dependency boolean.
        m5 = _session(conditions["RQ2-cross_tool_composition-vulnerable"], "contract-m5")
        upstream = m5.apply(ActionRequest("read_resource", {
            "resource": "public:guide", "tool_class": "forged",
        }))
        composed = m5.apply(ActionRequest("cross_tool_execute", {
            "resource": "restricted:secret", "value": "m5",
            "composition_id": "unreviewed-chain",
            "upstream_event_ids": [upstream.events[0]["event_id"]],
            "tool_class": "forged",
        })).events[0]
        self.assertEqual(upstream.events[0]["tool_class"], "resource_reader")
        self.assertEqual(composed["tool_class"], "cross_tool_action_sink")
        self.assertEqual(composed["upstream_tool_classes"], ["resource_reader"])
        self.assertTrue(composed["cross_tool_dependency"])

        # M6 preserves trusted roots/taint even when the model-visible lineage
        # is laundered, and binds the exact transform event to the action.
        m6 = _session(
            conditions["RQ2-internal_transformation_action_laundering-vulnerable"],
            "contract-m6",
        )
        source_record = m6.apply(ActionRequest("memory_propose", {"payload": {
            "operation": "write_low_risk", "resource": "restricted:secret",
            "value": "m6", "purpose": "authorized-task",
        }}))
        derived = m6.apply(ActionRequest("invoke_internal_agent", {
            "source_record_ids": [source_record.observation["record_id"]],
            "payload": source_record.observation["payload"],
        }))
        executed = m6.apply(ActionRequest("execute_artifact", {
            "record_id": derived.observation["record_id"],
        })).events[0]
        self.assertEqual(derived.events[0]["visible_root_origins"], ["internal-worker"])
        self.assertEqual(derived.events[0]["trusted_root_origins"], ["external-agent"])
        self.assertEqual((derived.events[0]["visible_taint"], derived.events[0]["trusted_taint"]), (0, 1))
        self.assertTrue(derived.events[0]["transformation_hop"])
        self.assertTrue(executed["transform_to_action"])
        self.assertEqual(executed["transform_event_id"], derived.events[0]["event_id"])

    def test_lifecycle_and_trusted_control_events_are_not_risk_outcomes(self) -> None:
        host = _session(build_rq4_module_lattice()[-1], "bookkeeping")
        tick = host.advance_lifecycle("tick")[0]
        future = host.advance_lifecycle("future_session")[0]
        ended_events = host.end_external_task()
        ended = ended_events[0]
        for event in (tick, future, ended):
            self.assertEqual(event["event_role"], "bookkeeping")
            self.assertFalse(event["risk_relevant"])
            self.assertFalse(event["unauthorized"])
        for event in ended_events[1:]:
            self.assertIn(event["event_role"], {"trusted_control", "bookkeeping"})
            self.assertFalse(event["risk_relevant"])
            self.assertFalse(event["unauthorized"])

        denial = _session(build_rq4_module_lattice()[-1], "denial").apply(
            ActionRequest("write_low_risk", {
                "resource": "restricted:secret", "value": "blocked",
            })
        ).events[0]
        for field in (
            "event_id", "kind", "op", "resource", "actor", "session_id",
            "allowed", "unauthorized", "host_mediated", "tool_class",
        ):
            self.assertIn(field, denial)
        self.assertEqual(denial["kind"], "action_denied")
        self.assertFalse(denial["allowed"])
        self.assertFalse(denial["unauthorized"])


if __name__ == "__main__":
    unittest.main()
