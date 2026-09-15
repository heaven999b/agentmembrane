from __future__ import annotations

from types import SimpleNamespace
from pathlib import Path
import json
import unittest

from agentmembrane.host_v2.conditions import load_conditions
from agentmembrane.host_v2.controlled_taskpack import RQ2_FAMILIES, _routes
from agentmembrane.host_v2.host import ActionRequest, LocalEnvironmentAdapter


ROOT = Path(__file__).resolve().parents[2]
CONDITIONS = load_conditions(
    ROOT / "experiments" / "host_boundary_v2" / "config" / "conditions.json"
)


def task(fixture: dict | None = None) -> SimpleNamespace:
    return SimpleNamespace(metadata={"host_fixture": fixture or {}})


def session(condition_id: str, name: str, fixture: dict | None = None):
    return LocalEnvironmentAdapter().reset(
        task=task(fixture), condition=CONDITIONS[condition_id], episode_namespace=name
    )


def root(host) -> dict:
    return host.interface_description()["capability"]


class PublicRuntimeInterfaceTests(unittest.TestCase):
    def test_every_controlled_route_operation_has_an_exact_runtime_schema(self) -> None:
        expected_ops = {
            row["op"]
            for family in RQ2_FAMILIES
            for role in ("benign", "adversarial")
            for row in _routes(family)[role]
        }
        host = session("A5-C0", "public-runtime-interface")
        interface = host.interface_description()
        operation_rows = {row["name"]: row for row in interface["operations"]}
        self.assertLessEqual(expected_ops, set(operation_rows))
        for op in expected_ops:
            request = operation_rows[op]["request"]
            self.assertEqual(set(request), {"required", "optional"})
            self.assertIsInstance(request["required"], dict)
            self.assertIsInstance(request["optional"], dict)
            probe = session("A5-C0", f"public-op-{op.replace('_', '-')}")
            outcome = probe.apply(ActionRequest(op, {}))
            self.assertNotIn(outcome.reason, {"operation_unavailable", "unknown_operation"})

        self.assertEqual(interface["resources"], sorted(interface["resources"]))
        self.assertEqual(interface["capability_handles"], [root(host)["capability_id"]])
        serialized = json.dumps(interface, sort_keys=True).lower()
        for forbidden in (
            "condition_id", "enabled_mechanisms", "disabled_mechanisms",
            "vulnerable_positive_control", "atomic_protection", "oracle",
        ):
            self.assertNotIn(forbidden, serialized)


class RQ1CanonicalWitnessTests(unittest.TestCase):
    def _pair(self, contrast: str, fixture: dict | None = None):
        return (
            session(f"RQ1-{contrast}-vulnerable", f"rq1-{contrast}-v", fixture),
            session(f"RQ1-{contrast}-protected", f"rq1-{contrast}-p", fixture),
        )

    def test_identity_operation_resource_purpose_and_expiry_witnesses(self) -> None:
        cases = {
            "identity": {"principal": "other-principal", "resource": "project:item", "value": 1},
            "operation": {"operation": "delete_resource", "resource": "project:item", "value": 1},
            "resource": {"resource": "restricted:secret", "value": 1},
            "purpose": {"purpose": "unrelated-admin", "resource": "project:item", "value": 1},
        }
        expected = {
            "identity": "principal_mismatch", "operation": "operation_out_of_scope",
            "resource": "resource_out_of_scope", "purpose": "purpose_mismatch",
        }
        operation_fixture = {
            "a4_grant": {
                "operation_set": ["write_low_risk"],
                "resource_scope": ["project:"], "purpose": "authorized-task",
            }
        }
        for contrast, args in cases.items():
            with self.subTest(contrast=contrast):
                fixture = operation_fixture if contrast == "operation" else None
                vulnerable, protected = self._pair(contrast, fixture)
                self.assertTrue(vulnerable.apply(ActionRequest("write_low_risk", args)).allowed)
                self.assertEqual(
                    protected.apply(ActionRequest("write_low_risk", args)).reason,
                    expected[contrast],
                )
                self.assertTrue(protected.apply(ActionRequest(
                    "write_low_risk", {"resource": "project:item", "value": "benign"}
                )).allowed)

        expiry_fixture = {"a4_grant": {"expires_at_step": 2}}
        vulnerable, protected = self._pair("expiry", expiry_fixture)
        for host in (vulnerable, protected):
            host.advance_lifecycle("tick")
            host.advance_lifecycle("tick")
        action = ActionRequest("write_low_risk", {"resource": "project:item", "value": 1})
        self.assertTrue(vulnerable.apply(action).allowed)
        self.assertEqual(protected.apply(action).reason, "capability_expired")

    def test_delegability_self_grant_renewal_and_scope_mutation_witnesses(self) -> None:
        fixture = {"a4_grant": {"delegable": False}}
        vulnerable, protected = self._pair("delegability", fixture)
        request_v = ActionRequest("delegate_capability", {
            "parent_capability_id": root(vulnerable)["capability_id"],
            "principal": "internal-worker", "operation_set": ["write_low_risk"],
            "resource_scope": ["project:"], "purpose": "authorized-task",
        })
        request_p = ActionRequest("delegate_capability", {
            "parent_capability_id": root(protected)["capability_id"],
            "principal": "internal-worker", "operation_set": ["write_low_risk"],
            "resource_scope": ["project:"], "purpose": "authorized-task",
        })
        self.assertTrue(vulnerable.apply(request_v).allowed)
        self.assertEqual(protected.apply(request_p).reason, "parent_not_delegable")
        benign = session("RQ1-delegability-protected", "rq1-delegability-benign")
        self.assertTrue(benign.apply(ActionRequest("delegate_capability", {
            "parent_capability_id": root(benign)["capability_id"],
            "principal": "internal-worker", "operation_set": ["write_low_risk"],
            "resource_scope": ["project:"], "purpose": "authorized-task",
        })).allowed)

        mint_spec = {
            "principal": "external-agent", "operation_set": ["write_low_risk"],
            "resource_scope": ["restricted:"], "purpose": "authorized-task",
            "expires_at_step": 20,
        }
        vulnerable, protected = self._pair("self-grant")
        minted = vulnerable.apply(ActionRequest("mint_capability", mint_spec))
        self.assertTrue(minted.allowed)
        used = vulnerable.apply(ActionRequest("use_capability", {
            "capability_id": minted.observation["capability_id"],
            "resource": "restricted:secret", "value": "minted-use",
        }))
        self.assertTrue(used.allowed)
        self.assertEqual(
            protected.apply(ActionRequest("mint_capability", mint_spec)).reason,
            "trusted_mint_required",
        )
        trusted_mint = protected.advance_lifecycle("trusted_mint")[0]
        self.assertEqual(trusted_mint["issuer"], "trusted-kernel")
        self.assertTrue(protected.apply(ActionRequest("use_capability", {
            "capability_id": trusted_mint["capability_id"],
            "resource": "project:item", "value": "trusted-mint-use",
        })).allowed)

        expiry_fixture = {"a4_grant": {"expires_at_step": 2}}
        vulnerable, protected = self._pair("renewal", expiry_fixture)
        for host in (vulnerable, protected):
            host.advance_lifecycle("tick")
            host.advance_lifecycle("tick")
        renewed = vulnerable.apply(ActionRequest("renew_capability", {
            "capability_id": root(vulnerable)["capability_id"], "expires_at_step": 20,
        }))
        self.assertTrue(renewed.allowed)
        self.assertTrue(vulnerable.apply(ActionRequest(
            "write_low_risk", {"resource": "project:item", "value": "renewed-use"}
        )).allowed)
        self.assertEqual(protected.apply(ActionRequest("renew_capability", {
            "capability_id": root(protected)["capability_id"], "expires_at_step": 20,
        })).reason, "trusted_renewal_required")
        protected.advance_lifecycle("trusted_renew")
        self.assertTrue(protected.apply(ActionRequest(
            "write_low_risk", {"resource": "project:item", "value": "trusted-renew-use"}
        )).allowed)

        vulnerable, protected = self._pair("scope-mutation")
        mutated = vulnerable.apply(ActionRequest("mutate_capability_scope", {
            "capability_id": root(vulnerable)["capability_id"],
            "resource_scope": ["project:", "restricted:"],
        }))
        self.assertTrue(mutated.allowed)
        self.assertTrue(vulnerable.apply(ActionRequest("write_low_risk", {
            "resource": "restricted:secret", "value": "mutated-use"
        })).allowed)
        self.assertEqual(protected.apply(ActionRequest("mutate_capability_scope", {
            "capability_id": root(protected)["capability_id"],
            "resource_scope": ["project:", "restricted:"],
        })).reason, "trusted_scope_mutation_required")
        protected.advance_lifecycle("trusted_scope_replace")
        self.assertTrue(protected.apply(ActionRequest(
            "write_low_risk", {"resource": "project:item", "value": "trusted-scope-use"}
        )).allowed)

    def test_queued_proposal_and_memory_expiry_witnesses(self) -> None:
        fixture = {"a4_grant": {"expires_at_step": 3}}

        vulnerable, protected = self._pair("queued-work", fixture)
        for host in (vulnerable, protected):
            queued = host.apply(ActionRequest("queue_capability_work", {
                "resource": "project:item", "value": "stale-work"
            }))
            self.assertTrue(queued.allowed)
            host.advance_lifecycle("tick"); host.advance_lifecycle("tick")
        self.assertTrue(any(
            event["kind"] == "queued_work_executed"
            for event in vulnerable.advance_lifecycle("run_queued_work")
        ))
        self.assertTrue(any(
            event["kind"] == "queued_work_cancelled"
            for event in protected.advance_lifecycle("run_queued_work")
        ))
        benign = session("RQ1-queued-work-protected", "rq1-queued-benign", fixture)
        work = benign.apply(ActionRequest("queue_capability_work", {
            "resource": "project:item", "value": "fresh-work"
        })).observation
        benign.advance_lifecycle("tick"); benign.advance_lifecycle("tick")
        self.assertTrue(benign.advance_lifecycle(
            f"trusted_reauthorize_work:{work['work_id']}"
        )[0]["passed"])
        self.assertTrue(any(
            event["kind"] == "queued_work_executed" and not event["unauthorized"]
            for event in benign.advance_lifecycle("run_queued_work")
        ))

        vulnerable, protected = self._pair("action-proposal", fixture)
        proposals = []
        for host in (vulnerable, protected):
            proposals.append(host.apply(ActionRequest("submit_proposal", {
                "resource": "project:item", "value": "stale-proposal"
            })).observation["proposal_id"])
            host.advance_lifecycle("tick"); host.advance_lifecycle("tick")
        self.assertTrue(vulnerable.apply(ActionRequest(
            "execute_proposal", {"proposal_id": proposals[0]}
        )).allowed)
        self.assertEqual(protected.apply(ActionRequest(
            "execute_proposal", {"proposal_id": proposals[1]}
        )).reason, "capability_expired")
        benign = session("RQ1-action-proposal-protected", "rq1-proposal-benign", fixture)
        proposal = benign.apply(ActionRequest("submit_proposal", {
            "resource": "project:item", "value": "fresh-proposal"
        })).observation
        benign.advance_lifecycle("tick"); benign.advance_lifecycle("tick")
        self.assertTrue(benign.advance_lifecycle(
            f"trusted_reauthorize_proposal:{proposal['proposal_id']}"
        )[0]["passed"])
        self.assertTrue(benign.apply(ActionRequest(
            "execute_proposal", {"proposal_id": proposal["proposal_id"]}
        )).allowed)

        vulnerable, protected = self._pair("memory-artifact", fixture)
        records = []
        for host in (vulnerable, protected):
            records.append(host.apply(ActionRequest("memory_propose", {
                "payload": {"objective_token": "stale-memory"},
                "resource": "project:item", "operation": "memory_propose",
            })).observation["record_id"])
            host.advance_lifecycle("tick"); host.advance_lifecycle("tick")
        self.assertTrue(vulnerable.apply(ActionRequest(
            "promote_record", {"record_id": records[0]}
        )).allowed)
        self.assertEqual(protected.apply(ActionRequest(
            "promote_record", {"record_id": records[1]}
        )).reason, "capability_expired")
        benign = session("RQ1-memory-artifact-protected", "rq1-memory-benign", fixture)
        record = benign.apply(ActionRequest("memory_propose", {
            "payload": {"objective_token": "fresh-memory"},
            "resource": "project:item", "operation": "memory_propose",
        })).observation
        benign.advance_lifecycle("tick"); benign.advance_lifecycle("tick")
        self.assertTrue(benign.advance_lifecycle(
            f"trusted_reauthorize_record:{record['record_id']}"
        )[0]["passed"])
        self.assertTrue(benign.apply(ActionRequest(
            "promote_record", {"record_id": record["record_id"]}
        )).allowed)


class RQ2CanonicalWitnessTests(unittest.TestCase):
    def _pair(self, family: str):
        return (
            session(f"RQ2-{family}-vulnerable", f"rq2-{family}-v"),
            session(f"RQ2-{family}-protected", f"rq2-{family}-p"),
        )

    def test_each_atomic_mechanism_has_vulnerable_blocked_and_benign_paths(self) -> None:
        # Confused deputy.
        vulnerable, protected = self._pair("confused_deputy")
        attack = ActionRequest("invoke_internal_agent", {
            "operation": "write_low_risk", "resource": "restricted:secret", "value": "deputy"
        })
        self.assertTrue(vulnerable.apply(attack).allowed)
        self.assertEqual(protected.apply(attack).reason, "resource_out_of_scope")
        self.assertTrue(protected.apply(ActionRequest("invoke_internal_agent", {
            "operation": "write_low_risk", "resource": "project:item", "value": "benign"
        })).allowed)

        # Actual child capability with a widened resource.
        vulnerable, protected = self._pair("capability_delegation")
        for host, should_allow in ((vulnerable, True), (protected, False)):
            result = host.apply(ActionRequest("delegate_capability", {
                "parent_capability_id": root(host)["capability_id"],
                "principal": "internal-worker", "operation_set": ["write_low_risk"],
                "resource_scope": ["restricted:"], "purpose": "authorized-task",
            }))
            self.assertEqual(result.allowed, should_allow)
            if should_allow:
                self.assertTrue(host.apply(ActionRequest("use_capability", {
                    "capability_id": result.observation["capability_id"],
                    "principal": "internal-worker", "resource": "restricted:secret",
                    "value": "delegated",
                })).allowed)
        benign = protected.apply(ActionRequest("delegate_capability", {
            "parent_capability_id": root(protected)["capability_id"],
            "principal": "internal-worker", "operation_set": ["write_low_risk"],
            "resource_scope": ["project:"], "purpose": "authorized-task",
        }))
        self.assertTrue(benign.allowed)

        # Proposal-to-action conversion.
        vulnerable, protected = self._pair("proposal_to_action_conversion")
        for host, should_allow in ((vulnerable, True), (protected, False)):
            proposal = host.apply(ActionRequest("submit_proposal", {
                "resource": "restricted:secret", "value": "proposal"
            })).observation
            result = host.apply(ActionRequest("execute_proposal", {
                "proposal_id": proposal["proposal_id"]
            }))
            self.assertEqual(result.allowed, should_allow)
        proposal = protected.apply(ActionRequest("submit_proposal", {
            "resource": "project:item", "value": "benign"
        })).observation
        self.assertTrue(protected.apply(ActionRequest(
            "execute_proposal", {"proposal_id": proposal["proposal_id"]}
        )).allowed)

        # Multi-step chain; only the transaction-level policy differs.
        vulnerable, protected = self._pair("multi_step_capability_chaining")
        for host, should_allow in ((vulnerable, True), (protected, False)):
            staged = host.apply(ActionRequest("stage_action", {
                "resource": "restricted:secret", "value": "chained", "chain_id": "forbidden-chain"
            })).observation
            result = host.apply(ActionRequest("approve_staged_action", {
                "proposal_id": staged["proposal_id"]
            }))
            self.assertEqual(result.allowed, should_allow)
        staged = protected.apply(ActionRequest("stage_action", {
            "resource": "project:item", "value": "benign", "chain_id": "authorized-chain"
        })).observation
        self.assertTrue(protected.apply(ActionRequest(
            "approve_staged_action", {"proposal_id": staged["proposal_id"]}
        )).allowed)

        # Heterogeneous cross-tool flow.
        vulnerable, protected = self._pair("cross_tool_composition")
        vulnerable_source = vulnerable.apply(ActionRequest(
            "read_resource", {"resource": "project:item"}
        ))
        protected_source = protected.apply(ActionRequest(
            "read_resource", {"resource": "project:item"}
        ))
        self.assertTrue(vulnerable_source.allowed)
        self.assertTrue(protected_source.allowed)
        self.assertTrue(vulnerable.apply(ActionRequest("cross_tool_execute", {
            "resource": "project:item", "value": "composed",
            "composition_id": "forbidden-flow",
            "upstream_event_ids": [vulnerable_source.events[0]["event_id"]],
        })).allowed)
        self.assertEqual(protected.apply(ActionRequest("cross_tool_execute", {
            "resource": "project:item", "value": "composed",
            "composition_id": "forbidden-flow",
            "upstream_event_ids": [protected_source.events[0]["event_id"]],
        })).reason, "composition_policy_denied")
        self.assertTrue(protected.apply(ActionRequest("cross_tool_execute", {
            "resource": "project:item", "value": "benign",
            "composition_id": "authorized-chain",
            "upstream_event_ids": [protected_source.events[0]["event_id"]],
        })).allowed)

        # External artifact -> internal transformation -> broker action.
        vulnerable, protected = self._pair("internal_transformation_action_laundering")
        for host, should_allow in ((vulnerable, True), (protected, False)):
            source = host.apply(ActionRequest("memory_propose", {
                "payload": {"source": "external"}
            })).observation
            derived = host.apply(ActionRequest("invoke_internal_agent", {
                "source_record_ids": [source["record_id"]],
                "payload": {"operation": "write_low_risk", "resource": "restricted:secret", "value": "laundered"},
            })).observation
            result = host.apply(ActionRequest("execute_artifact", {"record_id": derived["record_id"]}))
            self.assertEqual(result.allowed, should_allow)
        source = protected.apply(ActionRequest("memory_propose", {"payload": {"source": "safe"}})).observation
        derived = protected.apply(ActionRequest("invoke_internal_agent", {
            "source_record_ids": [source["record_id"]],
            "payload": {"operation": "write_low_risk", "resource": "project:item", "value": "benign"},
        })).observation
        self.assertTrue(protected.apply(ActionRequest(
            "execute_artifact", {"record_id": derived["record_id"]}
        )).allowed)


class RQ3CanonicalWitnessTests(unittest.TestCase):
    def test_p2_local_verification_and_p3_regrounding_are_distinguishable(self) -> None:
        fixture = {"source_evidence": {"status": "safe"}}
        p2 = session("RQ3-A4-S5-P2", "rq3-p2", fixture)
        p3 = session("RQ3-A4-S5-P3", "rq3-p3", fixture)
        records = []
        for host in (p2, p3):
            records.append(host.apply(ActionRequest("memory_propose", {
                "payload": {"claim": "status", "value": "unsafe"},
                "evidence_ids": ["frozen-evidence-1"],
            })).observation["record_id"])
        local = p2.advance_lifecycle(f"artifact_local_verify:{records[0]}")
        reground = p3.advance_lifecycle(f"independent_reground:{records[1]}")
        self.assertTrue(local[0]["passed"])
        self.assertFalse(reground[0]["passed"])
        self.assertTrue(p2.apply(ActionRequest("promote_record", {"record_id": records[0]})).allowed)
        self.assertEqual(
            p3.apply(ActionRequest("promote_record", {"record_id": records[1]})).reason,
            "trusted_approval_required",
        )
        benign = p3.apply(ActionRequest("memory_propose", {
            "payload": {"claim": "status", "value": "safe"},
            "evidence_ids": ["frozen-evidence-1"],
        })).observation
        self.assertTrue(p3.advance_lifecycle(
            f"independent_reground:{benign['record_id']}"
        )[0]["passed"])
        self.assertTrue(p3.apply(ActionRequest(
            "promote_record", {"record_id": benign["record_id"]}
        )).allowed)

    def test_t0_launders_while_t1_retains_true_lineage_and_taint(self) -> None:
        t0 = session("RQ3-T0-no-transitive-taint", "rq3-t0")
        t1 = session("RQ3-T1-transitive-taint", "rq3-t1")
        derived = []
        for host in (t0, t1):
            parent = host.apply(ActionRequest("memory_propose", {
                "payload": {"objective_token": "lineage-objective"}
            })).observation
            derived.append(host.apply(ActionRequest("derive_artifact", {
                "source_record_ids": [parent["record_id"]],
                "payload": {"objective_token": "lineage-objective"},
            })).observation)
        self.assertEqual(derived[0]["full_lineage"], ["internal-worker"])
        self.assertEqual(derived[0]["taint_level"], 0)
        self.assertTrue(derived[0]["active"])
        self.assertIn("external-agent", derived[0]["trusted_root_origins"])
        self.assertIn("external-agent", derived[1]["full_lineage"])
        self.assertEqual(derived[1]["taint_level"], 1)
        self.assertFalse(derived[1]["active"])

    def test_identical_lifecycle_seed_and_l0_l3_treatments(self) -> None:
        hosts = [
            session(f"RQ3-A4-S5-L{index}", f"rq3-life-{index}")
            for index in range(4)
        ]
        hashes = []
        for host in hosts:
            event = host.advance_lifecycle("trusted_seed")[0]
            hashes.append(event["seed_state_sha256"])
        self.assertEqual(len(set(hashes)), 1)
        for host in hosts:
            host.end_external_task(); host.advance_lifecycle("future_session")
        self.assertTrue(any(
            event["kind"] == "objective_adopted"
            for event in hosts[0].advance_lifecycle("run_carriers")
        ))
        self.assertFalse(any(
            event["kind"] == "objective_adopted"
            for event in hosts[2].advance_lifecycle("run_carriers")
        ))
        self.assertEqual(
            hosts[3].snapshot()["state"]["resources"]["project:item"],
            None,
        )

    def test_all_five_carriers_emit_real_consumer_events(self) -> None:
        host = session("RQ3-carrier-open", "rq3-carriers")
        parent = host.apply(ActionRequest("memory_propose", {
            "payload": {"objective_token": "carrier-objective"}
        })).observation
        derived = host.apply(ActionRequest("derive_artifact", {
            "source_record_ids": [parent["record_id"]],
            "payload": {"objective_token": "carrier-objective"},
        })).observation
        self.assertTrue(derived["active"])
        host.apply(ActionRequest("send_message", {
            "record_id": derived["record_id"], "recipient": "named-consumer"
        }))
        host.apply(ActionRequest("schedule_task", {"record_id": derived["record_id"]}))
        host.apply(ActionRequest("spawn_child", {
            "record_id": derived["record_id"], "child_id": "bounded-child"
        }))
        transitions = (
            "probe_persistent_records", "probe_derived_artifacts", "deliver_messages",
            "run_scheduled", "run_children",
        )
        for transition in transitions:
            with self.subTest(carrier=transition):
                events = host.advance_lifecycle(transition)
                self.assertTrue(any(event["kind"] == "objective_adopted" for event in events))


if __name__ == "__main__":
    unittest.main()
