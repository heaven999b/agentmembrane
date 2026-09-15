from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from agentmembrane.host_v2.schema import (
    SchemaError,
    profile_stage_contract,
    validate_json,
)


_V21_IDENTITY = {
    "construct_id": "host_mediated_capability_exploitation",
    "proposal_alignment": "RQ1b_host_mediated",
    "legacy_experiment_id": "HB-RQ2-HCE",
    "legacy_analysis_family": "RQ2",
    "answers_canonical_proposal_rq2": False,
    "pooling_with_semantic_rq2_permitted": False,
}

_CANONICAL_RQ1_IDENTITY = {
    "construct_id": "authority_admission_boundary",
    "construct_version": "1.0.0",
    "proposal_alignment": "RQ1_authority_admission",
    "ladder_id": "authority_admission_a0_a5",
    "ladder_version": "1.0.0",
}


def _legacy_gate_profile() -> dict:
    path = Path(
        "experiments/host_boundary_v2/config/profiles/rq2-g0-gate.template.json"
    )
    return json.loads(path.read_text(encoding="utf-8"))


def _v21_stage_s_profile() -> dict:
    value = _legacy_gate_profile()
    value.update(
        {
            "protocol_id": "host-boundary-v2.1",
            **_V21_IDENTITY,
            "execution_stage": "protocol_stage_s",
            "protocol_stage": "S",
            "h_ladder_covered": False,
            "scientific_sample_gate_satisfied": False,
        }
    )
    value["gates"].pop("gate_stage", None)
    return value


def _v21_atomic_profile() -> dict:
    value = _v21_stage_s_profile()
    value.update(
        execution_stage="atomic_synthetic_bringup",
        protocol_stage=None,
        run_kind="scripted",
        visible_context_profile="objective_aware_adaptive",
        offline_assay_binding={
            "taskpack_byte_tree_sha256": "1" * 64,
            "taskpack_logical_content_sha256": "2" * 64,
            "tasks_sha256": "3" * 64,
            "output_namespace": "atomic-output-v1",
            "cache_namespace": "atomic-cache-v1",
            "provider_calls_permitted": False,
            "model_calls_permitted": False,
            "formal_run_permitted": False,
            "external_run_authorized": False,
        },
    )
    return value


def _canonical_rq1_adaptive_profile() -> dict:
    value = _legacy_gate_profile()
    value["gates"].pop("gate_stage", None)
    value["run_kind"] = "formal"
    value.update(
        {
            **_CANONICAL_RQ1_IDENTITY,
            "execution_stage": "formal",
            "protocol_stage": None,
            "h_ladder_covered": False,
            "scientific_sample_gate_satisfied": False,
            "visible_context_profile": "objective_aware_adaptive",
            "execution_track": "adaptive_end_to_end",
        }
    )
    return value


class ProfileStageSchemaTests(unittest.TestCase):
    def test_legacy_read_normalizes_missing_stage_gates_false(self) -> None:
        value = _legacy_gate_profile()
        validate_json(value, schema_name="profile")
        self.assertEqual(
            profile_stage_contract(value),
            {
                "execution_stage": None,
                "protocol_stage": None,
                "h_ladder_covered": False,
                "scientific_sample_gate_satisfied": False,
                "legacy_compatibility": True,
            },
        )

    def test_v21_full_contract_loads_without_legacy_gate_stage(self) -> None:
        value = _v21_stage_s_profile()
        validate_json(value, schema_name="profile")
        self.assertEqual(profile_stage_contract(value)["protocol_stage"], "S")

    def test_v21_contract_is_all_or_none_and_identity_is_exact(self) -> None:
        partial = _legacy_gate_profile()
        partial["construct_id"] = "host_mediated_capability_exploitation"
        with self.assertRaisesRegex(SchemaError, "all-or-none"):
            validate_json(partial, schema_name="profile")

        wrong = _v21_stage_s_profile()
        wrong["answers_canonical_proposal_rq2"] = True
        with self.assertRaisesRegex(SchemaError, "must equal False"):
            validate_json(wrong, schema_name="profile")

    def test_v21_stage_mapping_and_nonclaim_rules_fail_closed(self) -> None:
        wrong_protocol_stage = _v21_stage_s_profile()
        wrong_protocol_stage["protocol_stage"] = "G"
        with self.assertRaisesRegex(SchemaError, "execution_stage"):
            validate_json(wrong_protocol_stage, schema_name="profile")

        claim = _v21_stage_s_profile()
        claim["claim_bearing"] = True
        with self.assertRaisesRegex(SchemaError, "non-formal"):
            validate_json(claim, schema_name="profile")

        legacy_label = _v21_stage_s_profile()
        legacy_label["gates"]["gate_stage"] = "G2"
        with self.assertRaisesRegex(SchemaError, "legacy G0/G1/G2"):
            validate_json(legacy_label, schema_name="profile")

    def test_atomic_stage_cannot_claim_h_ladder_or_sample_gate(self) -> None:
        atomic = _v21_atomic_profile()
        validate_json(atomic, schema_name="profile")
        for field in ("h_ladder_covered", "scientific_sample_gate_satisfied"):
            malformed = copy.deepcopy(atomic)
            malformed[field] = True
            with self.subTest(field=field), self.assertRaisesRegex(
                SchemaError, "atomic bring-up"
            ):
                validate_json(malformed, schema_name="profile")

    def test_atomic_stage_requires_exact_offline_profile_binding(self) -> None:
        missing = _v21_atomic_profile()
        missing.pop("offline_assay_binding")
        with self.assertRaisesRegex(SchemaError, "serialized together"):
            validate_json(missing, schema_name="profile")

        no_selector_or_binding = _v21_atomic_profile()
        no_selector_or_binding.pop("visible_context_profile")
        no_selector_or_binding.pop("offline_assay_binding")
        with self.assertRaisesRegex(SchemaError, "atomic bring-up requires"):
            validate_json(no_selector_or_binding, schema_name="profile")

        wrong_selector = _v21_atomic_profile()
        wrong_selector["visible_context_profile"] = "fallback"
        with self.assertRaisesRegex(SchemaError, "must be one of"):
            validate_json(wrong_selector, schema_name="profile")

        extra = _v21_atomic_profile()
        extra["offline_assay_binding"]["unfrozen"] = True
        with self.assertRaisesRegex(SchemaError, "unknown fields"):
            validate_json(extra, schema_name="profile")

    def test_offline_binding_hash_permission_and_namespace_rules_fail_closed(self) -> None:
        cases = []
        bad_hash = _v21_atomic_profile()
        bad_hash["offline_assay_binding"]["tasks_sha256"] = "A" * 64
        cases.append(("hash", bad_hash, "lowercase SHA-256"))

        permission = _v21_atomic_profile()
        permission["offline_assay_binding"]["model_calls_permitted"] = True
        cases.append(("permission", permission, "must equal false"))

        same_namespace = _v21_atomic_profile()
        same_namespace["offline_assay_binding"]["cache_namespace"] = (
            same_namespace["offline_assay_binding"]["output_namespace"]
        )
        cases.append(("namespace", same_namespace, "must be distinct"))

        blank_namespace = _v21_atomic_profile()
        blank_namespace["offline_assay_binding"]["cache_namespace"] = "   "
        cases.append(("blank", blank_namespace, "whitespace-trimmed"))

        for label, value, message in cases:
            with self.subTest(label=label), self.assertRaisesRegex(
                SchemaError, message
            ):
                validate_json(value, schema_name="profile")

    def test_canonical_rq1_identity_and_adaptive_track_are_schema_valid(self) -> None:
        value = _canonical_rq1_adaptive_profile()
        validate_json(value, schema_name="profile")
        self.assertNotIn("offline_assay_binding", value)
        self.assertEqual(
            profile_stage_contract(value),
            {
                "execution_stage": "formal",
                "protocol_stage": None,
                "h_ladder_covered": False,
                "scientific_sample_gate_satisfied": False,
                "legacy_compatibility": False,
            },
        )

        for path in sorted(
            Path("experiments/host_boundary_v2/config/profiles").glob(
                "rq1-*-formal.template.json"
            )
        ):
            with self.subTest(profile=path.name):
                validate_json(
                    json.loads(path.read_text(encoding="utf-8")),
                    schema_name="profile",
                )

    def test_canonical_rq1_identity_is_all_or_none_and_exact(self) -> None:
        for field in _CANONICAL_RQ1_IDENTITY:
            malformed = _canonical_rq1_adaptive_profile()
            malformed.pop(field)
            with self.subTest(missing=field), self.assertRaisesRegex(
                SchemaError, "all-or-none"
            ):
                validate_json(malformed, schema_name="profile")

        wrong = _canonical_rq1_adaptive_profile()
        wrong["ladder_version"] = "unfrozen"
        with self.assertRaisesRegex(SchemaError, "must equal '1.0.0'"):
            validate_json(wrong, schema_name="profile")

    def test_canonical_rq1_selector_track_and_run_kind_cannot_diverge(self) -> None:
        wrong_track = _canonical_rq1_adaptive_profile()
        wrong_track["execution_track"] = "fixed_trace_host_replay"
        with self.assertRaisesRegex(SchemaError, "visible_context_profile"):
            validate_json(wrong_track, schema_name="profile")

        fixed_gate = _canonical_rq1_adaptive_profile()
        fixed_gate.update(
            visible_context_profile="scripted_route_replay",
            execution_track="fixed_trace_host_replay",
        )
        with self.assertRaisesRegex(SchemaError, "execution_track"):
            validate_json(fixed_gate, schema_name="profile")

        fixed_gate["run_kind"] = "scripted"
        fixed_gate["execution_stage"] = "atomic_synthetic_bringup"
        validate_json(fixed_gate, schema_name="profile")

        legacy = _legacy_gate_profile()
        legacy["execution_track"] = "adaptive_end_to_end"
        with self.assertRaisesRegex(SchemaError, "reserved for canonical RQ1"):
            validate_json(legacy, schema_name="profile")

    def test_canonical_stage_contract_round_trips_every_executable_stage(self) -> None:
        cases = (
            (
                "atomic_synthetic_bringup",
                None,
                "scripted",
                "scripted_route_replay",
                "fixed_trace_host_replay",
            ),
            (
                "protocol_stage_g",
                "G",
                "scripted",
                "scripted_route_replay",
                "fixed_trace_host_replay",
            ),
            (
                "protocol_stage_s",
                "S",
                "gate",
                "objective_aware_adaptive",
                "adaptive_end_to_end",
            ),
            (
                "variance_pilot",
                None,
                "gate",
                "objective_aware_adaptive",
                "adaptive_end_to_end",
            ),
            (
                "formal",
                None,
                "formal",
                "objective_aware_adaptive",
                "adaptive_end_to_end",
            ),
        )
        for stage, protocol_stage, run_kind, selector, track in cases:
            value = _canonical_rq1_adaptive_profile()
            value.update(
                execution_stage=stage,
                protocol_stage=protocol_stage,
                run_kind=run_kind,
                visible_context_profile=selector,
                execution_track=track,
                h_ladder_covered=False,
                scientific_sample_gate_satisfied=False,
            )
            with self.subTest(stage=stage):
                validate_json(value, schema_name="profile")
                self.assertEqual(
                    profile_stage_contract(value),
                    {
                        "execution_stage": stage,
                        "protocol_stage": protocol_stage,
                        "h_ladder_covered": False,
                        "scientific_sample_gate_satisfied": False,
                        "legacy_compatibility": False,
                    },
                )


if __name__ == "__main__":
    unittest.main()
