from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from agentmembrane.host_v2.conditions import (
    ADMISSION_LEVELS,
    CONTAINMENT_LEVELS,
    HOST_SURFACE_LEVELS,
    KNOWN_MECHANISMS,
    LIFECYCLE_PROFILES,
    PROMOTION_PROFILES,
    RQ4_MODULES,
    RQ4_PRIMITIVES,
    ORIGINAL_RQ1_AUTHORITY_LEVELS,
    ORIGINAL_RQ1_HAZARD_OPERATIONS,
    ORIGINAL_RQ1_M1_MECHANISMS,
    STATE_SURFACE_LEVELS,
    ConditionError,
    ConditionSpec,
    assert_serializable_condition,
    build_admission_ladder,
    build_default_registry,
    build_host_surface_ladder,
    build_lifecycle_profiles,
    build_original_rq1_authority_matrix,
    build_primitive_leave_one_out,
    build_promotion_profiles,
    build_rq4_module_lattice,
    build_state_surface_ladder,
    load_conditions,
    make_condition,
    public_affordance,
    resolve_conditions,
    validate_condition,
    validate_condition_lattice,
    validate_fixed_a4_lattice,
)


class AxisConstructionTests(unittest.TestCase):
    def test_all_requested_axes_are_defined(self) -> None:
        self.assertEqual(set(ADMISSION_LEVELS), {f"A{i}" for i in range(6)})
        self.assertEqual(set(HOST_SURFACE_LEVELS), {f"H{i}" for i in range(6)})
        self.assertEqual(set(STATE_SURFACE_LEVELS), {f"S{i}" for i in range(6)})
        self.assertEqual(set(PROMOTION_PROFILES), {f"P{i}" for i in range(4)})
        self.assertEqual(set(LIFECYCLE_PROFILES), {f"L{i}" for i in range(4)})

    def test_containment_ladder_is_cumulative(self) -> None:
        self.assertEqual(set(CONTAINMENT_LEVELS), {f"C{i}" for i in range(4)})
        self.assertLess(CONTAINMENT_LEVELS["C0"], CONTAINMENT_LEVELS["C1"])
        self.assertLess(CONTAINMENT_LEVELS["C1"], CONTAINMENT_LEVELS["C2"])
        self.assertLess(CONTAINMENT_LEVELS["C2"], CONTAINMENT_LEVELS["C3"])

    def test_admission_ladder_and_assay_control(self) -> None:
        rows = build_admission_ladder()
        self.assertEqual(len(rows), 7)
        self.assertEqual([row.condition_id for row in rows[:6]], [f"A{i}-C1" for i in range(6)])
        self.assertEqual(rows[-1].condition_id, "A5-C0")
        self.assertEqual(rows[0].host_surface_level, "H0")
        self.assertEqual(rows[5].host_surface_level, "H5")
        self.assertEqual(rows[5].state_surface_level, "S4")

    def test_original_rq1_matrix_has_exact_five_level_mapping_and_matched_arms(self) -> None:
        rows = build_original_rq1_authority_matrix()
        self.assertEqual(len(rows), 10)
        self.assertEqual(
            ORIGINAL_RQ1_AUTHORITY_LEVELS,
            (
                ("A0", "A0", "H0", "S0"),
                ("A1", "A1", "H1", "S0"),
                ("A2", "A2", "H2", "S2"),
                ("A3", "A3", "H3", "S0"),
                ("A4", "A5", "H5", "S5"),
            ),
        )
        self.assertNotIn("A4", {row.admission_level for row in rows})
        for original, _, _, _ in ORIGINAL_RQ1_AUTHORITY_LEVELS:
            pair = [
                row
                for row in rows
                if row.parameters["original_authority_level"] == original
            ]
            self.assertEqual([row.parameters["protection_arm"] for row in pair], ["M0", "M1"])
            self.assertEqual(public_affordance(pair[0]), public_affordance(pair[1]))
            self.assertEqual(pair[0].admission_level, pair[1].admission_level)
            self.assertEqual(pair[0].host_surface_level, pair[1].host_surface_level)
            self.assertEqual(pair[0].state_surface_level, pair[1].state_surface_level)
        self.assertGreater(
            len(ORIGINAL_RQ1_M1_MECHANISMS),
            len(CONTAINMENT_LEVELS["C1"]),
        )

    def test_original_rq1_a2_pair_is_proposal_only_in_public_surface(self) -> None:
        rows = build_original_rq1_authority_matrix()
        for row in rows:
            if row.parameters["original_authority_level"] != "A2":
                continue
            names = {entry["name"] for entry in public_affordance(row)["operations"]}
            self.assertEqual(
                names,
                {"read_resource", "stage_action", "submit_proposal", "memory_propose"},
            )
            self.assertNotIn("write_low_risk", names)
            self.assertNotIn("execute_proposal", names)

    def test_original_rq1_exact_hazard_operations_exist_only_at_original_a4(self) -> None:
        rows = build_original_rq1_authority_matrix()
        for row in rows:
            names = {entry["name"] for entry in public_affordance(row)["operations"]}
            original = row.parameters["original_authority_level"]
            if original == "A4":
                self.assertLessEqual(set(ORIGINAL_RQ1_HAZARD_OPERATIONS), names)
            else:
                self.assertTrue(set(ORIGINAL_RQ1_HAZARD_OPERATIONS).isdisjoint(names))

    def test_canonical_admission_interfaces_are_reachable_and_a2_is_proposal_only(self) -> None:
        rows = build_admission_ladder()[:6]
        operation_names = [
            {entry["name"] for entry in public_affordance(row)["operations"]}
            for row in rows
        ]
        self.assertEqual(operation_names[0], set())
        self.assertEqual(operation_names[1], {"read_resource"})
        self.assertEqual(
            operation_names[2],
            {"read_resource", "stage_action", "submit_proposal", "memory_propose"},
        )
        self.assertNotIn("write_low_risk", operation_names[2])
        self.assertNotIn("execute_proposal", operation_names[2])
        self.assertIn("write_low_risk", operation_names[3])
        self.assertIn("delegate_capability", operation_names[4])
        self.assertIn("send_message", operation_names[5])
        self.assertEqual(rows[2].state_surface_level, "S2")
        for row in rows:
            admission = public_affordance(row)["admission_request"]
            self.assertEqual(
                set(admission["request"]["required"]),
                {
                    "principal_id", "lease_id", "declared_purpose",
                    "requested_receptor", "requested_capability_set",
                },
            )
            self.assertNotIn("requested_interface", admission["request"]["required"])
            self.assertNotIn("requested_operations", admission["request"]["required"])

    def test_h_ladder_is_fixed_a4_and_nested(self) -> None:
        rows = build_host_surface_ladder()
        self.assertEqual(len(rows), 6)
        self.assertEqual({row.admission_level for row in rows}, {"A4"})
        self.assertEqual({row.state_surface_level for row in rows}, {"S0"})
        self.assertEqual([row.host_surface_level for row in rows], [f"H{i}" for i in range(6)])
        sizes = [len(public_affordance(row)["operations"]) for row in rows]
        self.assertEqual(sizes, sorted(sizes))
        self.assertGreater(sizes[-1], sizes[0])

    def test_s_ladder_uses_real_state_levels(self) -> None:
        rows = build_state_surface_ladder()
        self.assertEqual(len(rows), 6)
        self.assertEqual({row.admission_level for row in rows}, {"A4"})
        self.assertEqual({row.host_surface_level for row in rows}, {"H5"})
        self.assertEqual([row.state_surface_level for row in rows], [f"S{i}" for i in range(6)])
        self.assertEqual(public_affordance(rows[0])["state_capabilities"], [])
        self.assertIn("cross_session_record", public_affordance(rows[-1])["state_capabilities"])

    def test_promotion_profiles_explicitly_account_for_toggles(self) -> None:
        rows = build_promotion_profiles()
        self.assertEqual([row.parameters["promotion_profile"] for row in rows], [f"P{i}" for i in range(4)])
        self.assertTrue(rows[0].has("direct_commit"))
        self.assertTrue(rows[1].has("proposal_gate"))
        self.assertTrue(rows[2].has("artifact_local_verification"))
        self.assertTrue(rows[3].has("re_grounding"))
        for row in rows:
            validate_condition(row)

    def test_lifecycle_profiles_are_ordered_treatments(self) -> None:
        rows = build_lifecycle_profiles()
        self.assertEqual([row.parameters["lifecycle_profile"] for row in rows], [f"L{i}" for i in range(4)])
        self.assertTrue(rows[0].has("revocation"))
        self.assertFalse(rows[0].has("container_cleanup"))
        self.assertTrue(rows[1].has("container_cleanup"))
        self.assertTrue(rows[2].has("lineage_purge"))
        self.assertTrue(rows[3].has("rollback"))
        self.assertTrue(all(row.parameters["trusted_identical_seed"] for row in rows))

    def test_default_registry_contains_every_core_axis(self) -> None:
        registry = build_default_registry()
        self.assertEqual(len(registry), 53)
        self.assertTrue(
            {f"ORIG-RQ1-A{i}-{arm}" for i in range(5) for arm in ("M0", "M1")}
            <= set(registry)
        )
        for condition in registry.values():
            validate_condition(condition)


class FailClosedValidationTests(unittest.TestCase):
    def _base(self, **updates: object) -> dict[str, object]:
        values: dict[str, object] = {
            "condition_id": "opaque-control",
            "admission_level": "A4",
            "host_surface_level": "H5",
            "state_surface_level": "S5",
            "enabled_mechanisms": {"basic_acl"},
            "disabled_mechanisms": set(),
            "parameters": {},
        }
        values.update(updates)
        return values

    def test_unknown_mechanism_is_rejected(self) -> None:
        with self.assertRaisesRegex(ConditionError, "unknown mechanisms"):
            make_condition(**self._base(enabled_mechanisms={"basic_acl", "typo_linegae"}))

    def test_has_unknown_mechanism_is_rejected(self) -> None:
        condition = make_condition(**self._base())
        with self.assertRaisesRegex(ConditionError, "unknown mechanism"):
            condition.has("not_registered")

    def test_enabled_disabled_contradiction_is_rejected(self) -> None:
        with self.assertRaisesRegex(ConditionError, "both enabled and disabled"):
            make_condition(
                **self._base(
                    enabled_mechanisms={"basic_acl", "lineage"},
                    disabled_mechanisms={"lineage"},
                )
            )

    def test_restrictive_admission_cannot_expose_stronger_surface(self) -> None:
        with self.assertRaisesRegex(ConditionError, "A0 cannot expose H1"):
            make_condition(
                **self._base(
                    admission_level="A0",
                    host_surface_level="H1",
                    state_surface_level="S0",
                )
            )
        with self.assertRaisesRegex(ConditionError, "A1 cannot expose S1"):
            make_condition(
                **self._base(
                    admission_level="A1",
                    host_surface_level="H1",
                    state_surface_level="S1",
                )
            )

    def test_unknown_axis_and_profile_are_rejected(self) -> None:
        with self.assertRaisesRegex(ConditionError, "unknown admission"):
            make_condition(**self._base(admission_level="A6"))
        with self.assertRaisesRegex(ConditionError, "unknown promotion"):
            make_condition(**self._base(parameters={"promotion_profile": "P9"}))

    def test_promotion_and_lifecycle_require_real_state(self) -> None:
        with self.assertRaisesRegex(ConditionError, "P0 requires state surface S3"):
            make_condition(
                **self._base(
                    state_surface_level="S2",
                    enabled_mechanisms={"basic_acl", "direct_commit"},
                    disabled_mechanisms={
                        "proposal_gate",
                        "promotion_enabled",
                        "artifact_local_verification",
                        "approval",
                        "re_grounding",
                    },
                    parameters={"promotion_profile": "P0"},
                )
            )
        with self.assertRaisesRegex(ConditionError, "L0 requires active seeded state S3"):
            make_condition(
                **self._base(
                    state_surface_level="S2",
                    enabled_mechanisms={"basic_acl", "revocation"},
                    disabled_mechanisms={"container_cleanup", "lineage_purge", "rollback"},
                    parameters={"lifecycle_profile": "L0"},
                )
            )

    def test_condition_id_is_not_a_behavior_parser(self) -> None:
        condition = make_condition(**self._base(condition_id="A0-C0"))
        view = public_affordance(condition)
        self.assertEqual(view["interface"], ADMISSION_LEVELS["A4"])
        self.assertTrue(view["operations"])
        assert_serializable_condition(condition)


class RQ4LatticeTests(unittest.TestCase):
    def test_modules_partition_exactly_twelve_primitives(self) -> None:
        self.assertEqual(set(RQ4_MODULES), {f"M{i}" for i in range(1, 5)})
        self.assertEqual(len(RQ4_PRIMITIVES), 12)
        flattened = [primitive for values in RQ4_MODULES.values() for primitive in values]
        self.assertEqual(len(flattened), len(set(flattened)))
        self.assertLessEqual(RQ4_PRIMITIVES, KNOWN_MECHANISMS)

    def test_full_sixteen_cell_lattice(self) -> None:
        rows = build_rq4_module_lattice()
        self.assertEqual(len(rows), 16)
        self.assertEqual(rows[0].condition_id, "A4-RQ4-0000")
        self.assertEqual(rows[-1].condition_id, "A4-RQ4-1111")
        self.assertEqual(validate_fixed_a4_lattice(rows), [])
        self.assertEqual(validate_condition_lattice(rows), [])
        for condition in rows:
            self.assertEqual(condition.admission_level, "A4")
            self.assertEqual(condition.host_surface_level, "H5")
            self.assertEqual(condition.state_surface_level, "S5")
            flags = condition.parameters["primitive_flags"]
            for primitive in RQ4_PRIMITIVES:
                self.assertEqual(flags[primitive], primitive in condition.enabled_mechanisms)
                self.assertNotEqual(
                    primitive in condition.enabled_mechanisms,
                    primitive in condition.disabled_mechanisms,
                )

    def test_fixed_a4_validator_rejects_missing_and_changed_cells(self) -> None:
        rows = build_rq4_module_lattice()
        errors = validate_fixed_a4_lattice(rows[:-1])
        self.assertTrue(any("requires 16" in error for error in errors))
        self.assertTrue(any("missing" in error for error in errors))

        changed = replace(rows[-1], host_surface_level="H4")
        errors = validate_fixed_a4_lattice((*rows[:-1], changed))
        self.assertTrue(any("hold H5 and S5 fixed" in error for error in errors))

    def test_module_primitive_disagreement_is_rejected(self) -> None:
        full = build_rq4_module_lattice()[-1]
        flags = dict(full.parameters["primitive_flags"])
        flags["lineage"] = False
        parameters = dict(full.parameters)
        parameters["primitive_flags"] = flags
        malformed = replace(full, parameters=parameters)
        with self.assertRaisesRegex(ConditionError, "contradicts|disagree"):
            validate_condition(malformed)

    def test_leave_one_out_from_full_cell_covers_all_primitives(self) -> None:
        full = build_rq4_module_lattice()[-1]
        rows = build_primitive_leave_one_out(full)
        self.assertEqual(len(rows), 12)
        self.assertEqual(
            {row.parameters["primitive_ablation"] for row in rows},
            set(RQ4_PRIMITIVES),
        )
        for row in rows:
            removed = row.parameters["primitive_ablation"]
            self.assertNotIn(removed, row.enabled_mechanisms)
            self.assertIn(removed, row.disabled_mechanisms)
            validate_condition(row)

    def test_leave_one_out_only_accepts_applicable_known_primitives(self) -> None:
        empty = build_rq4_module_lattice()[0]
        self.assertEqual(build_primitive_leave_one_out(empty), ())
        with self.assertRaisesRegex(ConditionError, "cannot ablate disabled"):
            build_primitive_leave_one_out(empty, ["lineage"])
        with self.assertRaisesRegex(ConditionError, "unknown RQ4 primitives"):
            build_primitive_leave_one_out(build_rq4_module_lattice()[-1], ["mystery"])

    def test_all_lattice_cells_have_identical_label_blind_view(self) -> None:
        serialized = {
            json.dumps(public_affordance(condition), sort_keys=True)
            for condition in build_rq4_module_lattice()
        }
        self.assertEqual(len(serialized), 1)
        view_text = next(iter(serialized)).lower()
        for forbidden in (
            "a4",
            "rq4",
            "m1",
            "m2",
            "m3",
            "m4",
            "secure",
            "vulnerable",
            "capability_broker",
            "lineage",
            "disabled_mechanisms",
            "condition_id",
        ):
            self.assertNotIn(forbidden, view_text)


class RegistryIOTests(unittest.TestCase):
    def test_strict_load_and_resolve_round_trip(self) -> None:
        rows = build_rq4_module_lattice()[:2]
        payload = {"conditions": [row.to_dict() for row in rows]}
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "conditions.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            registry = load_conditions(path)
        self.assertEqual(set(registry), {row.condition_id for row in rows})
        resolved = resolve_conditions([rows[1].condition_id, rows[0].condition_id], registry)
        self.assertEqual(resolved, (rows[1], rows[0]))

    def test_loader_rejects_unknown_top_level_and_condition_fields(self) -> None:
        row = build_rq4_module_lattice()[0].to_dict()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "conditions.json"
            path.write_text(json.dumps({"conditions": [row], "fallback": True}), encoding="utf-8")
            with self.assertRaisesRegex(ConditionError, "exactly"):
                load_conditions(path)
            row["unknown_security_toggle"] = False
            path.write_text(json.dumps({"conditions": [row]}), encoding="utf-8")
            with self.assertRaisesRegex(ConditionError, "unknown condition fields"):
                load_conditions(path)

    def test_loader_rejects_duplicate_ids_and_resolver_rejects_unknown(self) -> None:
        row = build_rq4_module_lattice()[0].to_dict()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "conditions.json"
            path.write_text(json.dumps({"conditions": [row, row]}), encoding="utf-8")
            with self.assertRaisesRegex(ConditionError, "duplicate condition_id"):
                load_conditions(path)
        registry = build_default_registry()
        with self.assertRaisesRegex(ConditionError, "unknown condition_id"):
            resolve_conditions(["missing"], registry)
        condition_id = next(iter(registry))
        with self.assertRaisesRegex(ConditionError, "duplicate requested"):
            resolve_conditions([condition_id, condition_id], registry)

    def test_general_lattice_validator_reports_duplicates(self) -> None:
        condition = build_admission_ladder()[0]
        errors = validate_condition_lattice([condition, condition])
        self.assertIn(f"duplicate condition_id: {condition.condition_id}", errors)


if __name__ == "__main__":
    unittest.main()
