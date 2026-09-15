from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from agentmembrane.semantic_rq2.confirmation_analysis import (
    analyze_confirmation_records,
    render_confirmation_report,
    write_confirmation_json,
    write_confirmation_report,
)
from agentmembrane.semantic_rq2.schema import RECEPTOR_ORDER, Receptor


def case_records(
    *,
    case_id: str,
    cluster_id: str,
    seed: int,
    downstream_id: str = "victim-a",
    attack_targets: set[Receptor] | None = None,
    invalid_arms: set[str] | None = None,
) -> list[dict]:
    attack_targets = attack_targets or set()
    invalid_arms = invalid_arms or set()
    common = {
        "case_id": case_id,
        "cluster_id": cluster_id,
        "downstream_id": downstream_id,
        "downstream_model": "model-a",
        "seed": seed,
        "gold_label": "Entailment",
        "assigned_target": "Contradiction",
        "packet_sha256": "sha",
        "packet_identity_ok": True,
        "terminal_status": "completed",
    }
    rows: list[dict] = []
    for receptor in RECEPTOR_ORDER:
        honest_arm = f"honest:{receptor.value}"
        attack_arm = f"attack:{receptor.value}"
        rows.append(
            common
            | {
                "arm_id": honest_arm,
                "mode": "honest",
                "receptor": receptor.value,
                "label": "Entailment",
                "hard_valid": honest_arm not in invalid_arms,
            }
        )
        rows.append(
            common
            | {
                "arm_id": attack_arm,
                "mode": "attack",
                "receptor": receptor.value,
                "label": "Contradiction" if receptor in attack_targets else "Entailment",
                "hard_valid": attack_arm not in invalid_arms,
            }
        )
    return rows


class ConfirmationAnalysisTests(unittest.TestCase):
    def test_two_cases_in_one_document_contribute_one_exact_sign(self) -> None:
        records = []
        for index in range(2):
            records.extend(
                case_records(
                    case_id=f"case-{index}",
                    cluster_id="one-contract",
                    seed=7,
                    attack_targets={Receptor.R2},
                )
            )
        result = analyze_confirmation_records(
            records, bootstrap_seed=101, bootstrap_samples=200
        )
        primary = result["per_downstream"]["victim-a"]["seed_results"]["7"][
            "primary_gamma_r2"
        ]["source_fidelity_valid"]
        self.assertEqual(primary["completed_case_n"], 2)
        self.assertEqual(primary["completed_document_cluster_n"], 1)
        self.assertEqual(primary["document_cluster_positive_n"], 1)
        self.assertEqual(primary["document_cluster_nonzero_n"], 1)
        self.assertEqual(primary["exact_two_sided_document_cluster_sign_p"], 1.0)
        self.assertEqual(primary["case_weighted_point"], 1.0)

    def test_primary_requires_common_r1_r2_source_fidelity_validity(self) -> None:
        invalid = {f"attack:{Receptor.R2.value}"}
        records = case_records(
            case_id="case-invalid",
            cluster_id="doc-invalid",
            seed=8,
            attack_targets={Receptor.R2},
            invalid_arms=invalid,
        )
        result = analyze_confirmation_records(
            records, bootstrap_seed=102, bootstrap_samples=200
        )
        primary = result["per_downstream"]["victim-a"]["seed_results"]["8"][
            "primary_gamma_r2"
        ]
        self.assertEqual(primary["all_attempt_robustness"]["completed_case_n"], 1)
        self.assertEqual(primary["all_attempt_robustness"]["case_weighted_point"], 1.0)
        self.assertEqual(primary["source_fidelity_valid"]["completed_case_n"], 0)
        self.assertIsNone(primary["source_fidelity_valid"]["case_weighted_point"])
        self.assertEqual(
            primary["source_fidelity_valid"]["source_fidelity_common_valid_coverage"],
            0.0,
        )

    def test_downstream_seed_case_blocks_are_kept_separate(self) -> None:
        records: list[dict] = []
        for downstream_id in ("victim-a", "victim-b"):
            for seed in (11, 12):
                records.extend(
                    case_records(
                        case_id="same-case-id",
                        cluster_id="same-document",
                        seed=seed,
                        downstream_id=downstream_id,
                        attack_targets={Receptor.R2, Receptor.R4},
                    )
                )
        result = analyze_confirmation_records(
            records, bootstrap_seed=103, bootstrap_samples=200
        )
        self.assertEqual(set(result["per_downstream"]), {"victim-a", "victim-b"})
        for downstream in result["per_downstream"].values():
            self.assertEqual(set(downstream["seed_results"]), {"11", "12"})
            for seed_result in downstream["seed_results"].values():
                self.assertEqual(seed_result["planned_case_n"], 1)
                self.assertEqual(seed_result["independent_document_cluster_n"], 1)

    def test_secondary_curve_keeps_all_attempt_and_valid_views(self) -> None:
        records = case_records(
            case_id="case-secondary",
            cluster_id="doc-secondary",
            seed=13,
            attack_targets={Receptor.R2, Receptor.R4},
        )
        result = analyze_confirmation_records(
            records, bootstrap_seed=104, bootstrap_samples=200
        )
        row = result["per_downstream"]["victim-a"]["seed_results"]["13"]
        secondary = row["secondary"]
        self.assertEqual(
            secondary["r2_direct_effect"]["source_fidelity_valid"]["case_weighted_point"],
            1.0,
        )
        self.assertEqual(
            secondary["r4_direct_effect"]["all_attempt_robustness"]["case_weighted_point"],
            1.0,
        )
        self.assertEqual(
            secondary["r4_minus_r1"]["source_fidelity_valid"]["case_weighted_point"],
            1.0,
        )
        self.assertEqual(
            list(secondary["complete_receptor_curve"]),
            [receptor.value for receptor in RECEPTOR_ORDER],
        )

    def test_json_and_human_report_helpers(self) -> None:
        result = analyze_confirmation_records(
            case_records(
                case_id="case-output",
                cluster_id="doc-output",
                seed=14,
                attack_targets={Receptor.R2},
            ),
            bootstrap_seed=105,
            bootstrap_samples=100,
        )
        rendered = render_confirmation_report(result)
        self.assertIn("Primary Gamma_R2", rendered)
        self.assertIn("one sign per document cluster", rendered)
        with tempfile.TemporaryDirectory() as directory:
            json_path = Path(directory) / "analysis.json"
            report_path = Path(directory) / "report.md"
            write_confirmation_json(json_path, result)
            write_confirmation_report(report_path, result)
            self.assertEqual(json.loads(json_path.read_text()), result)
            self.assertEqual(report_path.read_text(), rendered)


if __name__ == "__main__":
    unittest.main()
