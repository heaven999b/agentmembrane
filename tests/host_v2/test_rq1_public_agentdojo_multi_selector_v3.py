from __future__ import annotations

from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import subprocess
import unittest

from agentmembrane.host_v2.rq1_public_agentdojo_multi_v3.contracts import (
    CLAIM_ELIGIBLE,
    CONSTRUCT_STATUS,
    SOURCE_PACK_MANIFEST_SHA256,
    SOURCE_PACK_ROOT,
    SOURCE_PACK_TASKS_SHA256,
    SOURCE_TASK_IDS,
    SOURCE_UPSTREAM_ROOT,
    SOURCE_UPSTREAM_TASK_IDS,
    SOURCE_VERSION_OR_COMMIT,
    SOURCE_WORKFLOW_IDS,
    TOOL_PROFILES,
    TOOL_PROFILE_HASH_INPUTS,
    TOOL_PROFILE_SHA256,
    WORKFLOWS,
    contracts_manifest,
    tool_profile,
)
from agentmembrane.host_v2.rq1_public_agentdojo_multi_v3.selector import (
    all_cells,
    execution_order_scheme,
    select_cell,
    selector_manifest,
    workflow_cells,
)
from agentmembrane.host_v2.schema import SchemaError, sha256_json


ROOT = Path(__file__).resolve().parents[2]
PACK_ROOT = ROOT / SOURCE_PACK_ROOT
UPSTREAM_ROOT = ROOT / SOURCE_UPSTREAM_ROOT
LOCKED_PYTHON = (
    ROOT
    / "experiments/host_boundary_v2/runtime_envs/"
    "agentdojo-0.1.35-py3123-lock-395e3d0a5921/bin/python"
)

EXPECTED_TASK_IDS = (
    "agentdojo-v1-banking-u0-i5",
    "agentdojo-v1-banking-u2-i4",
    "agentdojo-v1-banking-u3-i1",
    "agentdojo-v1-slack-u0-i3",
    "agentdojo-v1-slack-u2-i5",
    "agentdojo-v1-slack-u6-i1",
    "agentdojo-v1-travel-u0-i0",
    "agentdojo-v1-travel-u1-i2",
    "agentdojo-v1-travel-u3-i1",
    "agentdojo-v1-workspace-u13-i0",
    "agentdojo-v1-workspace-u15-i2",
    "agentdojo-v1-workspace-u18-i3",
)


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class RQ1PublicAgentDojoMultiSelectorV3Tests(unittest.TestCase):
    def test_exact_deterministic_first_three_per_domain(self) -> None:
        self.assertEqual(SOURCE_TASK_IDS, EXPECTED_TASK_IDS)
        self.assertEqual(len(WORKFLOWS), 12)
        self.assertEqual(
            Counter(workflow.domain for workflow in WORKFLOWS),
            Counter({"banking": 3, "slack": 3, "travel": 3, "workspace": 3}),
        )
        self.assertEqual(len(set(SOURCE_WORKFLOW_IDS)), 12)
        self.assertEqual(len(set(SOURCE_UPSTREAM_TASK_IDS)), 12)
        self.assertTrue(
            all(workflow.source_id == "agentdojo-v0.1.35" for workflow in WORKFLOWS)
        )
        self.assertEqual(
            SOURCE_VERSION_OR_COMMIT,
            "0.1.35@089ed468cf3ed0322acc66b0211f26d9d90dbf60",
        )

    def test_exact_48_cell_engineering_matrix_is_private_and_non_claiming(self) -> None:
        cells = all_cells()
        self.assertEqual(len(cells), 48)
        self.assertEqual(len({cell.cell_id for cell in cells}), 48)
        for workflow in WORKFLOWS:
            four = workflow_cells(workflow.workflow_key)
            self.assertEqual(len(four), 4)
            self.assertEqual(
                {(cell.pair_role, cell.host_arm) for cell in four},
                {
                    ("benign", "vulnerable"),
                    ("benign", "protected"),
                    ("adversarial", "vulnerable"),
                    ("adversarial", "protected"),
                },
            )
            self.assertTrue(
                all(
                    cell.injection_enabled == (cell.pair_role == "adversarial")
                    for cell in four
                )
            )
            self.assertTrue(all(cell.engineering_smoke for cell in four))
            self.assertTrue(all(cell.construct_status == "parity_pending" for cell in four))
            self.assertTrue(all(cell.claim_eligible is False for cell in four))
        self.assertEqual(
            [cell.execution_ordinal for cell in cells], list(range(1, 49))
        )

    def test_execution_order_uses_four_balanced_latin_rotations(self) -> None:
        scheme = execution_order_scheme()
        self.assertEqual(scheme["scheme_id"], "four-coordinate-latin-rotation-v1")
        self.assertEqual(scheme["ordinal_base"], 1)
        self.assertEqual(scheme["workflows_per_rotation"], 3)
        self.assertEqual(
            Counter(row["rotation"] for row in scheme["assignments"]),
            Counter({0: 3, 1: 3, 2: 3, 3: 3}),
        )
        base = scheme["base_coordinate_order"]
        for row in scheme["assignments"]:
            rotation = row["rotation"]
            self.assertEqual(
                row["coordinate_order"], base[rotation:] + base[:rotation]
            )

    def test_model_view_is_identical_across_each_workflow_four_cell(self) -> None:
        private_terms = (
            "pair_role",
            "host_arm",
            "adversarial",
            "vulnerable",
            "protected",
            "injection_enabled",
            "injection_task",
            "injection_vector",
            "fixture_ref",
            "oracle_ref",
            "claim_eligible",
        )
        for workflow in WORKFLOWS:
            with self.subTest(workflow=workflow.workflow_key):
                views = [
                    cell.model_visible_initial()
                    for cell in workflow_cells(workflow.workflow_key)
                ]
                self.assertTrue(all(view == views[0] for view in views[1:]))
                self.assertEqual(
                    views[0]["messages"],
                    [{"role": "user", "content": workflow.surface_task}],
                )
                profile = tool_profile(workflow.domain)
                self.assertEqual(
                    [tool["name"] for tool in views[0]["tools"]],
                    [tool.name for tool in profile.tools],
                )
                rendered = json.dumps(views[0], sort_keys=True).casefold()
                for term in private_terms:
                    self.assertNotIn(term, rendered)

    def test_every_fixture_oracle_and_source_file_hash_is_bound(self) -> None:
        self.assertEqual(
            _sha256_file(PACK_ROOT / "manifest.json"),
            SOURCE_PACK_MANIFEST_SHA256,
        )
        self.assertEqual(
            _sha256_file(PACK_ROOT / "tasks.jsonl"), SOURCE_PACK_TASKS_SHA256
        )
        for workflow in WORKFLOWS:
            with self.subTest(workflow=workflow.workflow_key):
                for relative, expected in (
                    (workflow.benign_fixture_ref, workflow.benign_fixture_sha256),
                    (
                        workflow.adversarial_fixture_ref,
                        workflow.adversarial_fixture_sha256,
                    ),
                    (workflow.oracle_ref, workflow.oracle_sha256),
                ):
                    self.assertEqual(_sha256_file(PACK_ROOT / relative), expected)
                for relative, expected in (
                    (
                        workflow.user_task_source_path,
                        workflow.user_task_source_sha256,
                    ),
                    (
                        workflow.injection_task_source_path,
                        workflow.injection_task_source_sha256,
                    ),
                    (
                        workflow.injection_vector_source_path,
                        workflow.injection_vector_source_sha256,
                    ),
                    (
                        workflow.environment_source_path,
                        workflow.environment_source_sha256,
                    ),
                ):
                    self.assertEqual(_sha256_file(UPSTREAM_ROOT / relative), expected)
                self.assertRegex(workflow.initial_state_sha256, r"^[0-9a-f]{64}$")

    def test_all_native_tool_implementation_hashes_are_bound(self) -> None:
        self.assertEqual({profile.domain for profile in TOOL_PROFILES}, {
            "banking", "slack", "travel", "workspace"
        })
        self.assertEqual(
            {profile.domain: len(profile.tools) for profile in TOOL_PROFILES},
            {"banking": 11, "slack": 11, "travel": 28, "workspace": 24},
        )
        for profile in TOOL_PROFILES:
            for tool in profile.tools:
                with self.subTest(domain=profile.domain, tool=tool.name):
                    self.assertEqual(
                        _sha256_file(UPSTREAM_ROOT / tool.source_path),
                        tool.source_sha256,
                    )

    def test_profile_hash_inputs_are_explicit_and_self_consistent(self) -> None:
        self.assertEqual(set(TOOL_PROFILE_HASH_INPUTS), set(TOOL_PROFILE_SHA256))
        for domain, inputs in TOOL_PROFILE_HASH_INPUTS.items():
            with self.subTest(domain=domain):
                self.assertEqual(inputs["source_version"], SOURCE_VERSION_OR_COMMIT)
                self.assertEqual(inputs["suite_version"], "v1")
                self.assertEqual(inputs["domain"], domain)
                self.assertTrue(inputs["tools"])
                self.assertEqual(sha256_json(inputs), TOOL_PROFILE_SHA256[domain])

    def test_schema_digests_and_tool_order_match_locked_native_suite(self) -> None:
        self.assertTrue(LOCKED_PYTHON.is_file())
        source = r'''import hashlib, inspect, json
from pathlib import Path
from agentdojo.task_suite.load_suites import get_suite

root = Path.cwd() / "data/host_boundary_v2/upstream/agentdojo"
def digest(value):
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()

result = {}
for domain in ("banking", "slack", "travel", "workspace"):
    suite = get_suite("v1", domain)
    schemas = [
        {"type": "function", "function": {
            "name": tool.name,
            "description": tool.description,
            "parameters": tool.parameters.model_json_schema(),
        }}
        for tool in suite.tools
    ]
    result[domain] = {
        "names": [tool.name for tool in suite.tools],
        "tool_schemas_sha256": digest(schemas),
    }
print(json.dumps(result, sort_keys=True))
'''
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(UPSTREAM_ROOT / "src")
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        completed = subprocess.run(
            [str(LOCKED_PYTHON), "-B", "-c", source],
            cwd=ROOT,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        observed = json.loads(completed.stdout)
        for profile in TOOL_PROFILES:
            with self.subTest(domain=profile.domain):
                self.assertEqual(
                    observed[profile.domain]["names"],
                    [tool.name for tool in profile.tools],
                )
                self.assertEqual(
                    observed[profile.domain]["tool_schemas_sha256"],
                    profile.tool_schemas_sha256,
                )

    def test_manifest_stays_parity_pending_and_non_claiming(self) -> None:
        contract = contracts_manifest()
        selection = selector_manifest()
        self.assertEqual(contract["construct_status"], CONSTRUCT_STATUS)
        self.assertEqual(selection["construct_status"], CONSTRUCT_STATUS)
        self.assertEqual(selection["schedule_kind"], "engineering_48_cell_smoke")
        self.assertEqual(
            selection["execution_order_scheme"], execution_order_scheme()
        )
        self.assertEqual(
            selection["model_tool_view_kind"],
            "selector_only_opaque_native_refs",
        )
        self.assertEqual(selection["workflow_count"], 12)
        self.assertEqual(selection["cell_count"], 48)
        self.assertIs(contract["claim_eligible"], CLAIM_ELIGIBLE)
        self.assertIs(selection["claim_eligible"], CLAIM_ELIGIBLE)

    def test_selector_rejects_unknown_workflow_or_coordinate(self) -> None:
        with self.assertRaises(SchemaError):
            select_cell("unknown", "benign", "protected")
        with self.assertRaises(SchemaError):
            select_cell("banking-u0-i5", "other", "protected")  # type: ignore[arg-type]
        with self.assertRaises(SchemaError):
            select_cell("banking-u0-i5", "benign", "other")  # type: ignore[arg-type]
        by_source = select_cell(
            "agentdojo-v1-banking-u0-i5", "benign", "protected"
        )
        by_workflow = select_cell(
            "agentdojo:v1:banking:user_task_0", "benign", "protected"
        )
        self.assertEqual(by_source, by_workflow)


if __name__ == "__main__":
    unittest.main()
