"""Build the create-only formal runtime qualification after offline tests.

The input test report is zero-network evidence for the injected fake transport
suite.  The lifecycle receipt is the separate zero-model process rehearsal.
Neither input is a research sample.  This builder validates both against the
current code and route binding before writing the activation artifact.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

PROJECT = Path(__file__).resolve().parents[4]
if str(PROJECT) not in sys.path:
    sys.path.insert(0, str(PROJECT))

from agentmembrane.host_v2.rq1_collab_v1.audit import (
    _write_new, canonical, strict_loads,
)
from agentmembrane.host_v2.rq1_collab_v3.contract import digest
from agentmembrane.host_v2.rq1_three_tier_formal_v1 import runner
from agentmembrane.host_v2.rq1_three_tier_formal_v1.contract import (
    FORMAL_PROTOCOL,
)
from agentmembrane.host_v2.rq1_three_tier_formal_v1.gate import (
    RUNTIME_QUALIFICATION_SCHEMA,
    code_bundle_sha256,
    file_binding,
    validate_runtime_qualification,
)
from agentmembrane.host_v2.rq1_three_tier_formal_v1.proxy_lifecycle import (
    _route_runtime_binding,
)


HERE = Path(__file__).resolve().parent


def build(*, route_binding_path: Path, fake_transport_report_path: Path,
          lifecycle_receipt_path: Path, output: Path) -> dict:
    route_binding = strict_loads(route_binding_path.read_bytes())
    bound_route = _route_runtime_binding({
        "route_runtime_binding_sha256": route_binding.get(
            "route_runtime_binding_sha256"),
        "source_bindings": {
            "route_runtime_binding": file_binding(route_binding_path),
        },
    })
    if bound_route != route_binding:
        raise ValueError("formal_route_runtime_binding_changed")
    report = strict_loads(fake_transport_report_path.read_bytes())
    if (type(report) is not dict
            or report.get("schema_version")
               != "rq1-agentdojo-three-tier-formal-runtime-test-report/1"
            or report.get("code_bundle_sha256") != code_bundle_sha256()
            or report.get("real_model_calls") != 0
            or report.get("all_required_paths_passed") is not True
            or report.get("H_E_action_schema_contains_S") is not False
            or report.get("formal_evidence_envelope_passed") is not True
            or report.get("one_shot_runtime_objects_passed") is not True
            or report.get("proxy_process_lifecycle_tested") is not False):
        raise ValueError("formal_fake_transport_report_invalid")
    body = {
        "schema_version": RUNTIME_QUALIFICATION_SCHEMA,
        "formal_protocol_version": FORMAL_PROTOCOL,
        "code_bundle_sha256": code_bundle_sha256(),
        "route_runtime_binding_sha256": route_binding[
            "route_runtime_binding_sha256"],
        "fake_transport_only": True,
        "real_model_calls": 0,
        "formal_runner": file_binding(Path(runner.__file__)),
        "fake_transport_report": file_binding(fake_transport_report_path),
        "production_proxy_lifecycle_receipt": file_binding(
            lifecycle_receipt_path),
        "actor_set": ["H", "E"],
        "action_schemas": runner.FORMAL_ACTION_SCHEMAS,
        "action_schemas_sha256": digest(runner.FORMAL_ACTION_SCHEMAS),
        "formal_evidence_schema": runner.FORMAL_EVIDENCE_SCHEMA,
        "v6_evidence_admitted_directly": False,
        "H_E_action_schema_tested": True,
        "formal_evidence_envelope_tested": True,
        "one_shot_runtime_objects_tested": True,
        "production_proxy_lifecycle_tested": True,
        "all_required_paths_passed": True,
        "legacy_evidence_rejection_tested": True,
        "manifest_tamper_rejection_tested": True,
        "formal_activation": True,
    }
    value = {**body, "runtime_qualification_sha256": digest(body)}
    validate_runtime_qualification(
        value,
        code_sha256=code_bundle_sha256(),
        route_runtime_binding=route_binding,
    )
    _write_new(output.resolve(), canonical(value) + b"\n")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--route-binding", type=Path,
                        default=HERE / "route-runtime-binding.json")
    parser.add_argument("--fake-transport-report", type=Path, required=True)
    parser.add_argument("--lifecycle-receipt", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    value = build(
        route_binding_path=args.route_binding,
        fake_transport_report_path=args.fake_transport_report,
        lifecycle_receipt_path=args.lifecycle_receipt,
        output=args.output,
    )
    print(json.dumps({
        "runtime_qualification": str(args.output.resolve()),
        "runtime_qualification_sha256": value[
            "runtime_qualification_sha256"],
        "formal_runtime_qualified": True,
        "real_model_calls": 0,
        "research_sample_count": 0,
    }, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
