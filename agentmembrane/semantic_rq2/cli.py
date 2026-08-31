from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Iterable

from .analysis import analyze_multiseed_records, analyze_records
from .heldout import build_heldout_subset_manifest
from .manifest import build_contractnli_manifest, load_manifest, validate_manifest
from .p0_calibration import run_neutral_p0_calibration
from .profile import offline_preflight
from .runner import run_experiment
from .sensitivity import run_relaxed_reaudit
from .sensitivity_intermediate import run_intermediate_reaudit
from .sensitivity_omission import run_omission_reaudit


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{line_number}: expected a JSON object")
        rows.append(value)
    return rows


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="AgentMembrane canonical RQ2 semantic receptor baseline"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    build = commands.add_parser("build-manifest")
    build.add_argument("--split", type=Path, required=True)
    build.add_argument("--license", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    build.add_argument("--documents", type=int, default=100)
    build.add_argument("--seed", type=int, default=20260831)

    heldout = commands.add_parser("build-heldout-manifest")
    heldout.add_argument("--parent-manifest", type=Path, required=True)
    heldout.add_argument("--exclude-manifest", type=Path, required=True)
    heldout.add_argument("--output", type=Path, required=True)
    heldout.add_argument("--documents", type=int, default=25)
    heldout.add_argument("--seed", type=int, default=20260901)

    validate = commands.add_parser("validate-manifest")
    validate.add_argument("--manifest", type=Path, required=True)
    validate.add_argument("--split", type=Path)
    validate.add_argument("--allow-noncanonical-size", action="store_true")

    preflight = commands.add_parser("preflight")
    preflight.add_argument("--manifest", type=Path, required=True)
    preflight.add_argument("--profile", type=Path, required=True)
    preflight.add_argument("--formal", action="store_true")
    preflight.add_argument("--output", type=Path)

    analyze = commands.add_parser("analyze")
    analyze.add_argument("--records", type=Path, required=True)
    analyze.add_argument("--output", type=Path, required=True)
    analyze.add_argument("--seed", type=int, required=True)
    analyze.add_argument("--bootstrap-samples", type=int, default=10_000)

    aggregate = commands.add_parser("aggregate-seeds")
    aggregate.add_argument("--records", type=Path, nargs="+", required=True)
    aggregate.add_argument("--output", type=Path, required=True)
    aggregate.add_argument("--bootstrap-seed", type=int, default=20260831)
    aggregate.add_argument("--bootstrap-samples", type=int, default=10_000)

    run = commands.add_parser("run")
    run.add_argument("--manifest", type=Path, required=True)
    run.add_argument("--profile", type=Path, required=True)
    run.add_argument("--run-dir", type=Path, required=True)
    run.add_argument("--seed", type=int, required=True)
    run.add_argument("--formal", action="store_true")
    run.add_argument("--max-cases", type=int)

    reaudit = commands.add_parser("reaudit-sensitivity")
    reaudit.add_argument("--manifest", type=Path, required=True)
    reaudit.add_argument("--profile", type=Path, required=True)
    reaudit.add_argument("--source-run-dir", type=Path, required=True)
    reaudit.add_argument("--output-dir", type=Path, required=True)
    reaudit.add_argument("--seed", type=int, required=True)
    reaudit.add_argument("--max-cases", type=int)
    reaudit.add_argument("--preregistered-engineering", action="store_true")

    intermediate = commands.add_parser("reaudit-intermediate")
    intermediate.add_argument("--manifest", type=Path, required=True)
    intermediate.add_argument("--profile", type=Path, required=True)
    intermediate.add_argument("--source-run-dir", type=Path, required=True)
    intermediate.add_argument("--output-dir", type=Path, required=True)
    intermediate.add_argument("--seed", type=int, required=True)
    intermediate.add_argument("--max-cases", type=int)

    omission = commands.add_parser("reaudit-omission")
    omission.add_argument("--manifest", type=Path, required=True)
    omission.add_argument("--profile", type=Path, required=True)
    omission.add_argument("--source-run-dir", type=Path, required=True)
    omission.add_argument("--previous-stage-dir", type=Path, required=True)
    omission.add_argument("--output-dir", type=Path, required=True)
    omission.add_argument("--seed", type=int, required=True)
    omission.add_argument("--max-cases", type=int)

    p0 = commands.add_parser("calibrate-neutral-p0")
    p0.add_argument("--manifest", type=Path, required=True)
    p0.add_argument("--profile", type=Path, required=True)
    p0.add_argument("--source-run-dir", type=Path, required=True)
    p0.add_argument("--validity-stage-dir", type=Path, required=True)
    p0.add_argument("--output-dir", type=Path, required=True)
    p0.add_argument("--seed", type=int, required=True)
    p0.add_argument("--max-cases", type=int, required=True)
    p0.add_argument("--validity-records", default="records.omission.jsonl")
    p0.add_argument("--preregistered-engineering", action="store_true")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    if args.command == "build-manifest":
        manifest = build_contractnli_manifest(
            split_path=args.split,
            license_path=args.license,
            output_path=args.output,
            document_count=args.documents,
            seed=args.seed,
        )
        print(
            json.dumps(
                {
                    "output": str(args.output.resolve()),
                    "case_n": len(manifest["cases"]),
                    "cluster_n": manifest["sampling"]["document_clusters"],
                    "content_sha256": manifest["content_sha256"],
                },
                indent=2,
            )
        )
        return 0
    if args.command == "build-heldout-manifest":
        manifest = build_heldout_subset_manifest(
            parent_manifest_path=args.parent_manifest,
            exclusion_manifest_path=args.exclude_manifest,
            output_path=args.output,
            document_count=args.documents,
            seed=args.seed,
        )
        print(
            json.dumps(
                {
                    "output": str(args.output.resolve()),
                    "case_n": len(manifest["cases"]),
                    "cluster_n": manifest["sampling"]["document_clusters"],
                    "cluster_overlap_with_exclusion": manifest["heldout_confirmation"][
                        "cluster_overlap_with_exclusion"
                    ],
                    "content_sha256": manifest["content_sha256"],
                },
                indent=2,
            )
        )
        return 0
    if args.command == "validate-manifest":
        result = validate_manifest(
            load_manifest(args.manifest),
            expected_split_path=args.split,
            exact_baseline_shape=not args.allow_noncanonical_size,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["valid"] else 2
    if args.command == "preflight":
        result = offline_preflight(
            manifest_path=args.manifest,
            profile_path=args.profile,
            formal=args.formal,
        )
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["status"] == "PASS" else 2
    if args.command == "analyze":
        result = analyze_records(
            _read_jsonl(args.records),
            seed=args.seed,
            bootstrap_samples=args.bootstrap_samples,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
        print(json.dumps({"output": str(args.output.resolve()), "label": result["cross_model_result_label"]}, indent=2))
        return 0
    if args.command == "aggregate-seeds":
        records = [row for path in args.records for row in _read_jsonl(path)]
        result = analyze_multiseed_records(
            records,
            bootstrap_seed=args.bootstrap_seed,
            bootstrap_samples=args.bootstrap_samples,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
        print(
            json.dumps(
                {
                    "output": str(args.output.resolve()),
                    "seeds": result["seeds"],
                    "pooled_label": result["repeated_measure_pooled"]["cross_model_result_label"],
                },
                indent=2,
            )
        )
        return 0
    if args.command == "run":
        result = run_experiment(
            manifest_path=args.manifest,
            profile_path=args.profile,
            run_dir=args.run_dir,
            seed=args.seed,
            formal=args.formal,
            max_cases=args.max_cases,
        )
        print(
            json.dumps(
                {
                    "run_dir": str(args.run_dir.resolve()),
                    "case_n": result["case_n"],
                    "label": result["analysis"]["cross_model_result_label"],
                    "claim_bearing": result["claim_bearing"],
                },
                indent=2,
            )
        )
        return 0
    if args.command == "reaudit-sensitivity":
        result = run_relaxed_reaudit(
            manifest_path=args.manifest,
            profile_path=args.profile,
            source_run_dir=args.source_run_dir,
            output_dir=args.output_dir,
            seed=args.seed,
            max_cases=args.max_cases,
            post_pilot_sensitivity_only=not args.preregistered_engineering,
        )
        print(
            json.dumps(
                {
                    "output_dir": str(args.output_dir.resolve()),
                    "case_n": result["case_n"],
                    "formal_label": result["formal_analysis_label_unchanged_rules"],
                    "diagnostic_label": result["diagnostic_signal_label"],
                    "claim_bearing": result["claim_bearing"],
                },
                indent=2,
            )
        )
        return 0
    if args.command == "reaudit-intermediate":
        result = run_intermediate_reaudit(
            manifest_path=args.manifest,
            profile_path=args.profile,
            source_run_dir=args.source_run_dir,
            output_dir=args.output_dir,
            seed=args.seed,
            max_cases=args.max_cases,
        )
        print(
            json.dumps(
                {
                    "output_dir": str(args.output_dir.resolve()),
                    "case_n": result["case_n"],
                    "formal_label": result["formal_analysis_label_unchanged_rules"],
                    "diagnostic_label": result["diagnostic_signal_label"],
                    "claim_bearing": result["claim_bearing"],
                },
                indent=2,
            )
        )
        return 0
    if args.command == "reaudit-omission":
        result = run_omission_reaudit(
            manifest_path=args.manifest,
            profile_path=args.profile,
            source_run_dir=args.source_run_dir,
            previous_stage_dir=args.previous_stage_dir,
            output_dir=args.output_dir,
            seed=args.seed,
            max_cases=args.max_cases,
        )
        print(
            json.dumps(
                {
                    "output_dir": str(args.output_dir.resolve()),
                    "case_n": result["case_n"],
                    "formal_label": result["formal_analysis_label_unchanged_rules"],
                    "diagnostic_label": result["diagnostic_signal_label"],
                    "claim_bearing": result["claim_bearing"],
                },
                indent=2,
            )
        )
        return 0
    if args.command == "calibrate-neutral-p0":
        result = run_neutral_p0_calibration(
            manifest_path=args.manifest,
            profile_path=args.profile,
            source_run_dir=args.source_run_dir,
            validity_stage_dir=args.validity_stage_dir,
            output_dir=args.output_dir,
            seed=args.seed,
            max_cases=args.max_cases,
            validity_records_filename=args.validity_records,
            post_pilot_sensitivity_only=not args.preregistered_engineering,
        )
        print(
            json.dumps(
                {
                    "output_dir": str(args.output_dir.resolve()),
                    "case_n": result["case_n"],
                    "formal_label": result["formal_analysis_label_unchanged_rules"],
                    "diagnostic_label": result["neutral_p0_diagnostic_label"],
                    "claim_bearing": result["claim_bearing"],
                },
                indent=2,
            )
        )
        return 0
    raise AssertionError(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
