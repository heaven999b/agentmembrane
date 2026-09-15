"""Explicit -I -S launcher: locked dependencies, no ambient .pth startup hooks.

Run using the registered Python executable with ``-I -S path/to/launcher.py``.
The SQLite multiprocessing writer inherits these interpreter flags and the
explicit dependency paths. No authority, action budget or timeout is changed.
"""
from __future__ import annotations

import json
from pathlib import Path
import runpy
import sys

PROJECT = Path(__file__).resolve().parents[3]
ENVIRONMENT = PROJECT / "experiments/host_boundary_v2/runtime_envs/agentdojo-0.1.35-py3123-lock-395e3d0a5921-rq1v4"
TARGETS = {"workflow": "agentmembrane.host_v2.rq1_collab_v5.workflow",
           "paired": "agentmembrane.host_v2.rq1_collab_v5.paired_pilot",
           "score": "agentmembrane.host_v2.rq1_measurement_v1.workflow",
           "probe": "agentmembrane.host_v2.rq1_collab_v4.model_probe",
           "inventory": "agentmembrane.host_v2.rq1_collab_v1.live_pilot",
           "tests": "unittest"}


def bootstrap():
    if not sys.flags.isolated or not sys.flags.no_site:
        raise RuntimeError("explicit_isolated_no_site_startup_required_use_python_I_S")
    if Path(sys.executable).resolve() != (ENVIRONMENT / "bin/python").resolve() or sys.version_info[:3] != (3, 12, 3):
        raise RuntimeError("registered_python_3_12_3_required")
    site = ENVIRONMENT / "lib/python3.12/site-packages"
    if not site.is_dir():
        raise RuntimeError("registered_dependency_directory_missing")
    for path in (str(PROJECT), str(site)):
        if path not in sys.path:
            sys.path.append(path)
    return {"python": sys.executable, "python_version": sys.version.split()[0],
            "dependency_site": str(site), "no_site": bool(sys.flags.no_site),
            "isolated": bool(sys.flags.isolated), "pth_hooks_executed": False,
            "actor_permissions_changed": False, "runtime_limits_changed": False}


def main():
    startup = bootstrap()
    if len(sys.argv) < 2 or sys.argv[1] == "check":
        print(json.dumps(startup))
        return 0
    target = TARGETS.get(sys.argv[1])
    if target is None:
        raise ValueError("registered_rq1_command_required")
    sys.argv = [target, *sys.argv[2:]]
    runpy.run_module(target, run_name="__main__", alter_sys=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
