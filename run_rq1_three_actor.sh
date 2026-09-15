#!/bin/bash
# Dedicated reviewed runtime. No package installation or credential discovery.
set -euo pipefail
RQ1_PROJECT_ROOT="$(cd -- "$(dirname -- "$0")" && pwd)"
RQ1_RUNTIME="$RQ1_PROJECT_ROOT/experiments/host_boundary_v2/runtime_envs/agentdojo-0.1.35-py3123-lock-395e3d0a5921-rq1v4"
if [[ ! -x "$RQ1_RUNTIME/bin/python" ]]; then
    echo "The reviewed RQ1 Python runtime is unavailable." >&2
    exit 1
fi
cd -- "$RQ1_PROJECT_ROOT"
RQ1_MODULE="agentmembrane.host_v2.rq1_collab_v3"
if [[ "${1:-}" == "score" ]]; then
    RQ1_MODULE="agentmembrane.host_v2.rq1_scorecard_v5"
    shift
elif [[ "${1:-}" == "score-v4" ]]; then
    RQ1_MODULE="agentmembrane.host_v2.rq1_scorecard_v4"
    shift
fi
exec env PYTHONOPTIMIZE=0 PYDANTIC_DISABLE_PLUGINS=__all__ PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH="$RQ1_RUNTIME/lib/python3.12/site-packages:$RQ1_PROJECT_ROOT" \
    "$RQ1_RUNTIME/bin/python" -S -m "$RQ1_MODULE" "$@"
