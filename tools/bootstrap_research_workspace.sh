#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
UPSTREAM="$ROOT/data/host_boundary_v2/upstream"
AGENTDOJO="$UPSTREAM/agentdojo"
TAU2="$UPSTREAM/tau2-bench"
AGENTDOJO_COMMIT=089ed468cf3ed0322acc66b0211f26d9d90dbf60
TAU2_COMMIT=a2c024725189473d2d7cea3a5cfdbcc67478e41f

PYTHON_BIN=${AGENTMEMBRANE_PYTHON:-}
if [ -z "$PYTHON_BIN" ]; then
  if command -v python3.12 >/dev/null 2>&1; then
    PYTHON_BIN=$(command -v python3.12)
  elif command -v python3.13 >/dev/null 2>&1; then
    PYTHON_BIN=$(command -v python3.13)
  else
    PYTHON_BIN=$(command -v python3)
  fi
fi

"$PYTHON_BIN" -c 'import sys; assert (3, 12) <= sys.version_info[:2] < (3, 14), "AgentMembrane research bootstrap requires Python 3.12 or 3.13"'

mkdir -p "$UPSTREAM"

if [ ! -d "$AGENTDOJO/.git" ]; then
  git clone https://github.com/ethz-spylab/agentdojo.git "$AGENTDOJO"
fi
git -C "$AGENTDOJO" fetch --tags origin
git -C "$AGENTDOJO" checkout --detach "$AGENTDOJO_COMMIT"

if [ ! -d "$TAU2/.git" ]; then
  git clone https://github.com/sierra-research/tau2-bench.git "$TAU2"
fi
git -C "$TAU2" fetch --tags origin
git -C "$TAU2" checkout --detach "$TAU2_COMMIT"

"$PYTHON_BIN" -m venv "$ROOT/.venv"
"$ROOT/.venv/bin/python" -m pip install --upgrade pip
"$ROOT/.venv/bin/python" -m pip install -e "$AGENTDOJO" -e "$TAU2" -e "$ROOT[analysis,test]"

test "$(git -C "$AGENTDOJO" rev-parse HEAD)" = "$AGENTDOJO_COMMIT"
test "$(git -C "$TAU2" rev-parse HEAD)" = "$TAU2_COMMIT"

printf '%s\n' "Research workspace ready at $ROOT"
