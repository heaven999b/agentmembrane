# Three-tier pilot: immutable 24-cell checkpoint

Engineering evidence only; `claim_bearing=false`, formal sample count 0. This is
20 original tasks × 3 permission levels × 2 regimes, one run per cell. The
24-cell checkpoint has 23 complete closures and one upstream HTTP 408 unknown.
It is not the final 120-cell result. Execution uses frozen commit `5ddf821`;
scoring corrections are post hoc and original score aggregates remain visible.

- [CHECKPOINT_024.json](CHECKPOINT_024.json): aggregate results with execution,
  manifest, analysis and corrected-checker hashes. Individual cell diagnostics
  remain private; the one corrected L is counted explicitly.
- [STARTUP_FAILURE.json](STARTUP_FAILURE.json): separate first-start HTTP 401,
  baseline configuration and outcome-blind selected task IDs; never pooled into
  the new batch.
- [artifact_manifest.json](artifact_manifest.json): hashes of this public bundle.
- [Interpretation](../../reports/rq1/THREE_TIER_PILOT_20260916.md) and
  [run/export instructions](../../docs/THREE_TIER_LIVE_PILOT.md).

Audit from the repository root (no model calls):

```bash
python3 - <<'PY_AUDIT'
import hashlib, json
from pathlib import Path
root = Path.cwd().resolve()
bundle = root / "results/rq1_three_tier_pilot_20260916"
manifest = json.loads((bundle / "artifact_manifest.json").read_text())
assert manifest["claim_bearing"] is False
for item in manifest["artifacts"]:
    path = (root / item["path"]).resolve()
    assert path.parent == bundle
    data = path.read_bytes()
    assert len(data) == item["size_bytes"]
    assert hashlib.sha256(data).hexdigest() == item["sha256"]
value = json.loads((bundle / "CHECKPOINT_024.json").read_text())
assert "cells" not in value and value["formal_sample_count"] == 0
assert value["closed_cells"] == sum(g["closed_cells"] for g in value["groups"]) == 24
assert value["unknown_closure_cells"] == 1
assert value["scoring_correction_count"] == 1
print("RQ1 pilot public checkpoint audit passed")
PY_AUDIT
```

The hash audit detects changes relative to the manifest; it does not independently
replay the private benchmark. Original sealed evidence was separately verified
before aggregation. Preserve this checkpoint and publish final results in a new
file after all cells close.
