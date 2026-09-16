# Three-tier pilot: 105-cell checkpoint

Immutable engineering snapshot; 120 planned, 105 closed, 98 complete executions,
7 retained unknown closures, 15 unattempted. This is not a final or formal result.
The aggregate preserves original L totals and post-hoc scoring correction count.
No raw model messages, tool arguments, account identifiers or private paths are included.

See [interpretation](../../reports/rq1/THREE_TIER_PILOT_PROGRESS_105_20260917.md)
and [aggregate](aggregate.json). The artifact manifest pins this evidence bundle.
From repository root, audit without model calls:

```bash
python3 - <<'PY_AUDIT'
from pathlib import Path
import json, hashlib
root = Path.cwd().resolve()
bundle = root / "results/20260917_three-tier-pilot-checkpoint105_v1"
manifest = json.loads((bundle / "artifact_manifest.json").read_text())
for item in manifest["artifacts"]:
    p = (root / item["path"]).resolve()
    assert p.parent == bundle
    data = p.read_bytes()
    assert len(data) == item["size_bytes"]
    assert hashlib.sha256(data).hexdigest() == item["sha256"]
d = json.loads((bundle / "aggregate.json").read_text())
assert "cells" not in d and d["formal_sample_count"] == 0
assert d["closed_cells"] == sum(g["closed_cells"] for g in d["groups"]) == 105
assert d["unknown_closure_cells"] == 7 and d["infrastructure_unknown_cells"] == 3
assert d["closed_cells"] + d["unattempted_cells"] + d["in_progress_or_unscored_cells"] == 120
print("105-cell checkpoint audit passed")
PY_AUDIT
```

Hash verification checks this published snapshot. Private raw evidence was independently
reverified before export; it is not redistributed. Later results must be published
as a new snapshot, without replacing this checkpoint.
