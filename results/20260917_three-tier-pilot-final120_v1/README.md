# Final engineering pilot: 120 registered cells

All 120 cells closed and verified: 113 completed executions, 7 retained unknown
closures, no pending cells. There were 980 model requests in this batch. This is
engineering evidence, not a formal RQ1 claim. Original scores remain preserved.

- [aggregate.json](aggregate.json): final six-condition results and code/evidence bindings.
- [paired_final.json](paired_final.json): same-task utility comparison, with missing pairs retained in counts.
- [paired_checkpoint105.json](paired_checkpoint105.json): matching analysis of the previously published checkpoint.
- [Report and medium-tier diagnosis](../../reports/rq1/THREE_TIER_FINAL_MEDIUM_DIAGNOSIS_20260917.md).

The pair tool consumes the independently verified private snapshot with its
required SHA256, and exports aggregate counts only:

```bash
python3 tools/compare_rq1_pilot_pairs.py --snapshot "$VERIFIED_PRIVATE_SNAPSHOT" \
  --expected-sha256 "$SNAPSHOT_SHA256" --output "$NEW_PAIR_AGGREGATE"
```

Audit this published bundle from repository root, without model calls:

```bash
python3 - <<'PY_AUDIT'
from pathlib import Path
import json, hashlib
root = Path.cwd().resolve()
bundle = root / "results/20260917_three-tier-pilot-final120_v1"
m = json.loads((bundle / "artifact_manifest.json").read_text())
for item in m["artifacts"]:
    p = (root / item["path"]).resolve()
    assert p.parent == bundle
    data = p.read_bytes()
    assert len(data) == item["size_bytes"]
    assert hashlib.sha256(data).hexdigest() == item["sha256"]
a = json.loads((bundle / "aggregate.json").read_text())
assert "cells" not in a and a["formal_sample_count"] == 0
assert a["closed_cells"] == sum(g["closed_cells"] for g in a["groups"]) == 120
assert a["unknown_closure_cells"] == 7 and a["infrastructure_unknown_cells"] == 3
assert a["unattempted_cells"] == a["in_progress_or_unscored_cells"] == 0
for name in ["paired_final.json", "paired_checkpoint105.json"]:
    p = json.loads((bundle / name).read_text())
    for g in p["groups"]:
        assert g["paired_identified"] + g["missing_or_unidentified_pairs"] == g["planned_pairs"] == 20
        assert g["both_success"] + g["both_failure"] + g["honest_only_success"] + g["malicious_only_success"] == g["paired_identified"]
        assert g["honest_success"] == g["both_success"] + g["honest_only_success"]
        assert g["malicious_success"] == g["both_success"] + g["malicious_only_success"]
print("Final pilot aggregate and paired-count audits passed")
PY_AUDIT
```

These hash checks protect the published files, not a new replay of private raw
evidence. The sealed evidence was independently revalidated before export.
Raw trajectories and private accounts/routes are not distributed. Pair counts
are descriptive and use one run per condition; missing outcomes are never
silently treated as success or failure.
