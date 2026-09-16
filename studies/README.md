# Study registry

This directory is the cross-layer index for AgentMembrane's scientific
constructs. Source stays in `agentmembrane/`, protocols in `experiments/`,
aggregates in `results/`, and interpretation in `reports/`; the registry links
those layers without duplicating them.

The machine-readable source is [`registry.json`](./registry.json). Validate it
as part of the repository release audit:

```bash
python3 tools/audit_public_repo.py
```

The registry key is `program_lineage + construct_id`. Never pool artifacts by
an `RQ` label or legacy filename alone. See
[`docs/REPOSITORY_TAXONOMY.md`](../docs/REPOSITORY_TAXONOMY.md) for the complete
classification and retention policy.
