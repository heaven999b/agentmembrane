# Repository tools

This directory contains repository-wide operator commands: bootstrap, release
audits, validators, materializers, and reproducible entry points. Reusable study
logic belongs in `agentmembrane/`, while a thin operator CLI may remain here.

Before publishing, run at least:

```bash
python3 tools/audit_public_repo.py
```

Then run the tests and evidence-bundle audits relevant to the changed study.
Commands that can make paid calls or mutate external state must say so in their
help text and fail closed when required configuration is absent.
