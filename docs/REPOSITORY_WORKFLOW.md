# Repository and local workspace workflow

## Canonical locations

- Public Git repository: <https://github.com/heaven999b/agentmembrane>
- Canonical local Git checkout: `agentmembrane-publish/`
- Private research-data workspace: sibling directory `agentmembrane/`

The Git checkout owns source code, tests, protocols, public aggregate results,
reports, and the complete weekly-report index. The private workspace holds
datasets, raw model I/O, runtime environments, route/account attestations, and
large run artifacts. This is one project with a public repository and an
explicit local data boundary, rather than two competing source trees.

The artifact taxonomy, stable scientific identity rules, naming contract, and
local deletion gate are defined in
[`REPOSITORY_TAXONOMY.md`](./REPOSITORY_TAXONOMY.md). The machine-readable
construct map is [`studies/registry.json`](../studies/registry.json).

## Source-of-truth rules

1. GitHub `main` and the canonical local checkout are authoritative for code and
   public documentation.
2. New code changes start in the canonical checkout. If a data-bound experiment
   must run from the private workspace, the reviewed source diff is copied back
   and committed before the work is considered complete.
3. A report in staging, a handoff folder, or the private workspace is a draft.
   Publication requires the checklist in
   [`weekly_reports/PROCESS.md`](../weekly_reports/PROCESS.md).
4. Raw evidence never becomes public merely because code refers to it. Public
   artifacts contain aggregate results or intentionally sanitized fixtures.
5. Before every push, run `python3 tools/audit_public_repo.py` and the relevant
   offline tests. After the push, verify `main`, `origin/main`, and GitHub resolve
   to the same commit.

## Public repository contents

- `agentmembrane/`: runtime and analysis source
- `tests/`: offline and synthetic regression tests
- `tools/`: reproducible builders, validators, and release checks
- `experiments/`: frozen protocols and small public metadata only
- `results/` and `reports/`: aggregate, shareable results and interpretation
- `weekly_reports/`: the canonical Week 1 onward reporting sequence

## Local-only contents

- provider credentials and CLIProxy configuration
- account or route attestations, even when hashed
- raw prompts, responses, traces, receipts, and per-episode run directories
- downloaded benchmarks, third-party repositories, databases, and caches
- Python/runtime environments and binary wheels
- superseded live campaigns and their resumable state

## Explicit local route configuration

Public source contains no machine-specific proxy endpoint, credential-variable
name, account label, or configuration path. Live entry points fail closed until
the caller supplies their local values:

- Generic local client: `AGENTMEMBRANE_PROXY_BASE_URL` plus either
  `AGENTMEMBRANE_PROXY_API_KEY` or `AGENTMEMBRANE_PROXY_CONFIG`.
- Legacy bounded diagnostic: `RQ1_PROXY_CONFIG`, `RQ1_PROXY_BASE_URL`, and
  `RQ1_PROXY_CREDENTIAL_ENV`.
- V6 route collision/shared-route policy: `AGENTMEMBRANE_SHARED_PROXY_ENDPOINT`,
  `AGENTMEMBRANE_SHARED_PROXY_CREDENTIAL_ENV`, and
  `AGENTMEMBRANE_SHARED_PROXY_LABEL`.
- Management client: `AGENTMEMBRANE_PROXY_ADMIN_BASE_URL` and
  `AGENTMEMBRANE_PROXY_ADMIN_INSTRUCTIONS`.

Endpoints must be explicit loopback URLs. Credential values remain in the
caller-named environment variable or local configuration file and are never
written into repository artifacts.

The public audit rejects common secret forms, account-specific identifiers,
machine-specific proxy defaults, private route/account metadata, absolute
personal paths, unexpectedly large files, and broken Markdown links. Tracked
files must be UTF-8 text with an explicitly safe extension; any necessary
binary requires a reviewed, repository-relative allowlist entry.
