# Repository taxonomy and evidence lifecycle

This document defines where AgentMembrane artifacts belong and when a local
copy may be deleted. The rules are additive: existing public paths remain stable
unless a separately reviewed migration updates every import, link, test, and
manifest reference.

## Scientific identity

An `RQ` label is a human-facing label, not a stable database key. The canonical
identity of a study is:

```text
program_lineage + construct_id + study_id + run_id
```

The canonical construct map lives in [`studies/registry.json`](../studies/registry.json).
This is necessary because historical Host Boundary artifacts used `RQ2` for a
host-mediated authority experiment, while proposal RQ2 is now
`semantic_receptor_expressiveness`. Those artifacts may retain legacy aliases
for reproduction, but their evidence must never be pooled by the alias alone.

## Public repository classes

| Path | Owns | Must not contain |
| --- | --- | --- |
| `agentmembrane/` | reusable runtime, schema, analysis, and CLI source | local endpoints, credentials, datasets, run state |
| `apps/` | optional first-party interfaces with an independent README and test/build entry point | build output, hosting state, hard-coded local paths |
| `tests/` | synthetic, offline, and explicitly gated integration checks | licensed benchmark text or private live fixtures |
| `experiments/` | frozen protocols, preregistration, profiles, small configs, preflight receipts | raw prompts/responses, per-case records, resumable state |
| `results/` | immutable, sanitized aggregate evidence bundles | raw model I/O, dataset text, machine-local paths |
| `reports/` | stable human interpretation across one or more runs | results that are not linked to machine evidence |
| `weekly_reports/` | chronological lab record and historical decisions | the only copy of a protocol or result |
| `studies/` | cross-directory construct and study registry | raw evidence or duplicate implementations |
| `docs/` | proposal, governance, repository policy, and current entry points | generated run output |
| `references/` | literature notes and source metadata | downloaded third-party repositories or PDFs |
| `tools/` | repository-wide release, audit, bootstrap, and operator commands | study logic that belongs in the package |
| `data/` | acquisition/license instructions and intentionally synthetic fixtures | redistributable assumptions about licensed data |
| `outputs/` | ignored local run target only | tracked files of any kind |

Top-level classification is by artifact type. Scientific relationships across
those directories are represented by the study registry rather than by moving
all files for an RQ into one large folder.

## Private workspace classes

The sibling private workspace is a data plane, not a second source repository.
It may hold:

- licensed datasets and frozen manifests containing dataset text;
- raw prompts, responses, traces, evaluation records, and model caches;
- route/account attestations and local runtime bindings;
- exact runtime environments and third-party source checkouts;
- private evidence archives and resumable run state.

Credentials are never an archival artifact. They remain in the configured
credential store and are neither committed nor placed in evidence archives.

## Evidence lifecycle

1. **Plan:** register the construct and freeze a protocol under `experiments/`.
2. **Run:** write raw state only to the private workspace or ignored `outputs/`.
3. **Validate:** bind config, code, data fingerprint, seed, and integrity checks.
4. **Publish:** create a sanitized `results/` bundle with a README, aggregate
   result, artifact manifest, and executable audit command.
5. **Interpret:** update the stable `reports/` entry and, when appropriate, the
   weekly timeline in the same reviewed change.
6. **Index:** add or update the `studies/` record using canonical construct IDs.
7. **Retain or delete:** apply the deletion gate below; never infer deletability
   merely from a similar filename in GitHub.

## Naming contract

- Construct identifiers use stable snake case, for example
  `semantic_receptor_expressiveness`.
- New study directories use `<YYYYMMDD>_<study-slug>_vN` below their artifact
  class when a date/version is required.
- A public evidence bundle should declare `program_lineage`, `construct_id`,
  `construct_version`, `study_id`, `evidence_level`, `claim_bearing`, code/data
  bindings, and a repository-relative artifact manifest.
- Historical names remain unchanged when renaming would damage provenance.
  Their canonical interpretation belongs in the registry.

## Local deletion gate

A local path is deletable only when every applicable check passes:

1. its exact role is classified as `replicated`, `reconstructable`, or
   `disposable`; unique scientific evidence is never assumed reconstructable;
2. every retained object has a size and SHA-256 entry;
3. the remote object or Git commit has been read back and its identity verified;
4. a fresh checkout or restore drill reproduces the expected files and audits;
5. no running process has the path open as its code, data, runtime, or output;
6. deletion uses an explicit allowlist of resolved paths, never a broad glob;
7. the deletion is recorded with the remote recovery pointer.

| Local class | Public GitHub | Private versioned storage | Delete after verification |
| --- | --- | --- | --- |
| code, tests, protocols, sanitized aggregates | yes | optional | duplicate/temp copies only |
| raw prompts/responses and per-case evidence | no | yes | only after restore-tested private backup |
| licensed manifests/datasets | no | license-dependent private storage | only if reacquisition is verified |
| credentials | no | no | remove when expired or rotated |
| caches, build output, virtual environments | no | no | yes, when no active process depends on them |
| temporary clones and staging directories | no | no | yes, after canonical remote verification |

The current large private workspace cannot be deleted as one unit: it contains
unique evidence and runtime state, and active experiments may depend on it.
Cleanup must proceed by the explicit classes above.
