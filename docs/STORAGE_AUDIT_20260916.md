# AgentMembrane storage and cloud audit (2026-09-16)

## Outcome

The public repository and the private evidence workspace have different roles.
GitHub is the source of truth for public code and sanitized evidence; the large
private workspace is not a disposable clone and must not be deleted wholesale.
The governing rules are in
[`REPOSITORY_TAXONOMY.md`](./REPOSITORY_TAXONOMY.md).

This audit was based on public `main` commit
`5c3b9f8ba64fb8b3bc9dd62803ba70e953e67ded`, after the RQ2 confirmation bundle
was merged. A fresh checkout passed the public repository audit, the RQ2 bundle
audit, and 59 semantic-RQ2 tests. The taxonomy change then passed five
repository-audit tests and Python compilation before publication.

## Publicly recoverable RQ2 material

The private workspace and GitHub match byte-for-byte for:

- 20 semantic-RQ2 source files;
- 17 semantic-RQ2 test files;
- the independent-review tool;
- six calibration-result files and four held-out-result files;
- 18 public protocol/profile/preflight files;
- the confirmation report, confirmation analysis, focused-interaction result,
  semantic-ceiling result, and controller config.

The private experiment README is superseded by the public version, which adds
the published evidence-bundle entry. These small duplicated files are
recoverable from GitHub, but deleting them individually would break the private
workspace layout while saving little space. They remain in place until the
private workspace is retired as a whole under a separate migration.

## Private-only RQ2 evidence

The private `outputs/*rq2*` inventory contains 58 top-level items, 34,260 files,
and 313,136,029 content bytes (about 363 MiB on disk). Its sorted
`SHA-256 + relative path` tree digest is:

```text
5cd06e2c25b22f502440d078ae668122ed658e66ce9e32f40ee1742ed0663977
```

The inventory includes roughly 261 MiB of model caches and 31 MiB of records.
More than 30,000 files contain prompt/request/raw-response fields, and dozens
contain machine-local paths. These are unique audit evidence, not public Git
artifacts and not automatically reproducible.

Five frozen ContractNLI manifests (about 2.9 MiB) also remain private because
they contain licensed benchmark text. The public preflight receipts and
controller config retain their hashes, but hashes cannot reconstruct the
manifest content.

The current public GitHub repository is therefore not a backup of the raw RQ2
evidence. Those outputs and manifests may be deleted only after upload to an
access-controlled, versioned private object store and a full restore/hash drill.

## Other local classifications

- The authored RQ2 live-monitor source is local-only. It must be hardened and
  migrated as `apps/rq2-monitor/` before its source can be deleted. Generated
  `.next`, `.vinext`, `.wrangler`, `dist`, and cache directories are disposable
  only when no process uses them.
- Host Boundary files with legacy `RQ2` names answer canonical RQ1b
  (`host_mediated_capability_exploitation`), not semantic RQ2. They must remain
  separately classified and must never be pooled with canonical RQ2 evidence.
- The canonical public checkout contains active RQ1 work and is not a cleanup
  target.
- The large private workspace is used by active experiment processes and is not
  a cleanup target during those runs.

## Safe cleanup order

1. Merge and read back the public commit from GitHub.
2. Re-run audits and study tests from a fresh checkout.
3. Remove only temporary clean publication/verification checkouts created for
   the completed upload.
4. For private evidence, generate a complete per-file size/SHA-256 manifest,
   upload to private versioned storage, download it independently, and verify
   every file plus a representative reanalysis.
5. Move only the explicit verified paths to a recoverable trash/quarantine
   location; retain them for a review window before permanent deletion.

No raw RQ2 output, frozen manifest, canonical checkout, or active private
workspace is authorized for deletion by the public upload alone.
