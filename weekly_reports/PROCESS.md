# Weekly report process

`weekly_reports/` in this repository is the single canonical public home for the
weekly research sequence. Weeks 1--5 are an imported, content-preserving archive
of the predecessor memory-consolidation program. Week 6 marks the transition to
AgentMembrane. Copies in handoff packages, desktop folders, or research-output
directories are working copies only.

## Directory contract

New reports use this layout:

```text
weekly_reports/weekN/
  README.md
  weekN_report_YYYYMMDD_zh.md
  supporting/                  # optional, public and sanitized evidence only
```

Historical imports preserve their original naming when renaming would weaken the
archive trail. Week 1 is the documented legacy exception: it contains an English
report named `week1_report_20260709_en.md` and uses `supporting_materials/`; its
`week1_round_results_viewing_guide_zh.md` is the Chinese navigation entry point.
New weeks must follow the directory contract above.

The root [README](../README.md) must link every published week. Machine-readable
supporting files belong beside the report that cites them. Raw model prompts,
responses, credentials, local route metadata, private datasets, runtime
environments, and large run directories stay outside Git.

## Release checklist

1. Write the report inside its final `weekly_reports/weekN/` directory.
2. State the evidence level and distinguish diagnostic, engineering, and formal
   results. Never count tests or retries as research samples.
3. Use repository-relative links. Do not publish absolute local filesystem
   paths, loopback proxy configuration, account identifiers, credential variable
   names, or secrets.
4. Add only aggregate or otherwise shareable supporting evidence.
5. Verify every Markdown link and every numerical claim against the supporting
   snapshot.
6. Scan the complete staged diff for secrets, personal paths, and unexpectedly
   large files.
7. Run the relevant offline tests, commit the report and index together, push,
   then verify that local `main`, `origin/main`, and GitHub resolve to the same
   commit.

## Completion rule

A weekly report is published only when all four are true:

- the report and its `README.md` are tracked by Git;
- the root weekly index links it;
- release validation passes;
- the commit is present on GitHub `main`.

Staging folders may be used for recovery, but they are never the authoritative
copy after publication.
