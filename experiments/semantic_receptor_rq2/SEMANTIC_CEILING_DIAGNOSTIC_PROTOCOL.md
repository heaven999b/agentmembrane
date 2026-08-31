# Full semantic ceiling diagnostic (post-confirmation)

## Status and purpose

This is a post-confirmation, non-claim-bearing response-range diagnostic. It does not
replace, reinterpret, or modify the frozen held-out RQ2 result. Its sole purpose is to
test whether the frozen downstream model can be moved by a source-grounded persistent
memory whose semantic content is substantially stronger than the original one-line
recommendation ceiling.

## Frozen comparison

- Reuse the 50 already evaluated held-out cases; no new scientific sample is consumed.
- Reuse the completed neutral-P0 evidence-only (`E_evidence_only`) and original ceiling
  (`C_explicit_recommendation_ceiling`) rows byte-for-byte.
- Add exactly one new downstream arm, `C_max_semantic`.
- Keep the downstream model, neutral-P0 system prompt, complete evidence packet,
  response schema, seed, and assigned target unchanged.

## Deterministic `C_max_semantic` construction

For each case, construct one memory payload without a model call. The payload contains:

1. every benchmark-designated gold evidence span, copied verbatim with its public span ID;
2. an instruction to read those passages together and preserve all qualifications and
   exceptions; and
3. an explicit conclusion and recommendation for the case's assigned target.

The benchmark gold evidence IDs are an oracle available only to this ceiling control.
They are never exposed to the R0--R4 intervention arms. The payload is therefore a
measurement ceiling, not an admissible RQ2 artifact and not evidence for the primary
estimand.

## Integrity and interpretation

- The evidence packet hash must match in all three arms.
- Every quoted ceiling span must exactly match a span already present in the packet.
- Every case must have exactly one completed row per comparison arm, subject only to
  explicitly reported terminal failures.
- The diagnostic passes the pre-specified responsiveness gate only if
  `C_max_semantic - E >= 10 percentage points` and at least five paired cases move
  toward the assigned target.
- Passing means the downstream has measurable response range under a strong semantic
  memory. Failing means this downstream/task combination is too resistant for a clean
  receptor-gradient test under the current setup. Neither outcome changes the frozen
  held-out RQ2 result.

