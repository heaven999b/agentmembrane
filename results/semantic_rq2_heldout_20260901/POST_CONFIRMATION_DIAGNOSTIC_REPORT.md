# RQ2 post-confirmation response-range and nested-content diagnostics

## Status

These two 50-case panels were executed after the held-out result was known. They
are engineering diagnostics, not new confirmatory evidence, and they do not alter
the frozen held-out estimates. Both reuse the same 50 held-out cases from 25
ContractNLI document clusters and the same `gpt-5.6-terra` downstream.

The diagnostics answer two concrete questions raised by the held-out run:

1. Did the original one-line ceiling fail merely because it was too weak?
2. Did independently generated R0--R4 content cause the observed R3 dip?

## Diagnostic A: full semantic ceiling

The original ceiling was retained. A new `C_max_semantic` arm added every
benchmark-designated evidence span verbatim, explicitly instructed the reader to
preserve conditions and exceptions, and ended with the assigned wrong-target
conclusion and recommendation. The complete evidence packet, downstream model,
neutral-P0 wrapper, response schema, target assignment, and seed were unchanged.
This oracle-assisted arm is a response-range control only; its use of gold evidence
IDs makes it inadmissible as an RQ2 attack artifact.

All 150 comparison records completed and passed packet-identity checks. The
evidence-only and old-ceiling target rates were both 8%. The full semantic ceiling
raised the target rate to 12%, a paired increase of only 4 percentage points:

- 2 cases moved toward the assigned target;
- 0 cases moved away;
- exact McNemar `p=0.50`;
- document-cluster bootstrap 95% CI: `[0, 10]` percentage points.

The frozen responsiveness gate required at least +10 points and five toward-target
pairs, so it failed. The old one-line control was indeed weaker, but its weakness
was not the sole explanation. Even an oracle-grounded, explicit wrong-target memory
rarely overrode a complete packet on which evidence-only accuracy was 92%.

## Diagnostic B: nested R0--R4 projection

The original optimized-capacity panel generated every receptor independently. The
nested panel instead used each already frozen, source-fidelity-valid R3 artifact as
one semantic backbone per case and mode. It then projected that backbone without a
new generator call:

- R0 kept the same evidence IDs;
- R1 kept those IDs and added fixed annotations;
- R2 kept the exact R3 inference and uncertainty;
- R3 kept the original payload byte-for-byte; and
- R4 used a fixed lossless text rendering of the same R3 fields.

All 500 projected artifacts passed schema and nesting checks before evaluation.
All 600 downstream records completed, all packet hashes and citations were valid,
and broad construct-valid coverage was 100% at every receptor.

| Receptor | Nested paired effect | Toward / away | Exact paired p | Cluster bootstrap 95% CI |
|---|---:|---:|---:|---:|
| R0 evidence selection | -4 pp | 0 / 2 | 0.500 | [-10, 0] pp |
| R1 evidence annotation | -2 pp | 1 / 2 | 1.000 | [-8, 4] pp |
| R2 structured inference | +8 pp | 4 / 0 | 0.125 | [2, 16] pp |
| R3 recommendation | +2 pp | 2 / 1 | 1.000 | [-4, 8] pp |
| R4 free form | +8 pp | 4 / 0 | 0.125 | [2, 16] pp |

The observed curve remained non-monotone: `-4, -2, 8, 2, 8` points. R3 was 6
points below R2, and R4 was 6 points above R3. Neither adjacent contrast was exact-
test significant after multiplicity correction. Because R3 and R4 carry the same
propositions in this panel, their descriptive difference is a format/salience
effect rather than a content difference. Independent generation therefore
contributed to the larger original R2/R4 magnitudes, but it was not the main cause
of the R3 dip.

## RQ2 interpretation

This is not evidence of target or gold-label leakage. Downstream views outside the
declared ceiling contain no target, gold-label, mode, or arm fields; packet identity
and role isolation passed. The deliberate oracle disclosure is confined to
`C_max_semantic` and is labelled as such.

The proposal asks whether risk increases monotonically and whether a stable
receptor threshold exists, while explicitly stating that strict monotonicity is not
assumed and a non-monotone result is substantive. The current evidence therefore
supports a scoped conclusion: structured inference and free-form text show positive
semantic influence in this setup, but a monotone dose-response and stable `R*` are
not established. The main compression mechanism is high downstream reliance on the
complete evidence packet, combined with sensitivity to representation format.

## Decision and next experiment

Do not enlarge this exact ContractNLI/Terra configuration to a formal 100-cluster
run. More observations cannot repair a failed response-range gate, and only 57
unseen ContractNLI clusters remain under the balanced-pair rule.

The next informative step is a preregistered 50-case cross-model/domain panel:

1. keep both the optimized-capacity and nested-content estimands, named in advance;
2. run a genuinely different downstream model family on the already frozen cases
   to test whether the R3/R4 format effect is Terra-specific;
3. freeze a new SciFact sample before outcome inspection to obtain fresh independent
   clusters and a task with a different evidence/decision balance;
4. keep the same source-fidelity policy and add the planned human audit sample; and
5. treat non-monotonicity as an allowed result rather than changing the rubric until
   a monotone curve appears.

## Execution accounting and anchors

| Panel | New calls | Tokens | Integrity |
|---|---:|---:|---|
| Full semantic ceiling | 50 | 80,002 | 150/150 records PASS |
| Nested R0--R4 projection | 500 | 728,259 | 600/600 records PASS |

- Semantic-ceiling results SHA-256:
  `b7e118bf5bd4b2a12c3f95dbe228b5220583f737eb99eed894ab06704a45a8fc`
- Semantic-ceiling records SHA-256:
  `1c209f3ee35a4d25d17893b07de2e681268252265bd15870c323a842a9bd92a9`
- Nested results SHA-256:
  `61ea6d8a176e14e04e7cf81c2b2814918238c0fb9aac513d5f214eb72e20c583`
- Nested records SHA-256:
  `aef4a81dc93b42b2ba420e6787974fcb6fc4a4d6353aedd000a230d78d9a58af`
- Nested materialization receipt SHA-256:
  `ddfba0938f7994c58b0585153548d28ffc2a0fdce11709ce60216167d3ca093e`

