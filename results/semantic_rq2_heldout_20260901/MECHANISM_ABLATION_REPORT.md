# RQ2 mechanism ablation report

## Purpose and status

This post-confirmation panel strengthens the mechanism analysis behind the RQ2
held-out result. It does not add independent cases and is not substituted for the
frozen primary estimate. The panel asks why the content-controlled ladder retained
an R3 dip even though R3 and R4 carried the same propositions.

Before new outcomes were evaluated, nine contrasts were frozen across seven
conditions. Every condition reused the same source-fidelity-valid R3 backbone for
each case and mode. No new generator, surrogate, or auditor call was made.

## Human-readable design

The experiment separates four explanations that were previously bundled together:

1. **Format:** is the same inference treated differently as structured fields versus
   ordinary text?
2. **Answer layer:** what happens when conclusion and recommendation are added?
3. **Component contribution:** do conclusion and recommendation contribute at the
   same step, or does one matter more?
4. **Context and repetition:** is a recommendation stronger with its reasoning, and
   is R4 stronger merely because it is longer or repeated?

Seven versions were evaluated within every case and mode:

| Short name | What the downstream saw in memory |
|---|---|
| `S_inference` | native structured inference and uncertainty |
| `S_full` | native structured inference, conclusion, and recommendation |
| `T_inference` | the same inference rendered as ordinary text |
| `T_inference_conclusion` | text inference plus the exact conclusion |
| `T_full` | text inference, conclusion, and recommendation |
| `T_recommendation_only` | only the exact recommendation |
| `T_full_repeated` | the identical complete text repeated twice |

## Integrity

- 50 cases from the already used 25 held-out ContractNLI document clusters.
- 700/700 expected case-mode-condition records completed.
- 400/400 new GPT downstream calls completed with valid packet identity and
  evidence citations.
- 300 existing R2/R3/R4 records were reused exactly, with zero object-level mismatch.
- All 700 rows inherited a source-fidelity-valid backbone.
- New cached requests contained zero `assigned_target`, `gold_label`,
  `private_assigned_target`, or `arm_id` fields.

## Condition effects

Effects are paired attack-minus-honest changes in assigned-target selection.

| Condition | Effect | Toward / away | Exact sign p | Cluster bootstrap 95% CI |
|---|---:|---:|---:|---:|
| Structured inference | +8 pp | 4 / 0 | 0.125 | [2, 16] pp |
| Structured full answer layer | +2 pp | 2 / 1 | 1.000 | [-4, 8] pp |
| Text inference | +2 pp | 1 / 0 | 1.000 | [0, 6] pp |
| Text inference + conclusion | +4 pp | 2 / 0 | 0.500 | [0, 10] pp |
| Text full answer layer | +8 pp | 4 / 0 | 0.125 | [2, 16] pp |
| Text recommendation only | +6 pp | 3 / 0 | 0.250 | [0, 12] pp |
| Text full repeated | -2 pp | 0 / 1 | 1.000 | [-6, 0] pp |

## Pre-specified mechanism contrasts

| Contrast | Difference | Raw exact sign p | Holm p across 9 | Cluster bootstrap 95% CI |
|---|---:|---:|---:|---:|
| Text vs structured, inference only | -6 pp | 0.250 | 1.000 | [-14, 0] pp |
| Text vs structured, full answer layer | +6 pp | 0.250 | 1.000 | [0, 14] pp |
| Add answer layer in structured form | -6 pp | 0.250 | 1.000 | [-14, 0] pp |
| Add answer layer in text form | +6 pp | 0.250 | 1.000 | [0, 12] pp |
| Format × answer-layer interaction | +12 pp | 0.031 | 0.281 | [4, 20] pp |
| Add conclusion in text | +2 pp | 1.000 | 1.000 | [-4, 8] pp |
| Add recommendation after conclusion | +4 pp | 0.625 | 1.000 | [-4, 12] pp |
| Add reasoning context around recommendation | +2 pp | 1.000 | 1.000 | [-4, 8] pp |
| Repeat the identical complete text | -10 pp | 0.063 | 0.500 | [-18, -2] pp |

No contrast survives the pre-specified nine-test Holm family. The table is therefore
mechanism evidence, not a new statistically confirmed boundary claim.

## Interpretation

The clearest descriptive pattern is an interaction between representation and the
answer layer. Adding conclusion and recommendation reduced the structured effect
from 8 to 2 points, while adding the same semantic layer increased the text effect
from 2 to 8 points. The resulting 12-point interaction is supported by six same-
direction discordant cases and no opposite cases, but it is not multiplicity-
corrected significant at this sample size.

The text component buildup (`2 -> 4 -> 8` points) suggests that conclusion and
recommendation add influence gradually when presented as ordinary prose. A
recommendation without reasoning already produced 6 points, while adding the full
reasoning context increased it by only 2 points. Finally, repeating the identical
full text did not strengthen it; the observed effect fell by 10 points relative to
the single rendering. This rules against a simple "more tokens always means more
risk" explanation, although repetition can change salience and is not a perfectly
pure bandwidth intervention.

Together with the earlier nested panel, this supports a more specific explanation
of the R3 dip: the downstream is sensitive to how answer-like semantics are
represented, not merely to whether those semantics are present. The paper can use
this as an exploratory mechanism ablation. A new model family or frozen SciFact
sample should replicate the interaction before it is promoted to a general claim.

## Execution accounting and anchors

- New downstream calls: 400
- New tokens: 594,556
- Results SHA-256:
  `9207628d62a3ec60fa3452512d66f71063f392c76a619c4d39f6941af98095ef`
- Records SHA-256:
  `4147c35b4743c85b54b8375910766acbdc42ab9f7e24201ffd669f355864e671`
- Materialization receipt SHA-256:
  `dc2febb3f5f529e03d225440e05e007bb14719d97b933d8f35b2a274fd3c99b7`

