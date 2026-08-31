# RQ2 mechanism ablations: format, answer layer, components, context, and repetition

## Status

This is a post-confirmation, non-claim-bearing mechanism panel. It reuses the 50
held-out ContractNLI cases and the already frozen, source-fidelity-valid R3 semantic
backbone for each case and mode. It does not alter or replace the held-out RQ2 result.

The panel is frozen before its new downstream outcomes are evaluated. It makes no
new generator, surrogate, or auditor calls. Every new artifact is a deterministic
R4 rendering of fields already present in the admitted R3 backbone.

## Conditions

Seven conditions are compared within every case and mode. `S` means a native
structured receptor and `T` means a free-text carrier.

| Condition | Frozen construction | Source |
|---|---|---|
| `S_inference` | evidence IDs + inference + uncertainty | existing nested R2 |
| `S_full` | the same fields + conclusion + recommendation | existing nested R3 |
| `T_inference` | fixed text rendering of inference + uncertainty | new R4 projection |
| `T_inference_conclusion` | `T_inference` + the exact conclusion | new R4 projection |
| `T_full` | the exact inference, uncertainty, conclusion, and recommendation | existing nested R4 |
| `T_recommendation_only` | the exact recommendation without its reasoning context | new R4 projection |
| `T_full_repeated` | the exact `T_full` block rendered twice, with no new proposition | new R4 projection |

All conditions retain exactly the same evidence IDs within a case and mode. Text is
copied byte-for-byte from the common backbone; no paraphrase is generated.

## Pre-specified contrasts

Every condition first receives the standard paired attack-minus-honest target-rate
estimate. Eight mechanism contrasts are then computed within the same case:

1. `format_without_answer_layer`: `T_inference - S_inference`;
2. `format_with_answer_layer`: `T_full - S_full`;
3. `answer_layer_in_structured`: `S_full - S_inference`;
4. `answer_layer_in_text`: `T_full - T_inference`;
5. `format_x_answer_layer_interaction`: contrast 4 minus contrast 3;
6. `add_conclusion_in_text`: `T_inference_conclusion - T_inference`;
7. `add_recommendation_in_text`: `T_full - T_inference_conclusion`;
8. `reasoning_context_for_recommendation`: `T_full - T_recommendation_only`;
9. `repeat_same_full_text`: `T_full_repeated - T_full`.

The interaction is retained as a planned ninth contrast, so Holm correction is
applied jointly across all nine tests. Exact two-sided sign tests ignore ties;
document-cluster bootstrap intervals resample ContractNLI documents, not individual
questions.

## Interpretation boundaries

- A positive format contrast means the same propositions are more influential in
  free text than in native structured fields.
- The conclusion and recommendation contrasts separate the two answer-layer
  components instead of treating R3 as one indivisible change.
- The context contrast asks whether reasoning surrounding an identical recommendation
  strengthens or weakens its influence.
- The repetition contrast is a bandwidth/emphasis sensitivity check. It is not
  described as a perfectly pure token-count intervention because repetition can
  itself change salience.
- These results are mechanism ablations on reused cases. They do not provide new
  independent confirmation, a formal monotonicity claim, or a stable `R*`.

