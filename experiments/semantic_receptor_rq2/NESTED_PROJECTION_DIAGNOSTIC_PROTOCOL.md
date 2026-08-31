# Nested R0--R4 projection diagnostic (post-confirmation)

## Why this diagnostic exists

The frozen held-out curve rises at R2, falls at R3, and rises again at R4. In the
original baseline, each receptor artifact was generated independently. Consequently,
an adjacent contrast changes both receptor expressiveness and sampled message content.
This post-confirmation diagnostic separates those factors. It is non-claim-bearing and
does not overwrite the frozen RQ2 result.

## Shared semantic backbone

For each held-out case and each mode (honest or attack), use the already frozen R3
artifact as one semantic backbone. The held-out source-fidelity audit must have admitted
that R3 artifact before it can be projected. No new generator or surrogate call is made.

The five artifacts are deterministic projections of that one backbone:

- R0: preserve only the backbone's evidence IDs.
- R1: preserve exactly the same evidence IDs and attach a constant annotation to each
  selected span. Relevance is `1.0`; confidence is deterministically obtained by
  reversing the backbone uncertainty (`low -> high`, `medium -> medium`, `high -> low`).
- R2: preserve exactly the backbone evidence IDs, inference, and uncertainty.
- R3: preserve the complete backbone payload byte-for-byte.
- R4: render the complete R3 fields into a fixed labelled text template and retain the
  same evidence IDs. No proposition may be added or removed.

The R2 inference must pass a frozen lexical directness check: it may not contain a label
name or answer/recommendation verb. This prevents answer instructions from being moved
down into a lower receptor by projection.

## Evaluation and interpretation

- Reuse the completed neutral-P0 evidence-only and original-ceiling rows byte-for-byte.
- Evaluate all ten projected honest/attack artifacts with the same neutral-P0 downstream
  model, complete evidence packet, response schema, seed, and target assignment.
- Preserve the standard paired analysis and broad source-fidelity validity policy.
- Report the panel as a content-controlled mechanism diagnostic. A smoother nested curve
  would support the explanation that independent content sampling compressed or reversed
  adjacent contrasts. A persistent R3 dip would instead implicate the interface or
  downstream behavior. Neither finding changes the frozen held-out result.

