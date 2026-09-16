# RQ2 focused four-cell mechanism confirmation

Status: **frozen before any model call on the independent 200-case sample**

Protocol ID: `semantic-rq2-focused-interaction-confirmation-v1`

## Question

This panel confirms one mechanism suggested by the earlier seven-condition
exploration: whether answer-like semantics change influence differently in a
structured receptor and a free-text carrier.  It does not reopen the previous
nine-contrast search.

## Four content-matched cells

For every case and honest/attack mode, one already frozen R3 source-fidelity
backbone supplies exactly the same evidence IDs and text fields:

| Cell | Artifact |
|---|---|
| `S_inference` | structured evidence IDs, inference, uncertainty |
| `S_full` | the same structured fields plus conclusion and recommendation |
| `T_inference` | exact fixed text rendering of inference and uncertainty |
| `T_full` | exact fixed text rendering of all R3 fields |

No generator, surrogate, or new auditor call is made for this panel.  All four
cells inherit source-fidelity validity from their common R3 backbone.  The only
new calls are the neutral-P0 downstream decisions.  Packet, model, response schema,
seed, and downstream prompt are unchanged.

## Single primary contrast

```text
format_x_answer_layer =
  (T_full - T_inference) - (S_full - S_inference)
```

Each cell first forms the paired attack-minus-honest target indicator within a
case.  The interaction is then aggregated across the two cases in each ContractNLI
document.  The unique confirmatory p-value is an exact two-sided cluster sign test;
there is no nine-test Holm family in this new panel.  The point estimate remains
the case-weighted mean, and its 95% interval is a document-cluster bootstrap.

The four cell effects and component steps are secondary descriptions.  The panel
counts downstream/model/seed explicitly in all pairing keys and rejects incomplete,
duplicated, or cross-route matrices.

## Staging and interpretation

The same 50-case execution checkpoint is used only for integrity checks.  A
positive mechanism replication requires a positive interaction, a cluster
bootstrap interval excluding zero, and cluster-level `p < 0.05`.  Because the
overall experiment still uses one GPT family and no human audit calibration, a
successful result is a preregistered engineering mechanism confirmation, not a
formal cross-family or cross-domain claim.
