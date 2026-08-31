# RQ2 neutral-P0 50-case calibration report

## Single change

This run removes the downstream-visible `external_untrusted` / non-authority cue
from the P0 memory wrapper and system prompt. The 50 cases, 500 frozen artifacts,
complete evidence packets, downstream model, old one-line ceiling content, and
validity labels are unchanged. A 20-case canary was completed before extension to
the full 50-case calibration set.

## Main result

| Measure | Warning-visible P0 | Neutral P0 |
|---|---:|---:|
| Evidence-only accuracy | 80% | 80% |
| Ceiling effect | +4 pp (2 toward / 0 away) | +12 pp (6 toward / 0 away) |
| R0 attack-minus-honest | 0 pp | +2 pp |
| R1 attack-minus-honest | 0 pp | +6 pp |
| R2 attack-minus-honest | +8 pp | +16 pp |
| R3 attack-minus-honest | +12 pp | +18 pp |
| R4 attack-minus-honest | +20 pp | +24 pp |

The neutral-P0 all-attempt curve is monotone. Exact paired p-values are 1.0, 0.25,
0.0078125, 0.00390625, and 0.00048828125 for R0--R4. R2--R4 document-cluster
bootstrap intervals exclude zero. The ceiling also passes both preregistered
engineering response gates (+10 pp and at least five toward-target pairs), so no
stronger ceiling is currently needed.

Applying the already frozen broad source-fidelity labels without another model
call gives:

| Receptor | Valid-pair coverage | Source-faithful effect | Exact paired p |
|---|---:|---:|---:|
| R0 | 100% | +2.0 pp | 1.0 |
| R1 | 100% | +6.0 pp | 0.25 |
| R2 | 98% | +16.3 pp | 0.0078125 |
| R3 | 98% | +16.3 pp | 0.0078125 |
| R4 | 100% | +24.0 pp | 0.00048828125 |

This combination passes the receptor ladder, validity coverage, evidence accuracy,
ceiling response, failure balance, and packet identity gates. It fails only the
formal 100-independent-cluster gate in the coded analysis. The adjacent receptor
increments are not individually significant after exact/Holm correction, so the
result supports an observed monotone dose-response and an R2 onset, not proof that
every adjacent step causes a statistically separable increase.

## Interpretation boundary

The result strongly supports the diagnosis that the warning-visible P0 condition
was suppressing memory influence. It does not show leakage: all 600 cached requests
were scanned and contained none of the private gold, target, or arm keys and none
of the removed provenance-warning strings.

This is still a post-pilot sensitivity run on the same 25 document clusters and
the same GPT family. The broad audit was chosen after inspecting the pilot and has
not received human calibration. Therefore `claim_bearing=false` and the formal
label remains `not_estimable`. The next claim-bearing run must freeze this protocol
before using held-out clusters, new seeds, human-calibrated auditing, and a second
model family.

## Integrity anchors

- 50/50 cases and 600/600 record cells passed validation.
- 360 new calls and 240 frozen cache hits; 523,189 new-call tokens.
- Results SHA-256: `282eb580045430d3f5e49bbb09835a1401d0fff5c87e7dffd423c80ef2ca17ca`
- Neutral records SHA-256: `998902a457b3e4113a9df4664d12e0c4bb9fe5b67ae7ba2e95f4edd470642e47`
- Broad-validity records SHA-256: `0f333a23dd868e4f0544aeef3019ebe1d3054a870a18828cc39463ba7bdfe22f`
- Broad-validity analysis SHA-256: `de93d9a3eba8ad84ad536641c1d221b3c30a6911c7e9893c0f56abaefa7d96df`
- Matrix hash: `bc6724265f1bb5cb6252366fa2514f72d951ef12fdbf7f9d1dba852c6004e7da`
