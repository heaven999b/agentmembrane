# RQ2 one-change intermediate audit report

## What changed

This 50-case post-pilot sensitivity analysis changes exactly one admission rule
from strict v1: an explicitly final answer, conclusion, or recommendation may be
unsupported without automatically invalidating the artifact. Every strict-valid
artifact is retained without re-audit. Contract facts, citations, material
qualifiers, intermediate reasoning, evidence-denial, control-content, schema, and
directness retain their strict v1 decisions.

Only otherwise-valid R3/R4 artifacts whose strict audit failed proposition-level
entailment were eligible for the focused blind audit. Thirteen artifacts were
audited and three passed: one attack R3, one honest R3, and one honest R4. This
created two additional construct-valid pairs.

## Strict, intermediate, and broad comparison

| Receptor | Strict coverage | Intermediate coverage | Broad coverage | Strict effect | Intermediate effect | Broad effect |
|---|---:|---:|---:|---:|---:|---:|
| R0 | 100% | 100% | 100% | 0.0 pp | 0.0 pp | 0.0 pp |
| R1 | 84% | 84% | 100% | 0.0 pp | 0.0 pp | 0.0 pp |
| R2 | 72% | 72% | 98% | 8.3 pp | 8.3 pp | 10.2 pp |
| R3 | 48% | 50% | 98% | 4.2 pp | 4.0 pp | 10.2 pp |
| R4 | 50% | 52% | 100% | 16.0 pp | 15.4 pp | 20.0 pp |

The intermediate result is almost identical to strict v1. It does not recover the
monotone broad-rubric curve and does not inflate the observed effect. The large
strict-to-broad difference therefore cannot be attributed mainly to whether the
final answer itself is supported. It arises later in the audit boundary, especially
how selective emphasis and qualifier non-mention are treated.

The all-attempt results remain unchanged at `0, 0, 8, 12, 20` percentage points.
The ceiling remains +4 percentage points and the dataset still contains only 25
independent document clusters. Formal status is therefore still `not_estimable`;
this analysis is post-pilot and `claim_bearing=false`.

## Integrity and reproducibility

- 50/50 cases and 600/600 record cells passed matrix validation.
- 13 focused auditor calls completed; 31,975 total tokens.
- Results SHA-256: `7ea783ee8a9d3aa19af12e0f6595207e85b7d81b2ebbf5a1640e5c72a1dce8ec`
- Records SHA-256: `93f81074da82e3519b8f7b65eecf5b10580366eeb61c628c94906936e7d87a28`
- Audit receipt SHA-256: `de873720e109dee0a28225044cf7441dbfb9e8b8f62fdf72ca5e2235d3dec176`
- Frozen matrix hash: `bc6724265f1bb5cb6252366fa2514f72d951ef12fdbf7f9d1dba852c6004e7da`

The superseded first implementation is preserved in the sibling `r1` directory
with `INVALIDATED.md`; it must not be used because it re-audited strict-valid rows
and unintentionally tightened an omission rule.
