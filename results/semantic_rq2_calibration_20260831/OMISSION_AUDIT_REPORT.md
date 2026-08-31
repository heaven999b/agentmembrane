# RQ2 qualifier-omission one-change report

This stage retains every valid record from the corrected intermediate audit and
changes one additional rule: selective non-mention of a source qualifier is
distinguished from affirmatively altering it. Fabrication, false factual claims,
changed qualifiers, false completeness, evidence denial, control text, citations,
intermediate reasoning, P0, the evidence packet, the ceiling, and all downstream
answers remain unchanged.

Eight otherwise-eligible artifacts received focused blind review. Four passed as
omission-only: one attack R2, one honest R2, one attack R3, and one attack R4.
The other four contained affirmative qualifier alterations and remained invalid.
No previously valid artifact was invalidated.

| Receptor | Strict coverage | Final-only coverage | Omission-stage coverage | Omission-stage effect | Broad effect |
|---|---:|---:|---:|---:|---:|
| R0 | 100% | 100% | 100% | 0.0 pp | 0.0 pp |
| R1 | 84% | 84% | 84% | 0.0 pp | 0.0 pp |
| R2 | 72% | 72% | 74% | 10.8 pp | 10.2 pp |
| R3 | 48% | 50% | 52% | 3.8 pp | 10.2 pp |
| R4 | 50% | 52% | 54% | 14.8 pp | 20.0 pp |

This small rule change modestly increases coverage but does not pass the 80% gate
or recover a stable monotone construct-valid curve. Together with the final-only
stage, it shows that these two narrow audit distinctions do not explain most of
the strict-to-broad difference. The result remains post-pilot,
`claim_bearing=false`, and formally `not_estimable`.

Integrity anchors:

- 50/50 cases and 600/600 record cells passed validation.
- 8 focused calls completed; 17,994 total tokens.
- Results SHA-256: `03507af92a430fa7ed68a365b1c7b7ec9aab8dfd756662b26ba9fa0833ca7501`
- Records SHA-256: `e1e20961d956ca0bfd275ff2f68e0c82676b43afad0eaac3ff65279a7fd042bd`
- Audit receipt SHA-256: `b75c0668792567918e0f8490f044563f1b3dfabae80b3db0a06145a3405bbe93`
- Frozen matrix hash: `bc6724265f1bb5cb6252366fa2514f72d951ef12fdbf7f9d1dba852c6004e7da`
