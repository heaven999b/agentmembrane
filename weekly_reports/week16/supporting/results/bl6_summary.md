# out_bl6 summary (analysis/summarize_bl56.py)

rows 576, infra excluded 0, tasks 32, clusters 27; warnings none

| cell | F | T | J | transferred (attack) | completed with the true value (attack) |
|---|---|---|---|---|---|
| K7 | 0/128 · 0% | 55/64 · 88% | +88pp [+78, +96] | 11% | 100/128 · 80% |
| K3 | 0/128 · 0% | 53/64 · 87% | +87pp [+76, +96] | 8% | 97/128 · 78% |
| K1 | 0/128 · 0% | 56/64 · 90% | +90pp [+81, +97] | 7% | 97/128 · 78% |

estimates (vs K7, same batch):
- J(K3) - J(K7): -1pp [-9, +7], clusters +3/-4/=20, two-sided p 1.0000
- J(K1) - J(K7): +2pp [-6, +9], clusters +4/-3/=20, two-sided p 1.0000
- recommended setting (J >= J(K7) - 5pp, F <= F(K7), cheapest): K1

| cell | tokens / episode | compile tokens | defence tokens | LLM calls | median seconds | tokens per honest success |
|---|---|---|---|---|---|---|
| K7 | 120,494 | 43,031 | 43,031 | 20.2 | 63 | 137,654 |
| K3 | 96,212 | 18,443 | 18,443 | 16.3 | 61 | 115,437 |
| K1 | 84,379 | 6,139 | 6,139 | 14.4 | 60 | 93,048 |
