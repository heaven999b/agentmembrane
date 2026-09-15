# Week 3 Report · RT-02: Self-Audit, Reconstruction, and Confirmatory Launch

**2026-07-19**

> **Background in one line**: RT-02 has two lines — **CHIR** (after correcting the original erroneous memory, does the system actually recover?) and **PairGain** (can we predict, at each memory rewrite, that "this step will make the future more dangerous"?). Last week produced three verdicts: CHIR had a signal, PairGain did not, and CHIR's selective repair did not.
> **What this week did**: Instead of pushing forward, I first **audited last week's verdicts**. The numbers were reproducible but contaminated by **6 shared construct flaws**. I rewrote a corrected version of the experiments (v2), validated everything offline, ran a machine-validation (dev smoke), and **caught and fixed two construct bugs of my own** along the way (one structurally-broken measurement, one retrieval crowding-out confound). Finally I audited reliability against the public benchmark item by item, and **launched a 30-case independent confirmatory (running)**.
> **Thesis**: The value this week is **not "piling up new positives" but "catching a bug every time I look"**. The evidence so far is **directionally** in favor of CHIR, but the real verdict is locked in the running confirmatory.
> **How to read**: Each section starts with one line [what was done + result]. Terms in the table below.

| Term | Plain meaning |
|---|---|
| **Consolidation operator** | The background "memory tidying" action. append = only appends, never rewrites old memory; summary = actually rewrites old memory into a summary |
| **retrieval / top-k** | When answering, only the k most relevant memories are pulled up, not the whole store |
| **retrieval crowding-out** | When memory grows, the corrected record gets **pushed out of top-k**, so the agent never sees it |
| **dev / confirmatory** | dev = small development runs (no conclusions drawn); confirmatory = a one-shot, frozen test on unseen data |
| **semantic_residual** | The residual from **pure semantic contamination**, after controlling for crowding-out (= contam_d3 − safe_d3) |
| **displacement_effect** | The residual from **pure retrieval crowding-out / volume** (= benign_vol − d0) |

---

## 0. Bottom line

| Question | This week's verdict | Confidence |
|---|---|---|
| Were last week's three verdicts sound? | **Numbers sound, constructs not** — contaminated by 6 shared flaws; PairGain's "no signal" is nearly meaningless (it measured its own control) | Strong |
| The biggest flaw? | **The project never actually implemented "consolidation"** — both lines only "appended", and appending = not tidying | Strong |
| After fixing, does CHIR still have a signal? | **Yes, confirmed**: on 30 unseen cases, semantic_residual = **+0.170 [0.085, 0.270]**, surviving AND dual-judge + genuine operator (no-op 0.2%) + crowding-out control. But **much milder than v1's +0.70**, and still owes the final k-sensitivity check | Medium (confirmed but pending k-test) |
| How many papers can RT-02 yield? | **Realistically one (CHIR), not two**; PairGain's comparator can't be run, downgraded/pending | Medium |

---

## 1. Self-audit: where were last week's verdicts wrong? (6 shared root causes)

| Root cause | The flaw | Consequence |
|---|---|---|
| **R1: no genuine consolidation operator** | Both lines only `pool.append`, never rewrite old memory | PairGain measured exactly the "no-tidying" control → verdict nearly tautological |
| **R2: no retrieval** | The official static path dumps the whole store into the prompt | Contamination always visible; effect idealized/inflated |
| **R3: whole-store averaging dilutes** | The signal is averaged over the whole store | **Measured: appending 20 irrelevant records drops the signal from 0.643 to 0.031 (21×)** |
| **R4: future ≈ present** | Only 3 steps, reusing the same 3 queries | Current state nearly determines the next; ~0 predictive room; query leakage |
| **R5: degenerate comparator** | The comparator score is near-constant; selective repair has only 3 descendants per case | Comparison void / threshold unreachable |
| **R6: unaligned branches** | Whole erroneous content swapped for the correct content | Length/style mismatch (WF length ratio 0.34) contaminates the measurement |

**Conclusion**: Last week's verdicts were an "instrument" problem, not a "theory" problem.

---

## 2. Reconstruction: how v2 fixes all 6 (zero cost, offline self-validated)

| Fix | How | Self-validation |
|---|---|---|
| **R1 genuine operator** | append_only / summary / merge + fail-fast (error if it degenerates to appending) | self-test 8/8; on real API, summary "creates + rewrites" each round |
| **R2 retrieval** | TF-IDF top-k, feed only top-5, log which were retrieved | self-test 6/6 |
| **R3 lineage-local** | Measure over "source + consolidated carrier" only | self-test; 21× stronger signal than whole-store |
| **R4 query separation** | 3 queries split into "drive consolidation" vs "test the future only"; the latter never written back | validated in the runner |
| **R6 branch-match audit** | Per-record comparison, ±15% length tolerance, non-conforming cases excluded with logged reason | on real API, 6/6 clean alignment |

Also: rebuilt the list of cases used by v1 and carved out a **completely unseen** split — QA unseen 45 = dev 15 + confirmatory 30 — so the confirmatory is a truly independent test. Master offline self-test (syntax + modules + end-to-end mock + resume idempotency + stats) **all green**.

---

## 3. dev smoke + two of my own bugs caught on the spot

> **One line**: A small real run; the machinery was all correct; but running the evaluation for real **caught two construct bugs of my own in a row** — which is exactly the point of dev/smoke: **fix the instrument before spending real money on the confirmatory.**

**Machine check all passed**: on real API the genuine operator did rewrite old state, retrieval fed only top-5, branch alignment 0 failures, no crashes.

### 3.1 Bug one: structurally-broken primary measurement
Running NLI for real, I found my frozen primary measurement `source_only` gives a **constant signal on real data → the predictor G is identically 0**: it measures only the source, but the source no longer changes after correction, and all consolidation dynamics live in the **summary**, which it excluded (I over-corrected when fixing R3). **Freezing this would have produced a fake "no signal".** Fixed to `consolidated_state` (source + summary), 6/6 recovers variation. Later found that under append this is structurally zero, which turns the "operator effective / ineffective" comparison into a **circular argument**; fixed again to **`carrier_matched`** (a comparable carrier defined the same way for both operators).

### 3.2 Bug two: retrieval crowding-out confound (changed the primary endpoint)
Inspecting the real retrieval logs: **a larger d3 pool pushes the corrected record out of top-k** (contaminated arm retrieves the corrected source 1/3–2/3 of the time, control arm 3/3); the effect size tracks the **number of displaced slots**, not "whether contamination is carried by consolidation". → The naive `d3−d0` **conflates "semantic contamination" with "retrieval crowding-out".**

**(This also retracts the early dev-smoke claim that "d3−d0 residual survives = first counter-evidence" — that number was confounded.)**

**Fix**: primary endpoint changed from `d3−d0` to a **residual decomposition**:

| Quantity | Definition | dev preview (n=2, descriptive) |
|---|---|---|
| **semantic_residual** | contam_d3 − safe_d3 (**same pool size, same retrieval structure**, controls crowding-out) | **+0.44** [0.33, 0.56] |
| **displacement_effect** | benign_vol − d0 (**pure crowding-out / volume**) | +0.06 [−0.11, 0.22] (small, CI incl. 0) |
| composite d3−d0 | — | +0.48 (≈ semantic + displacement 0.50 ✓ consistent) |

**Directional read (not a verdict)**: under summary, the residual is **mostly semantic contamination, crowding-out is a rounding error** — supporting the original headline. But n=2, and summary displaces only 1 slot while append displaces 3 → **the 30-case five-arm confirmatory will resolve this.**

---

## 4. Two execution / methodology corrections (recorded honestly)

- **The real cause of "slow"**: I earlier blamed "concurrency rate-limiting", but the **main cause was laptop sleep** (closing the lid suspends the process; a single API call is only ~1.2s). Machinery throughput is fine when awake; long jobs stretch across sleep in wall-clock but **resume, so nothing is lost**. Lesson still stands: don't run many jobs concurrently, but the main culprit is sleep.
- **git-verified alignment to the standard**: item-by-item audit of the official benchmark — the official repo is the public `github.com/xiewwee11/MemEvoBench`; **the 7 QA data files are unmodified, the official judge rubric has zero changes (diff only adds sys.path), and our code has no home-made safety rubric** (all unsafe verdicts go through the official judge). **The only methodological deviation**: the primary judge uses gpt-4.1-mini rather than the official default gpt-4o (mitigated by a gpt-4o AND-gate as judge2), declared; WF-side official files are modified but unaudited (WF is the secondary line).

---

## 5. RQ restructuring: what to save, what to retire

| RQ | Decision | Notes |
|---|---|---|
| **RQ3 (CHIR)** | ✅ **Rewritten, main focus** | New framing: how much of the residual is **semantic-contamination persistence** vs **retrieval crowding-out**? |
| **RQ1 (PairGain)** | 🟡 Kept but downgraded | Circular argument fixed via carrier_matched; but the comparator (RQ2) is gone → low novelty ceiling |
| **RQ2 (beyond the verifier)** | 🟡 Salvage attempted | No longer compared against a degenerate TrustMem; added a **calibrated verifier** (forces flaw-finding + anchors low scores; mock produces variance) + a stats **`verifier_has_variance` guard** (if still degenerate, the comparison is voided, no hard verdict); GO = verifier has variance ∧ joint G beats verifier ∧ RQ1 holds. Real variance pending the PairGain confirmatory |
| **RQ4 (selective repair)** | ❌ Still retired (unsalvageable) | Only 3 descendants per case = structurally insufficient; deepening only yields near-duplicate descendants, no distinguishable influence structure. A real fix needs new data (multi-source lineage / synthetic graph); no speculative code. The overfitting finding (dev 1.0 → held-out 0.41) kept as a limitation |
| **RQ5 (scope of validity)** | ❌ Minimized | Only k / domain / NLI checkpoint axes |

**Strategic conclusion: RT-02 is realistically one paper (Paper B / CHIR), not two.** Paper A depends on the CHIR confirmatory outcome.

---

## 6. Current status: confirmatory running

> **One line**: With your authorization, a **confirmatory over 30 unseen QA cases × five arms × {genuine operator, append control} is running serially in the background**; it will give the confirmatory CI for semantic_residual, deciding Paper B's headline (or a negative verdict).

**Three possible outcomes (all reported honestly, positive or negative)**:
1. **semantic_residual significantly > 0** → "contamination persists semantically in the consolidated state; source correction is insufficient for closure" (original hypothesis holds)
2. **semantic ≈ 0, displacement dominates** → headline changes to "**consolidated products crowd out the retrieval budget, so the correction can't be retrieved**" (a more actionable mechanism)
3. **both ≈ 0** → v1's +0.70 is absorbed by the two controls → **Paper B's core collapses, honest negative verdict**

### 6.1 ✅ CHIR/RQ3 confirmatory result (summary_rewrite, 30 unseen QA cases, frozen criteria) = **GO**

| Metric | Value | Verdict |
|---|---|---|
| **semantic_residual** (primary, d3−safe, controls crowding-out + trajectory) | **+0.170, 95% CI [0.085, 0.270]** | **CI > 0 ✓** |
| **AND dual-judge** (stricter) | **+0.178, CI [0.093, 0.278]** | survives ✓ |
| displacement_effect (pure crowding-out) | +0.011, CI incl. 0 | no crowding-out confound ✓ |
| operator no-op rate | **0.2%** | genuine operator (99.8% real rewrites) ✓ |

Arm levels: contam_d3 0.311 / safe_d3 0.141 / contam_d0 0.070 / benign_vol 0.081 / full_closure 0.056.

**This is the project's first genuinely confirmatory positive**: after correcting the source, the semantic residual left by contamination in the consolidated state **is real**, and it survives a genuine consolidation operator (not appending), real top-k retrieval, crowding-out control, consolidation-trajectory control, and the AND dual-judge. **"source correction ≠ correction closure" holds under strict controls.**

**Honest bounds**: +0.17 is **much smaller than v1's +0.70** — because we stripped out three confounds (retrieval crowding-out, consolidation trajectory, volume). This is a **real but modest** effect, not the inflated original number. **One final hurdle remains**: k-sensitivity (k=3/10) — whether the effect appears only at k=5. The append operator-off control, PairGain (RQ1+RQ2), and multi-seed are still queued.

**Next**: append control (running) → k∈{3,10} sensitivity → PairGain confirmatory → backfill everything (positive/negative).

**Unresolved / resource-dependent** (commands ready): k-sensitivity / multi-seed / second model (needs API), dense retrieval (needs a download approval), citation verification (author only). Structurally unsalvageable items (RQ2 / RQ4 / NLI sentence-level blind spot / full_closure oracle ceiling) are written as paper limitations.

---

## 7. Deliverables (this week)

| Type | File |
|---|---|
| v1 per-RQ critical review | `state/rt02_v1_critical_review_20260719.md` |
| v2 construct-validity frozen design | `state/rt02_v2_construct_validity_design_20260719.md` |
| Confirmatory frozen config (primary = semantic_residual) | `state/rt02_confirmatory_config_20260719.md` |
| dev smoke report (with the two construct bugs) | `state/rt02_v2_dev_smoke_report_20260719.md` |
| git-verified benchmark alignment audit | `state/rt02_v2_benchmark_alignment_20260719.md` |
| Paper-gap checklist + limitations / action plan | `state/rt02_paper_gap_checklist_20260719.md`, `state/rt02_limitations_and_action_plan_20260719.md` |
| Full v2 code (operators / retrieval / measurement / two runners / eval pipeline / self-test) | `scripts/run/rt02/rt02_v2_*.py`, `run_rt02_v2_*.py`, `rt02_v2_selftest.sh` |
| Retired research lines | `state/RETIRED_LINES.md` |
| This report | `weekly_reports/week3/week3_report_20260719_en.md` |

**Closing line**: This week I honestly took apart last week's verdicts, found "numbers right, constructs wrong", and fixed them one by one (catching two more of my own bugs in the process); so far the dev evidence directionally supports CHIR's semantic residual, but the real verdict is left to the running 30-case confirmatory — **whatever the result, positive or negative, it will be reported honestly within this framework.**
