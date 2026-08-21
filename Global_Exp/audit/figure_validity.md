# Figure validity audit (per-figure judgments)

Every judgment below is a verdict on the **figure as published/defined**, not
on the underlying measurement integrity.  All numbers were honestly measured
(real pairings, identical workload objects, no fabricated data) — the
questions are what a figure's *headline* claims and whether the OR workload
distorts it.

Verdict scale: **VALID AS-IS** / **VALID BUT NEEDS CLARIFICATION** /
**NEEDS RE-BENCHMARK** / **MISLEADING**.

| Figure | Verdict | Rationale |
|---|---|---|
| Exp01 Setup | VALID AS-IS | Direct measurement of the real setup; Base/Full share the same setup, so their 15-17 ms vs FABEO 8.9 ms reflects FXABE's larger MSK (kappa, revocation tree, system params). No workload distortion. |
| Exp02 Provisioning | VALID AS-IS | Real keygen. Full 236 ms vs Base 146 ms is the OPRF tokenization + anonymous key (FX-ABF tags). Caveat (needs one-line clarification): Full provisioning *includes* the same tokenization that Exp06 re-times per query as `user_oprf` — see timing_boundary.md. |
| Exp03 Encrypt (l-scaling) | VALID AS-IS | Real scheme, real pairings, correct monotone scaling. **Needs clarification** only on the *interpretation* of the FABEO→Base ratio: it is dominated by one G2 exponentiation per row (4.0 ms vs 0.54 ms G1 on this MNT224 backend). The "×4" is a backend-asymmetry-inflated scheme cost, not extra pairing count. |
| Exp04 Transform | VALID BUT NEEDS CLARIFICATION | Numbers are correct for what the code does, but the figure's implicit message — "outsourcing costs ~l×3.4 ms" — is workload/implementation specific: the transform pairs **every matched row** (2 pairings each; Case A), while the minimum authorized subset is 1 for the OR policy. pair_count = 2 + 2·matched is not a scheme-formula minimum. A reader would over-generalize. |
| Exp05 Client decrypt | VALID AS-IS | Phase asymmetry is intended: FABEO decodes on the client (3 pairings); FXABE outsources the pairings and leaves the client a GT-exponentiation FinalDec. Correct as measured. |
| Exp06 E2E decrypt | VALID BUT NEEDS CLARIFICATION | Real measurement, but the headline ratio (FABEO 11.4 ms vs FXABE 1032/1154 ms) stacks three distinct things: (a) the transform pairing cost amplified to 2·matched by the OR workload + Case A, (b) a **conservative per-query OPRF boundary** (0.59-0.66 ms/attr; deployed scheme pays it once per privacy epoch in keygen), (c) final_dec GT exps (small). Re-run with a minimal-subset transform or threshold policy to get the "true outsourcing" number. |
| Exp07 Storage | VALID AS-IS | Deterministic byte accounting; verified against component sums (exact reconciliation, seed-fixed). Dominated by per-row C2 ∈ G2. Caveat: the Full FX-ABF filter is *data-dependent* (4160-4500 B at l=320 across scheme keys) — a ~1.2% ciphertext-level spread, worth one footnote. |
| Exp08 Breakdown | VALID AS-IS | Parts sum to totals; segment attribution (oprf / filter / pstore / abe) is accurate. No distortion. |
| Exp09 Normalized overhead | NEEDS RE-BENCHMARK (as defined) | As defined (FXABE/FABEO ratio growing in l) it measures the **OR-workload Case-A matched-row overhead**, not an intrinsic FXABE property: the FABEO denominator is flat (prune → 1 node → 3 pairings, independent of l) while the FXABE numerator is 2·(l/2) pairings. The curve is a property of the workload + row-selection implementation. Redefine (threshold policy, or per-row pairing counts, or matched-row-normalized) before use in a paper. |

## Cross-cutting clarification that applies to several figures

All FXABE *transform/E2E* figures were run on the OR-policy workload
(`or_policy(l)`), in which **l unit rows share one target vector** and the
user satisfies **l/2** of them.  This is the single worst case for a
pair-all-matched-rows transform and the best case for FABEO's
first-match-only prune.  Two audit experiments show the sensitivity:

* l fixed = 32, m ∈ {1, 8, 16}: Base transform 13.0 / 57.9 / 108.7 ms —
  linear in m (≈3.4 ms per matched row × 2 pairings), while the minimum
  reconstruction subset is constant at 1.
* Threshold contrast (2-of-3): minimum authorized subset = 2, proving the
  "min subset = 1" result is OR-workload-specific, not a general LSSS property.

## Bottom line

* **No figure is fabricated or MISLEADING as a measurement.**
* Exp04 and Exp06 are VALID numbers that need a clarifying annotation: they
  report the *implementation's* pairing cost under a worst-case workload, not
  the scheme's structural minimum.
* Exp09, as currently defined, would mislead a reader about FXABE's intrinsic
  overhead; re-benchmark it over a threshold policy or report per-row pairing
  counts instead.
