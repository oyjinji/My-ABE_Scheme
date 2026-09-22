# FX-ABE Global Performance Complexity Audit — Summary

Audit-only. No scheme modification, no optimization implemented, no re-run of the formal suite.
Baseline `src/experiments/global_exp/results/global_full_20260812_v1/` untouched. All evidence under `src/experiments/global_exp/audit/results/` + `profiles/`.

## The three gaps, explained without excuses

1. **Transform ≈ 1000 ms vs FABEO ≈ 11 ms** — the transform pairs **every matched row** (2 pairings each; Case A), while the OR policy's minimum authorized subset is **1**. At l=320: 322 pairings executed, 4 structurally required under the existing equations. ~97% of the transform is surplus row pairings. FABEO's prune takes 1 node and 3 fixed pairings. **Cause: implementation + OR workload (Cat. B + A).**

2. **Encrypt ×4 (411 → 1717 ms)** — one **G2 exponentiation per row** (`C2 = g2^r`, 4.0 ms vs 0.54 ms G1 on MNT224). Measured slope Base−FABEO = 4.12 ms/row ≈ one G2 exp. FABEO uses zero G2 exps per row. **Cause: inherent scheme cost, backend-inflated (Cat. C).**

3. **Storage ×3.4 (17.4 → 58.6 KB)** — the per-row **C2 ∈ G2** element (118 B/row) is 91.7% of the Base−FABEO gap. Same `C2` root as encrypt. **Cause: inherent scheme cost (Cat. C).**

## Audit verdicts (all proven by read-only measurement)

- **Audit A:** OR-policy reconstruction minimum authorized subset = **1** (brute-forced at l=8; threshold 2-of-3 contrast = 2, proving OR-specificity).
- **Case A confirmed:** transform feeds all matched rows to the pairing phase; no pruning; surplus discarded only in final_dec.
- **FABEO:** prune → 1 node → 3 fixed pairings, l-invariant.
- **pair_count = 2 + 2·matched** is implementation/workload behavior, not a scheme-formula minimum (structural min = 4 for OR).
- **OPRF:** per-privacy-epoch (Option B); tokens stored, reused; Exp06's per-query timing is a conservative boundary that re-counts provisioning.
- **C_rev:** already minimal — single ciphertext-level G1 (42 B), no redundancy found.
- **Storage CSV** reconciles **exactly** with the official `storage.py` at all 9 (scheme, l) cells (seed-fixed); Full's FX-ABF filter is data-dependent (±~8%).

## Root causes (ranked)

| Impact | Cause | Category |
|---|---|---|
| Critical | Transform pairs all matched rows; OR min subset = 1 | B + A |
| High | Per-row G2 exp `C2 = g2^r` (4.0 ms) → encrypt ×4 | C |
| High | Per-row G2 storage element (118 B) → storage ×3.4 | C |
| High | OR workload maximizes matched-vs-min gap (amplifier) | A |
| Medium | Exp06 per-query OPRF boundary (re-count of per-epoch cost) | A |
| Medium | Anonymous layer: +14% enc, +22% stor, +90 ms prov | C |
| Low | Charm ZR zero-coeff filter dead code; policy re-parse; filter size variance | B |

## What was NOT done (guardrails held)

- No equations changed; no FX-ABF/OPRF/PStore/Dual-Epoch/revocation-tree/Transform/FinalDec formulas touched.
- No workload or CSV edits; no mock/deleted pairings; no FABEO rewrite; no optimization scheme implemented.
- The minimal-subset-transform fix is described only, as an **estimate** (l=320: ~1083 ms → ~13 ms implied by 322→4 pairings at the measured 3.27 ms/pair), explicitly **not a benchmark**, and gated on next-phase implementation + correctness/security validation.

## NEXT ACTION (proposed only, nothing implemented)

Benchmark FXABE Transform/E2E over a **threshold-policy workload**, or (after separate correctness/security validation) a **minimal-reconstruction-subset transform**, to produce the scheme's true outsourcing floor; plus additive per-row ledger and matched-normalized Exp09 figures. Re-run of the existing full suite: none.

Full evidence: `AUDIT_REPORT.md` · `reconstruction_trace.csv` · `row_selection_trace.csv` · `diagnostic_m_sweep.csv` · `encrypt_operation_scaling.csv` · `operation_costs.csv` · `storage_breakdown.csv` · `encrypt_operation_ledger.csv` · `transform_operation_ledger.csv` · `timing_boundary.md` · `figure_validity.md` · `profiles/`.
