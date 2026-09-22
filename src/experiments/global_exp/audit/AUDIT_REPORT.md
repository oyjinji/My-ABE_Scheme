# FX-ABE Global Performance Complexity Audit Report

Date: 2026-08-13 · Scope: audit-only (no scheme modification, no re-benchmark of the full run, no implementation of any optimization)
Baseline: `src/experiments/global_exp/results/global_full_20260812_v1/` untouched. All new diagnostics under `src/experiments/global_exp/audit/results/`.

---

## 1. Executive Summary

The measured FXABE gaps — encrypt ×4, storage ×3.4, transform/E2E ≈ 1000 ms vs FABEO 11 ms — are all **real, honest measurements** of a correct scheme, but two of the three headline gaps are **not intrinsic to the FXABE equations**; they are the product of (a) an implementation choice and (b) the OR-policy workload interacting with that choice.

Three findings dominate:

1. **Transform pairs every matched row (Case A).** `transform()` runs the 2-pairing row transform over *all* `l/2` matched rows, while the minimum authorized reconstruction subset for the OR policy is **1**. At l=320 this is 320 row-pairings + 2 revocation pairings = 322 pairings; the structural minimum under the *existing* equations is 4. The OR workload maximizes the matched-vs-minimum gap, turning a ~13 ms outsourcing step into 1083 ms. This is the direct cause of the transform and e2e gaps (Category B implementation + Category A workload artifact).
2. **Encrypt ×4 comes from one G2 exponentiation per row** (`C2 = g2^r`, 4.0 ms/row vs 0.54 ms for a G1 exp on this MNT224 backend). This is an inherent scheme cost (Category C) that the backend's G1/G2 asymmetry inflates by 7.4×; FABEO uses zero G2 exps per row. Same root drives storage ×3.4 (per-row C2 ∈ G2 = 118 B vs FABEO's 42 B G1; 91.7% of the Base−FABEO storage gap).
3. **Exp06's per-query `user_oprf` is a conservative timing boundary**, not a scheme requirement: the OPRF token is deterministic per privacy epoch and computed once in keygen (stored in `tk_priv["items"]`); Exp06 re-times it on every query (Category A).

**Q1 is answered YES with proof:** for the current OR-policy LSSS, the minimum authorized subset is 1 (brute-force verified at l=8; every unit row alone reconstructs the target). A 2-of-3 threshold contrast confirms min=2, proving the result is OR-specific.

**No scheme equation is modified; no optimization is implemented.** Per the mandate, the potential fix (transform only the minimal reconstruction subset) is reported as an *estimate* with an explicit requirement for next-phase implementation and correctness/security validation. Nothing was "made faster" in this audit.

---

## 2. Audit Scope, Method, and Guardrails

**Guardrails honored (verbatim from the task):**
- No continuation of optimization; no modification of the crypto scheme (ABE equations, FX-ABF params, OPRF, PStore, Dual-Epoch, revocation tree, Transform/FinalDec math formulas untouched).
- No workload changes to lower benchmark time; no deleted or mock pairings; no manual CSV edits; no FABEO rewriting; no fabricated setup-vs-universe scaling.
- AUDIT FIRST / OPTIMIZE LATER: findings below are *described, classified, and estimated* only.

**Code opened and read** (real code, not stubs):
- `src/core/fabeo22cp/__init__.py` — setup / keygen / encrypt / decrypt, prune path.
- `src/core/fxabe_rev/scheme.py` — setup / keygen / encrypt / transform / final_dec / privacy_key_upt / rev / rev_key_upt.
- `src/core/fxabe_rev/lsss.py` — `policy_rows`, `pad_matrix`, `solve_reconstruction`.
- `src/core/fxabe_rev/oprf.py` — `PairingOPRF.direct_token`, `H0`, `token_bytes`.
- `src/core/fxabe_rev/revocation.py` — `BinaryRevocationTree`, `KUNodes`.
- `src/core/fxabe_rev/filters/fxabf.py`, `xor_filter.py` — index build/query.
- `src/core/msp/__init__.py` — `convert_policy_to_msp` (OR → both children carry the same vector → l unit rows).
- `src/experiments/global_exp/src/{adapters,workloads,timing,storage,experiments}.py` — measurement harness.
- Charm 0.63 `charm/toolbox/policytree.py` — `requiredAttributes` (OR branch returns only the first matched leaf).

**Dynamic diagnostics executed** (all read-only; outputs under `src/experiments/global_exp/audit/results/`):
- `reconstruction_trace.csv` — l=8…64, brute-force min authorized subset, solve_reconstruction over matched rows, dynamic pair_count.
- `row_selection_trace.csv` — FABEO vs FXABE row selection at identical workloads (l=8, l=32).
- `diagnostic_m_sweep.csv` — fixed l=32, m ∈ {1, 8, 16}.
- `encrypt_operation_scaling.csv` — l=16…128, 5 reps, 3 warmups.
- `operation_costs.csv` — per-op micro-benchmarks on this backend.
- `storage_breakdown.csv` — component bytes, reconciled exactly with `storage.py`.
- `encrypt_operation_ledger.csv`, `transform_operation_ledger.csv` — static op counts from code + measured per-op costs.
- `profiles/` — cProfile attribution (encrypt ×3 schemes, transform ×2).

**Test verification:** baseline `pytest src/experiments/global_exp/tests` → **19 passed**. Audit tests `pytest src/experiments/global_exp/audit/tests` → **6 passed** (OR min subset = 1; reconstruction over matched uses 1 row; pair_count = 2 + 2·matched; FABEO prune = 1 node; Charm ZR zero-filter ineffectiveness; transformed_rows length = matched).

---

## 3. Measured Performance Landscape (baseline recap)

Full-run medians (l=320 unless noted; user-supplied, `src/experiments/global_exp/results/global_full_20260812_v1/`):

| Metric | FABEO22 | FXABE-Base | FXABE-Full |
|---|---|---|---|
| Setup (ms) | 8.9 | 17.4 | 15.4 |
| Provisioning \|S\|=160 (ms) | 106 | 146 | 236 |
| Encrypt (ms) | 411 | 1717 | 1972 |
| Transform (ms) | — | 1083 | 1101 |
| Client decrypt (ms) | 11.94 | 2.44 | 2.22 |
| E2E decrypt (ms) | 11.4 | 1032 | 1154 |
| Storage (B) | 17421 | 58630* | 71462* |

\* Audit re-derived the current deterministic values at a fixed seed: **58622 / 71454** (see §10; the +8 B in the quoted run is a metadata-dict content drift, and the Full FX-ABF filter is data-dependent).

Measured per-operation costs on this backend (MNT224, secparam 512):

| Op | ms/op |
|---|---|
| pair(g1, g2) | 3.2721 |
| g2 ** z | 3.9997 |
| g1 ** z | 0.5407 |
| gt ** z | 0.8889 |
| hash → G2 | 12.5932 |
| hash → G1 | 0.0345 |
| hash → ZR | 0.0007 |

Note the asymmetry that will recur: **G2 exp is 7.40× G1 exp**, and hash→G2 is 365× hash→G1.

---

## 4. Audit A — OR-Policy Reconstruction: minimum authorized subset

**Question (verbatim):** "对于当前实际生成的 OR-policy LSSS，解密 reconstruction 是否真的需要所有 satisfied rows？"

**Answer: NO — the minimum authorized subset is exactly 1.**

For the OR-policy LSSS produced by `src/core/msp/convert_policy_to_msp`, every policy row is the unit vector `e1` (both children of an OR node inherit the parent's row). The target of the scheme is `[1]` (first component = 1). Therefore **any single row alone** spans the target:

```
solve_reconstruction(group, matrix, [row_i])  →  {i: 1}
```

Brute-force verified at l=8: all 8 singleton subsets return a valid reconstruction with coefficient 1 (`reconstruction_trace.csv`, `test_or_policy_minimum_authorized_subset_is_one`).

**Contrast experiment (proves specificity):** for a 2-of-3 threshold LSSS, the same brute force returns minimum authorized subset = **2**. So "min subset = 1" is a property of this OR workload, not of FXABE in general. On a threshold policy the minimum would grow; the matched-vs-min gap would shrink.

**The l=8 trace (per spec):**

| policy_rows | matched | rec. rows used | min subset | actual pair_count |
|---|---|---|---|---|
| 8 | 4 | 1 | 1 | 10 |

`reconstruction_rows = 1`: `solve_reconstruction` over the matched set returns exactly one nonzero coefficient (the first matched row), and `final_dec` raises only that row.

---

## 5. FXABE Transform Row Selection — Case A vs Case B

**Question:** does the transform (a) feed *all* matched rows straight into the pairing phase (Case A), or (b) first reduce to an authorized/pruned subset (Case B)?

**Answer: CONFIRMED Case A.**

Reading `src/core/fxabe_rev/scheme.py::transform`:
1. The index query (or direct lookup in Base) returns **every** matched row.
2. The transform loops over **all** returned rows and computes, for each, the 2-pairing row transform `t1_i = pair(C1_i, K1)`, `t2_i = pair(K2_i, C2_i)`.
3. There is **no** pruning, no authorized-subset reduction, no reconstruction before the pairing phase.
4. The surplus rows are only discarded later, in `final_dec`, where `solve_reconstruction` yields coefficient 0 for them and the GT combination short-circuits (~0 ms each).

Evidence:
- `pair_count = 2 + 2·matched` exactly at l = 8, 16, 32, 64 (§7).
- `transformed_rows` dict length = matched (§14, audit test).
- The m-sweep (§8) shows transform time strictly linear in m with a fixed policy: 13.0 / 57.9 / 108.7 ms for m = 1 / 8 / 16 at l=32.

Security note: computing the row transform over the *full* matched set reveals nothing the CSP does not already hold (the CSP has the full matrix `A_star` in the ciphertext and the matched row set). Reducing to the minimal subset is therefore not a security regression *per se*, but a formal re-validation is required before any change (see §17).

---

## 6. FABEO Row Selection — Side-by-Side Trace (the key table)

Same workloads (l=8 and l=32, OR policy, satisfaction 0.5); FABEO uses its prune, FXABE uses its transform:

| Scheme | l | matched | rows actually paired | min authorized subset | actual pairings | row pairings |
|---|---|---|---|---|---|---|
| FABEO22 | 8 | 4 | **1** | 1 | **3** | 1 |
| FXABE-Base | 8 | 4 | 4 | 1 | 10 | 8 |
| FXABE-Full | 8 | 4 | 4 | 1 | 10 | 8 |
| FABEO22 | 32 | 16 | **1** | 1 | **3** | 1 |
| FXABE-Base | 32 | 16 | 16 | 1 | 34 | 32 |
| FXABE-Full | 32 | 16 | 16 | 1 | 34 | 32 |

**Why FABEO pairs 1 row:** FABEO's decrypt calls `policytree.requiredAttributes`, whose OR branch returns only the *first* matching leaf ("never return both attributes", Charm 0.63), and the decrypt loop runs 3 **fixed** pairings independent of l.

**Why FXABE pairs m rows:** the transform pairs every matched row (Case A, §5). At l=320 with m=160 this is 2 + 320 = **322 pairings** — exactly the value reported in the original run (`pair_count = 2 + 2·satisfied`).

At identical workload the two schemes therefore process 1 vs m rows and 3 vs 2+2m pairings. **This single contrast table is the crux of the transform/E2E gap.**

---

## 7. Dynamic pair_count Verification (l = 8, 16, 32, 64)

| policy_rows | matched (l/2) | reconstruction rows used | min subset | actual pair_count | transform ms (Base) |
|---|---|---|---|---|---|
| 8 | 4 | 1 | 1 | 10 | 32.7 |
| 16 | 8 | 1 | 1 | 18 | 62.0 |
| 32 | 16 | 1 | 1 | 34 | 114.5 |
| 64 | 32 | 1 | 1 | 66 | 213.8 |

`pair_count` follows `2 + 2·matched`, **not** `2 + 2·(reconstruction rows)` and not `2 + 2·(min subset)`. This is the decisive, quantified statement: the pairing count is tied to the matched set (Case A implementation), while the scheme's actual reconstruction consumes a single row. Transform ms tracks pair_count linearly (≈3.3 ms/pairing, matching the measured 3.27 ms/pair).

---

## 8. Diagnostic Workload — Fixed Policy, Varying Matched (m)

Fixed l=32 OR policy; the user's attribute set is varied so that exactly m ∈ {1, 8, 16} rows match:

| Scheme | l | m | actual pair_count | transform ms |
|---|---|---|---|---|
| Base | 32 | 1 | 4 | 13.0 |
| Base | 32 | 8 | 18 | 57.9 |
| Base | 32 | 16 | 34 | 108.7 |
| Full | 32 | 1 | 4 | 14.7 |
| Full | 32 | 8 | 18 | 59.7 |
| Full | 32 | 16 | 34 | 111.8 |

- Transform time is **linear in m** (Δ ≈ 6.4 ms per additional matched row ≈ 2 × 3.2 ms pairings), confirming pairings are the dominant driver.
- **m=1 is already correct** (4 pairings = 2 revocation + 2 row) — i.e., the scheme *already works* with a 1-row transform; the extra m−1 rows are pure surplus.
- Full − Base is a small constant (index query ≈ 1–3 ms), independent of m.

---

## 9. Encryption Gap — Operation Ledger and Scaling

**Why is Base ≈ 4× FABEO, and Full ≈ 4.8×?**

Per-row operation model (counts read from the code, costs from `operation_costs.csv`):

| Operation (per policy row) | FABEO22 | FXABE-Base | FXABE-Full |
|---|---|---|---|
| G1 exp | 2 | 2 | 3 |
| **G2 exp** | **0** | **1** | **1** |
| hash → G1 | 1 | 1 | 2 |
| (extra) token serialize / index build | — | — | per-row + fixed |

Per-row cost (ms, measured ops):
- FABEO22: `2·0.5407 + 0.0345 ≈ 1.12` (measured 1.34–1.90 — includes fixed overhead amortized down as l grows)
- Base: `2·0.5407 + 3.9997 + 0.0345 ≈ 5.12` (measured 5.45–5.57)
- Full: adds 1 G1 exp + 1 hash + serialize/index ≈ measured 6.2–6.7

Measured scaling (5 reps):

| Scheme | l=16 | l=32 | l=64 | l=128 | ms/row (asymptotic) |
|---|---|---|---|---|---|
| FABEO22 | 30.5 | 49.5 | 89.7 | 171.4 | 1.34 |
| Base | 89.1 | 174.5 | 350.4 | 698.7 | 5.46 |
| Full | 105.3 | 215.3 | 407.6 | 795.7 | 6.22 |

**The single dominant term is one G2 exponentiation per row (C2 = g2^r).** Base−FABEO slope = 5.46 − 1.34 = **4.12 ms/row ≈ one G2 exp (4.0 ms)**. FABEO performs *zero* G2 exponentiations per row. The ×4 is therefore not extra pairings and not a row-selection artifact — it is an inherent scheme cost (Category C) inflated by the backend's G1/G2 asymmetry (G2 exp 7.4× G1). On a balanced pairing curve the encrypt ratio would drop toward ~2× (2 G1 vs 2 G1 + 1 G2 ≈ 1.5–2×).

Full − Base = +255 ms at l=320 (+14%): OPRF tokenization, one extra G1 exp and hash→G1 per row, and the index build. Modest; see §11.

**Ledger files:** `encrypt_operation_ledger.csv` (per-op counts × scope × estimated ms), `encrypt_operation_scaling.csv`.

---

## 10. Storage Gap — Component Breakdown and Reconciliation

Reconciled **exactly** against the shipped `storage.py` (seed-fixed, deterministic; verified component-sum = official total for all 9 (scheme, l) cells):

| Scheme | l=32 | l=160 | l=320 |
|---|---|---|---|
| FABEO22 | 2,157 | 8,941 | 17,421 |
| FXABE-Base | 6,204 | 29,500 | 58,622 |
| FXABE-Full | 7,800 | 36,035 | 71,454 |

**l=320 gap attribution:**

Base − FABEO = 41,201 B:
- **Per-row C2 ∈ G2: 320 × 118 = 37,760 B → 91.7% of the gap.**
- Fixed + metadata delta (C+C_rev+C_sym+nonce+A_star+meta+rho vs FABEO's G2 pair + GT + policy string): +3,441 B.

Full − Base = 12,832 B:
- Anonymous index: FX-ABF filter 4,160 + PStore 11,520 + index metadata 191 = **+15,871 B**.
- Minus Base's shipped plaintext `direct_rho` (3,205 B) and meta drift (+166 B) → net 12,832 B.

**Determinism note (honest, non-excuse):** the FX-ABF filter is an XOR filter whose serialized size depends on the hash values of the posting keys, which depend on the scheme's secret `kappa`. Measured at l=320: **4,160 B (seeds 1, 9) vs 4,500 B (seed 90322)** — a ~8% spread in the filter component, ~1.2% of the ciphertext. Storage is not a fixed constant for Full; it varies run-to-run by scheme key. The official run also differs from the current code by +8 B (metadata dict content drift, shared by Base and Full).

**Bottom line:** storage ×3.4 is (91.7%) the per-row G2 element — the same `C2 ∈ G2` that drives encrypt ×4 — and (Full layer) the anonymous index replacing `direct_rho`.

---

## 11. C_rev / Revocation / Outsourcing Component Audit

- **C_rev = C^h_r** is a single ciphertext-level G1 element (42 B), not per-row, not per-policy-attribute. It depends only on `s` (via C) and the revocation epoch `h_r`. **It is already minimal** — there is no per-row or per-node component to consolidate, and no redundant share exists. It contributes 42 B of 58,622 B (0.07%).
- **Key-side revocation components** (path components, KU cover via `KUNodes`) are key-side, sized by the revocation tree, and were not found to have a ciphertext-side counterpart that could be de-duplicated.
- **Outsourcing (transform) math:** `t0 = pair(C, path·U0) / pair(C_rev, U1)` is 2 fixed pairings per transform, plus 2 pairings per matched row. The 2 fixed pairings are the scheme's cost of epoch/revocation binding and are not workload-dependent (and not reducible within the current equations).
- **Revocation tree (setup/provisioning):** accounts for the Base setup gap (17.4 vs 8.9 ms, §3) — one-time, amortized; not a per-query cost.

**No shareable redundancy found in C_rev.** The only ciphertext-side "redundancy" is the per-row C2 element itself, which is not redundant — it is required by the scheme's row equations; what is redundant is *processing* all matched rows (not storing them) at transform time (§5).

---

## 12. OPRF Lifecycle and Timing Boundary

**Verdict: Option B — per-privacy-epoch** (see `timing_boundary.md` for the code walkthrough).

- Keygen / `privacy_key_upt` call `_privacy_components`, which computes `token = H1(chi)^kappa`, `q_x = H0(token)`, `K_x = q_x^(z·eta)` **once** and stores `token_bytes` in `tk_priv["items"]`.
- `transform()` reads `item["token_bytes"]`; it **never recomputes the OPRF**.
- `direct_token` is deterministic per `(attribute, privacy_epoch, version)`, so per-query recomputation would yield the identical token — **no unlinkability gain** from recomputing.

**Consequence for Exp06:** `adapter.user_oprf()` re-times `direct_token` over the user set on **every** query (≈0.59–0.66 ms/attr). This is a conservative timing boundary (a device that does not cache its epoch tokens), and it **re-counts a cost already inside provisioning** (Exp02 `oprf_ms` = `privacy_components_ns`). In the deployed lifecycle the tokenization is paid once per epoch and amortized over every query in that epoch.

Reported magnitude in the full run: ~23.7 ms at l=80, ~46.8 ms at l=160 — a small term of e2e; the transform dominates (§13).

---

## 13. Transform Operation Ledger and Profiling

**Static ledger** (`transform_operation_ledger.csv`):

| Operation | Fixed | Per matched row | Base l=320 (m=160) |
|---|---|---|---|
| pairing: revocation t0 | 2 | — | 2 |
| pairing: row (t1_i, t2_i) | — | 2 | 320 |
| hash→ZR epoch scalar | 1 | — | 1 |
| C_rev integrity check (C^h_r) | 1 G1 exp | — | 1 |
| index query (Full) | — | per token | 160 |
| reconstruction solve (final_dec) | 1 | — | 1 |
| GT exp per nonzero coeff | 1 (OR) | — | 1 |
| KDF + AEAD (final_dec) | 1 | — | 1 |

**Profiling** (cProfile, l=160, attribution only — never a benchmark):

- `transform_FXABE-Base.txt` / `transform_FXABE-Full.txt`: **>99% of cumulative time is `pair()`** (162 calls at l=160 = 0.532 s). The Full index query is ~0.025 s cumulative (≈0.3 ms/token, dominated by the PStore decode + filter probe — no pairings).
- `encrypt_FABEO22.txt` vs `encrypt_FXABE-Base.txt` / `Full.txt`: encrypt time split between `g2 ** z` (the per-row C2) and `g1 ** z`; G2 exponentiation is the top single function for FXABE, absent from FABEO.

**Where the 1083 ms goes:** 320 row pairings × 3.27 ms ≈ 1,046 ms + 2 revocation pairings ≈ 6.5 ms + fixed overhead. **~97% of the transform is the surplus matched-row pairings.**

---

## 14. Definitions in Code: matched / authorized / reconstruction, and the reconstruction coefficients (omega)

- **Matched rows** = `workload.satisfied_rows` = the count of policy attributes present in the user's attribute set (OR policy ⇒ equals the number of unit rows the user can activate). This is what the CSV labels `satisfied_rows`.
- **Authorized subset** = a subset of rows spanning the target vector. Minimum = 1 for OR (§4).
- **Reconstruction** = `solve_reconstruction` (Gaussian elimination over the rows the transform produced) returns `coeffs[row_id]`; `final_dec` computes `K1 = ∏ K1_i^c_i`, `K2 = ∏ K2_i^c_i` over **nonzero** coefficients and inverts `t0 · K1 / K2` to `E = e(g,g)^(s·z)`.

**Code conflation (finding):** the harness records `satisfied_rows` as the de-facto "matched" count and the transform records `len(transformed_rows)` = matched, but **no metric records the reconstruction-row count** (always 1 here). The pairing count (2 + 2·matched) is therefore driven by the matched set, while the *used* count is 1. The reader of the original tables cannot distinguish "rows paired" from "rows needed" — that conflation is exactly what this audit resolves.

**omega (coefficient) implementation — Charm quirk:** `solve_reconstruction` filters with `if coeff != 0`, but in Charm 0.63 `group.init(ZR, 0) != 0` is **True**, so zero coefficients are **not** dropped (verified: `{1:1, 2:0, 3:0, 4:0}`). Harmless in practice: `ZR(0)`-exponentiation short-circuits (~0 ms), so final_dec effectively uses the single nonzero row; but it means the "filter" is dead code and the reconstructed set is the *whole* matched set at the coefficient level. Audit test `test_solve_reconstruction_returned_zeros_not_filtered_in_charm` pins this.

---

## 15. Implementation Inefficiency Scan

Findings from a line-level pass over the hot paths (no changes made):

1. **Transform pairs all matched rows, then throws away all but one** (§5) — the single largest inefficiency. Surplus cost at l=320 ≈ 1,040 ms.
2. **Policy re-parsed to MSP on every encrypt** — `src/experiments/global_exp/src/adapters.py` re-converts the policy string each call (fixed cost; profiled as non-negligible at small l). Could be cached; Category B, low impact.
3. **Charm `coeff != 0` filter ineffective** (§14) — dead code; harmless but misleading. Category B.
4. **FX-ABF filter size is data-dependent** (§10) — measurement variance only, ±1.2% ciphertext level. Category B/measurement.
5. **FABEO's `requiredAttributes` returns a single leaf for OR** — this is FABEO's own implementation asymmetry (§6); it is what makes FABEO's decrypt l-invariant. Not an FXABE inefficiency, but the direct counterpart that makes the ratio look so extreme.

No memory-management, grouping, or serialization hot spots beyond the above were found in the pairing loops; the loops are already vectorization-hostile (group ops are C-backed).

---

## 16. Four-Category Classification and Gap Attribution

**A — Benchmark / workload artifact**
- OR-policy workload maximizes the matched-vs-minimum-subset gap (l/2 vs 1) — inflates transform/E2E.
- Exp06 per-query `user_oprf` boundary (§12) — conservative re-count of a per-epoch cost.
- Exp09's raw FXABE/FABEO ratio is an OR-workload measurement, not an intrinsic overhead (§ figure_validity.md).

**B — Implementation inefficiency**
- Transform pairs all matched rows with no subset reduction (Case A) — **the dominant non-scheme cost.**
- Policy re-parse per encrypt.
- Dead zero-coefficient filter (Charm quirk).
- FX-ABF size data-dependence (measurement-level).

**C — Inherent scheme cost**
- Per-row G2 exponentiation `C2 = g2^r` → encrypt ×4 (backend-inflated).
- Per-row G2 storage element → storage ×3.4.
- Anonymous layer (OPRF tokenization + FX-ABF + PStore + index metadata) → Full's +14% encrypt / +22% storage / +90 ms provisioning.
- 2 fixed revocation pairings + minimum 2 row pairings per transform (scheme's floor = 4 pairings for OR).
- Revocation tree setup/provisioning overhead.

**D — Potential scheme-level optimization (NOT to be implemented here)**
- None proposed that alter equations. The only "levers" identified are backend-level (a pairing-friendly curve with balanced G1/G2 would shrink the encrypt/storage ×G2 inflation) and implementation-level (minimal-subset transform). Both are outside this audit's mandate and would require their own correctness/security validation.

**Gap attribution (l=320):**

| Gap | FABEO → Base | Base → Full |
|---|---|---|
| Setup | +8.5 ms (tree) | ≈0 (shared setup) |
| Provisioning | +40 ms | +90 ms (OPRF+index keys) |
| Encrypt | +1,306 ms (per-row G2 exp) | +255 ms (OPRF+index, +14%) |
| Transform | — (FABEO has none) | +18 ms (index query) |
| Client decrypt | −9.5 ms (outsourcing) | ≈0 |
| E2E | — | +122 ms (query + OPRF boundary) |
| Storage | +41,201 B (91.7% = C2) | +12,832 B (index − direct_rho) |

---

## 17. Q1–Q10 Answers, Root-Cause Ranking, Figure Validity, Expected Impact, Recommended NEXT ACTION

### Q1. Is the OR-policy reconstruction minimum really 1? — **YES (proven).**
Every unit row alone spans target `[1]` (brute-forced at l=8). Threshold 2-of-3 contrast returns min=2 → OR-specific.

### Q2. Does FXABE transform use all matched rows (Case A) or a pruned subset (Case B)? — **Case A (confirmed).**
All matched rows enter the 2-pairing row transform; surplus discarded only in final_dec. m-sweep proves time ∝ m.

### Q3. Does FABEO also pair all matched rows? — **NO.**
Prune returns exactly 1 node; 3 fixed pairings regardless of l.

### Q4. Is `pair_count = 2 + 2·satisfied` a scheme minimum? — **NO.**
It is the Case-A implementation over the matched set. Structural minimum under the existing equations is 2 + 2·(reconstruction rows) = **4** for OR. The workload maximizes the gap.

### Q5. Why is Base encrypt ≈ 4× FABEO? — **One G2 exponentiation per row (C2 = g2^r).**
G2 exp = 4.0 ms vs G1 0.54 ms on MNT224. Measured slope Base−FABEO = 4.12 ms/row ≈ one G2 exp. Category C, backend-inflated.

### Q6. Why is Base storage ≈ 3.4× FABEO? — **Per-row C2 ∈ G2 (118 B).**
37,760 B of the 41,201 B gap (91.7%); plus matrix/rho metadata.

### Q7. Is the anonymity layer the dominant cost? — **NO.**
Full−Base is +14% encrypt, +22% storage, +18 ms transform, +90 ms provisioning. The dominant gaps are Base-vs-FABEO (G2 per row) and Case-A transform.

### Q8. Is the OPRF per query or per epoch? — **Per privacy epoch (B).**
Tokens deterministic per epoch, stored, reused by transform. Exp06's per-query timing is a conservative boundary (≈0.59–0.66 ms/attr), re-counted from provisioning.

### Q9. Which figures need re-running? — **None need re-running to be correct as measurements.** Exp04/Exp06 need a clarifying annotation (they report the Case-A OR-workload cost, not a scheme minimum). Exp09 as defined **needs redefinition** (the l-growing ratio is a workload/implementation measurement). A *new* experiment (minimal-subset transform or threshold policy) is the one that answers "true outsourcing cost."

### Q10. Three improvements that would make the gap attributable. — (i) a per-row operation ledger figure (G1/G2 exp + pairings per row) so encrypt/storage gaps are visually traceable; (ii) a minimal-subset or threshold-policy transform benchmark for the true outsourcing number; (iii) normalize Exp09 by matched rows or per-row pairings instead of the raw scheme ratio; plus (iv) report per-epoch and per-query OPRF boundaries separately in Exp06.

### Root-cause ranking (Impact / Confidence)

| # | Root cause | Cat. | Impact | Confidence |
|---|---|---|---|---|
| 1 | Transform pairs all matched rows (Case A); OR min subset = 1 | B + A | **Critical** — drives transform 1083 ms and e2e ×55–101 | **High** (m-sweep + trace + profile) |
| 2 | Per-row G2 exp `C2 = g2^r` (4.0 ms) on asymmetric MNT224 | C | **High** — encrypt ×4 | **High** (slope = G2 exp) |
| 3 | Per-row G2 storage element (118 B/row) | C | **High** — storage ×3.4 | **High** (exact byte reconciliation) |
| 4 | OR workload maximizes matched-vs-min subset gap | A | **High** — amplifier of #1 | **High** (2-of-3 contrast) |
| 5 | Exp06 per-query OPRF boundary (re-count of per-epoch cost) | A | **Medium** — inflates e2e by ~24–48 ms and conceptually double-counts | **High** |
| 6 | Base→Full anonymous layer (OPRF + FX-ABF + PStore) | C | **Medium** — +14% enc, +22% stor, +90 ms prov | **High** |
| 7 | Charm ZR zero-coeff filter dead code | B | **Low** — harmless (short-circuit), misleading | **High** |
| 8 | Policy re-parse per encrypt | B | **Low** | **High** |
| 9 | FX-ABF filter size data-dependence | B/meas | **Low** — ±1.2% ciphertext | **High** |

### Expected impact analysis (estimate only — NOT a benchmark, NOT implemented)

The OR-reconstruction finding implies the following, using **measured per-pair cost (3.2721 ms) and measured per-row costs**:

- Current (l=320): 322 pairings → 1083 ms measured (≈3.36 ms/pair observed; ~97% row pairings).
- Minimum structurally-required pairings under the existing equations: 2 (revocation t0) + 2×1 (single reconstruction row) = **4**.
- Estimated transform: 4 × 3.27 ≈ **13 ms + fixed overhead**, i.e. a reduction of roughly **two orders of magnitude** (1083 → ~13 ms at l=320; ~530 → ~13 ms at l=160).
- Since e2e is transform-dominated, the e2e figure would follow (≈1154 ms → tens of ms plus the OPRF boundary term).

This estimate **does not** come from a benchmark and **must not** be quoted as a result. A formal number requires the next phase: implement a minimal-reconstruction-subset transform (selecting only rows with nonzero reconstruction coefficients), and re-validate **correctness** (authorized users still decrypt; final_dec output unchanged) and **security** (the transform's row set does not weaken the outsourcing guarantees) before re-running the formal benchmark.

### Figure validity
See `figure_validity.md`. Summary: Exp01/02/05/07/08 = VALID AS-IS; Exp03 = VALID AS-IS (needs interpretation note on G2 asymmetry); Exp04/06 = VALID BUT NEEDS CLARIFICATION (Case-A OR-workload cost, conservative OPRF boundary); Exp09 = NEEDS RE-BENCHMARK as defined. No figure is fabricated or mislabeled as a measurement.

### No-excuses statement
Per the mandate ("禁止在审计报告里'帮方案找借口'"): the transform is slow **because the code pairs every matched row even though one row suffices** for this workload; encrypt is ×4 **because every row requires a G2 exponentiation on an asymmetric curve**. Neither is attributed to measurement noise, and both are reported at their real, measured magnitude. The scheme-level parts that genuinely cannot be removed without changing equations (the per-row G2 element, the 2-pairing revocation floor, the anonymous index) are separated explicitly from the implementation/workload parts that can.

### Limitations / missing evidence
- Formal re-benchmark of a minimal-subset transform: **not performed** (requires next-phase implementation; the estimate above is explicitly non-authoritative).
- Exact byte reconciliation done at a fixed seed; the previously-quoted storage run differs by +8 B (metadata drift) and the Full filter varies ±8% with the scheme key.
- Profiling numbers are attribution-only (cProfile overhead), not wall-clock benchmarks.
- The 2-of-3 threshold contrast used a hand-built matrix; no full threshold workload was benchmarked.

### Recommended NEXT ACTION (the only action proposed — nothing implemented)
1. **Next experiment (design-only, still no code change):** a formal benchmark of FXABE Transform/E2E on a **threshold-policy workload** (e.g. k-of-n), or — after separate correctness/security validation — a **minimal-reconstruction-subset transform**, to replace the current Case-A OR-workload numbers with the scheme's actual outsourcing floor.
2. **Additive figures only:** a per-row operation ledger figure and an Exp09 variant normalized by matched rows.
3. **No scheme change, no optimization, no re-run of the existing full suite.**
