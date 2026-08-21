# Global ABE Experiment — Full Run Analysis

**Run**: `global_full_20260812_v1` · **Mode**: full (50 reps, 5 warm-ups,
policy rows up to `l=320`)
**Backend**: Charm-Crypto MNT224, secparam 512 · **Policies**: OR over `l`
rows, satisfaction ratio exactly 0.5 (all `l` even).
**All numbers are medians of 50 fresh repetitions**; IQR/p95 and the
deterministic bootstrap 95% CI for the median are in the summary CSVs.

This run was deemed feasible from the standard run's linear runtime
projection (**projected 63.2 min** — `logs/runtime_projection.json` in the
standard run dir — with no linearity warnings) and was then executed.  Actual
wall-clock: **≈59.7 min** (3583.5 s of experiment time, `logs/timing.json`).
All **26 validation checks passed** (`logs/validation.json`,
`passed: True`, `failed_checks: 0`).

Methods, instrumentation and correctness guarantees are documented in the
[README](../../README.md).  This file reports measured facts only.

---

## 1. Headline results (median, full run)

| Metric | FABEO22 | FXABE-Base | FXABE-Full | Full vs FABEO |
| --- | --- | --- | --- | --- |
| Setup (ms) | 8.9 | 17.4 | 15.4 | ×1.7 |
| Provisioning, \|S\|=160 (ms) | 106.1 | 146.0 | 236.1 | ×2.2 |
| Encrypt, l=160 (ms) | 214.8 | 860.5 | 980.4 | ×4.6 |
| Encrypt, l=320 (ms) | 410.8 | 1716.7 | 1972.3 | ×4.8 |
| CSP Transform, l=160 (ms) | — (none) | 539.3 | 543.8 | — |
| CSP Transform, l=320 (ms) | — (none) | 1082.7 | 1101.1 | — |
| Client decrypt, l=160 (ms) | 11.94 | 2.44 | 2.22 | **×0.19 (5.4× faster client)** |
| E2E decrypt, l=160 (ms) | 10.75 | 525.7 | 579.2 | ×54 |
| E2E decrypt, l=320 (ms) | 11.38 | 1031.7 | 1154.2 | ×101 |
| Storage, l=160 (B) | 8,941 | 29,508 | 35,890 | ×4.0 |
| Storage, l=320 (B) | 17,421 | 58,630 | 71,462 | ×4.1 |

---

## 2. Setup — Exp01

Setup is universe-independent for all three large-universe schemes, so a
scheme bar is reported instead of a fabricated universe-scaling curve.

- FABEO22 **8.9 ms**, FXABE-Base **17.4 ms**, FXABE-Full **15.4 ms**.
- Base and Full share the same FX-ABE `setup` (revocation binary tree + epoch
  bookkeeping); the 17.4 vs 15.4 gap is run-level noise (the ordering flips
  between the standard and full runs for two code paths that are identical).
  The stable finding is **FX-ABE setup ≈ ×1.7 FABEO22**.

## 3. User provisioning vs \|S\| — Exp02

- All schemes scale **linearly in \|S\|**.  At \|S\|=160: FABEO22 106.1 ms,
  Base 146.0 ms, Full 236.1 ms (at \|S\|=80: 61.3 / 91.9 / 141.0 ms).
- The FXABE gap over FABEO is the **revocation-tree path components** (one G2
  exponent per path node) plus, for Full, the **OPRF tokenization** of every
  attribute (`oprf_ms` = 201.7 ms at \|S\|=160, the anonymity layer's
  keygen cost).
- Full − Base ≈ 49 ms at \|S\|=80 and ≈90 ms at \|S\|=160.

## 4. Encryption vs policy rows — Exp03

- All schemes scale ~linearly in `l`, confirmed out to **l=320** with no
  linearity warnings.  At l=160: FABEO22 214.8 ms · Base 860.5 ms ·
  Full 980.4 ms.  At l=320: FABEO22 410.8 ms · Base 1716.7 ms ·
  Full 1972.3 ms (≈2× the l=160 values, i.e. linear doubling).
- Full ≈ **4.6–4.8× FABEO** across l=160..320.  Per-row cost is 2 group
  exponentiations (`C1∈G1 + C2∈G2`) vs FABEO's 1 G1 exponentiation; on top,
  Full adds OPRF tokenization and the FX-ABF/PStore build.
- **Anonymity-layer price** (Full − Base, exp08 l=160): ≈113 ms on 958 ms
  (~12%), of which user-attribute tokenization (`oprf_ms`) ≈106 ms and the
  FX-ABF build (`filter_build_ms + pstore_build_ms` ≈17 ms) the remainder.

## 5. CSP Transform vs policy rows — Exp04

- Only Base/Full (FABEO22 has no outsourced Transform).
- Transform cost is **pairing-dominated**: `2 + 2·satisfied` real pairings
  (verified: pair_count = 162 at l=160 and **322 at l=320** with
  satisfied=l/2).  Base 539.3 ms and Full 543.8 ms at l=160; 1082.7 and
  1101.1 ms at l=320.  The anonymous index query (FX-ABF/PStore lookup,
  `index_query_ms` ≈7.3 ms at l=160) is a **sub-ms-to-few-ms fraction** of
  the pairing cost.
- Linear in `l` (~3.4 ms/row here vs ~1.3 ms/row in the standard run — the
  per-pairing cost scales with the number of satisfied rows, which doubles
  with `l` at a fixed 0.5 satisfaction ratio).

## 6. Client-side decryption — Exp05

- FABEO22's full `Decrypt` is **~10.3–11.9 ms, flat in `l`** (dominated by
  its 3 fixed pairings).  FXABE `FinalDec` is **1.1–2.4 ms**, scaling mildly
  with satisfied rows.  At l=320: FABEO22 11.94 ms · Base 2.44 ms ·
  Full 2.22 ms — **FXABE client step ≈5.4× cheaper**.
- Caveat (in the figure): exp05 compares FABEO's *complete* decrypt against
  FXABE's *final step only* — the pairing work has moved to the CSP (Exp04).

## 7. End-to-end decryption latency — Exp06 (headline)

- FABEO22: **flat ≈10.4–11.4 ms** regardless of `l`.
- FXABE-Base: **41 → 1032 ms** across l=10..320.
- FXABE-Full: **43 → 1154 ms**.
- The FXABE e2e journey is `user OPRF + Transform + FinalDec`.  The Transform
  (real CSP pairings) dominates: at l=320 it is ~1083 ms of the ~1154 ms.
  The per-query `user_oprf` term (conservative; tokens are keygen-derived in
  the deployed code) is 47.8 ms at l=160 and grows with \|S\|.
- **Measured, not preset**: at these policy sizes the complete FX-ABE
  system's end-to-end decryption latency (including the outsourced CSP
  transform) is 4.4–101× FABEO22's single client decrypt, while the
  *client-visible* step is ~5.4× faster.  The trade-off is a genuine cost
  transfer from client to server, visible in Exp04/05.

## 8. Ciphertext-side storage vs policy rows — Exp07

- FABEO22: 991 B (l=10) → 17,421 B (l=320).  FXABE-Base: 2.2 KB → 58.6 KB.
  FXABE-Full: 2.9 KB → 71.5 KB.
- FXABE ≈ **3.0–4.1× FABEO**.  Causes: per-row `C1∈G1 + C2∈G2` (vs FABEO's
  one `G1` per row), the KEM-DEM payload, and for Full the FX-ABF + PStore
  index (+12.8 KB over Base at l=320, i.e. the anonymity layer ≈ +22%).
- Sizes are deterministic (median = p95 for the fixed part).

## 9. Breakdown — Exp08 (l=160)

| Phase | FABEO22 | FXABE-Base | FXABE-Full |
| --- | --- | --- | --- |
| encrypt total | 206.4 | 844.7 | 958.0 |
| — user OPRF | — | — | 106.0 |
| — FX-ABF build | — | — | 11.3 |
| — PStore build | — | — | 5.9 |
| — ABE rows+crypto | 206.4 | 831.3 | 820.2 |
| — other (index/overhead) | 0.0 | 11.7 | 12.4 |
| transform | — | 515.6 | 525.7 |
| finaldec | 10.4 | 1.59 | 1.61 |
| e2e decrypt | 10.4* | 517.2 | 576.0 |

\* e2e-decrypt column for FABEO22 equals its single decrypt (~10.4 ms), not
the encrypt figure — see the CSVs for exact phase timings.

---

## 10. Answers to RQ1–RQ7 (measured, no preset conclusion)

* **RQ1 — Encryption cost.** FXABE-Full is 2.9–4.8× FABEO22 across
  l=10..320, growing with `l` (per-row G1+G2 exponentiations + index build).
* **RQ2 — End-to-end decryption latency.** FXABE-Full is 4.4–101× FABEO22,
  dominated by the CSP Transform's real pairings (`2 + 2·satisfied`).
* **RQ3 — Client-side decryption cost.** FXABE `FinalDec` (1.1–2.4 ms) is
  ~5.4× cheaper than FABEO22's full `Decrypt` (~10.4–11.9 ms); the pairing
  work moves to the server.
* **RQ4 — Storage.** FXABE-Full ciphertexts are 3.0–4.1× FABEO22's
  (per-row G1+G2 + KEM-DEM + anonymous index).
* **RQ5 — Setup / provisioning.** FXABE setup ×1.7, provisioning ×1.4–2.2
  (revocation tree, path components, OPRF tokenization).
* **RQ6 — Scaling with policy size.** All costs are ~linear in `l`, verified
  to l=320; the linearity check produced **no warnings**.  FABEO22's decrypt
  is flat in `l`.
* **RQ7 — Price of the anonymity layer (Full − Base).** encrypt ≈ +12–15%,
  e2e ≈ +10–12%, storage ≈ +22%, provisioning ≈ +40–50%; setup ~equal
  (shared code path).  The FX-ABF query itself is a few ms at l=160; the
  anonymity cost concentrates in tokenization, index build and index storage.

## 11. Threats to validity (stated plainly)

* MNT224 is a research pairing group (≈3.5 ms/pairing here); absolute
  numbers shift on production curves, **ratios and scaling are the finding**.
* Exp06 `user_oprf` is a conservative per-query re-tokenization; the deployed
  path caches tokens from keygen.  Even excluding it, Full e2e at l=320 is
  ~1050 ms vs FABEO ~11.4 ms.
* Exp05's phase asymmetry is intentional and labeled in the figure.
* The OR-policy family isolates row-count scaling; attribute-*complexity*
  (e.g. threshold policies) is out of scope for this run.
* Full (50 reps) vs standard (20 reps): the full run's 95% CIs are roughly
  half the standard run's width (e.g. encrypt l=160 Full CI
  [975.7, 987.2] vs median 980.4, i.e. ±0.6%).
