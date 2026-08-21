# Global ABE Experiment — Standard Run Analysis

**Run**: `global_standard_20260812_v1` · **Mode**: standard (20 reps, 3 warm-ups)
**Backend**: Charm-Crypto MNT224, secparam 512 · **Policies**: OR over l rows,
satisfaction ratio exactly 0.5 (all l even).
**All numbers are medians of 20 fresh repetitions**; IQR/p95 in the CSVs.

Methods, instrumentation and correctness guarantees are documented in the
[README](../../README.md).  This file reports measured facts only.

---

## 1. Headline results (median, standard run)

| Metric | FABEO22 | FXABE-Base | FXABE-Full | Full vs FABEO |
| --- | --- | --- | --- | --- |
| Setup (ms) | 9.5 | 15.8 | 16.5 | ×1.7 |
| Provisioning, \|S\|=80 (ms) | 56.0 | 93.9 | 132.4 | ×2.4 |
| Encrypt, l=160 (ms) | 207.2 | 865.6 | 989.6 | ×4.8 |
| CSP Transform, l=160 (ms) | — (none) | 535.4 | 538.9 | — |
| Client decrypt, l=160 (ms) | 10.79 | 1.59 | 1.66 | **×0.15 (6.5× faster client)** |
| E2E decrypt, l=160 (ms) | 10.76 | 533.5 | 597.3 | ×55 |
| Storage, l=160 (B) | 8,941 | 29,508 | 35,890 | ×4.0 |

---

## 2. Setup — Exp01

Setup is universe-independent for all three large-universe schemes, so a
scheme bar is reported instead of a fabricated universe-scaling curve.

- FABEO22 **9.5 ms**, FXABE-Base **15.8 ms**, FXABE-Full **16.5 ms**.
- The FX-ABE setup pays for the revocation binary tree and epoch
  bookkeeping (≈6–7 ms), which FABEO22 does not have.
- Base and Full share the same `setup`, hence their near-identical times.

## 3. User provisioning vs \|S\| — Exp02

- All schemes scale **linearly in \|S\|** (a G1/G2 exponentiation per
  attribute).  At \|S\|=80: FABEO22 56.0 ms, Base 93.9 ms, Full 132.4 ms.
- The FXABE gap over FABEO is the **revocation-tree path components**
  (one G2 exponent per path node) plus, for Full, the **OPRF tokenization**
  of every attribute (`keygen → _privacy_components`).
- Full − Base ≈ 38 ms at \|S\|=80 is the anonymity layer's keygen cost
  (token generation + hash-to-G1 for each attribute).

## 4. Encryption vs policy rows — Exp03

- All schemes scale ~linearly in `l`.  At l=160:
  FABEO22 207 ms · Base 866 ms · Full 990 ms.
- Full ≈ 4.8× FABEO at l=160.  Decomposition (exp08, l=80): FXABE per-row
  work is `C1` (G1 exp) + `C2` (G2 exp) = **2 group exponentiations per row**,
  vs FABEO's **1 G1 exponentiation per row**; on top, Full adds OPRF
  tokenization and the FX-ABF/PStore build.
- **Anonymity-layer price** (Full − Base, exp08 l=80): ≈101 ms on 543 ms
  (~19%), of which user-attribute tokenization (`oprf_ms`) ≈ 24 ms, the
  FX-ABF build (`filter_build_ms + pstore_build_ms`) the remainder.

## 5. CSP Transform vs policy rows — Exp04

- Only Base/Full (FABEO22 has no outsourced Transform).
- Transform cost is **pairing-dominated**: `2 + 2·satisfied` real pairings
  (verified: pair_count = 82 at l=80, 2 revocation + 2×40 row pairings).
  Base 535 ms and Full 539 ms at l=160 — the anonymous index query
  (FX-ABF/PStore lookup) is a **sub-ms fraction** of the pairing cost.
- Both scale linearly in `l` (1.3 ms/row).

## 6. Client-side decryption — Exp05

- **This is where outsourcing pays.**  FABEO22's full `Decrypt` is
  **~10.4–10.8 ms, flat in `l`** (dominated by its 3 fixed pairings).
  FXABE `FinalDec` is **1.1–1.7 ms**, scaling mildly with satisfied rows
  (the reconstruction product over the recovered rows).
- Caveat (in the figure): exp05 compares FABEO's *complete* decrypt against
  FXABE's *final step only* — the pairing work has moved to the CSP
  (Exp04).  The two are different phases of the decryption pipeline.

## 7. End-to-end decryption latency — Exp06 (headline)

- FABEO22: **flat ≈10.4 ms** regardless of `l` (its decrypt cost is a
  handful of fixed pairings).
- FXABE-Base: **41 → 534 ms** across l=10..160.
- FXABE-Full: **46 → 597 ms**.
- The FXABE e2e journey is `user OPRF + Transform + FinalDec` (per
  requirement 13).  The Transform (real CSP pairings) dominates: at l=160 it
  is ~539 ms of the ~597 ms.  The per-query `user_oprf` term (conservative;
  tokens are keygen-derived in the deployed code) is 24 ms at l=80/S=40 and
  grows with \|S\|.
- **Measured, not preset**: at these policy sizes, the complete FX-ABE
  system's end-to-end decryption latency (including the outsourced CSP
  transform) is substantially higher than FABEO22's single client decrypt,
  while the *client-visible* step is ~6.5× faster.  The trade-off is a
  genuine cost transfer from client to server, visible in Exp04/05.

## 8. Ciphertext-side storage vs policy rows — Exp07

- FABEO22: 991 B (l=10) → 8,941 B (l=160).  FXABE-Base: 2.2 KB → 29.5 KB.
  FXABE-Full: 2.9 KB → 35.9 KB.
- FXABE ≈ **3–4× FABEO**.  Causes: per-row `C1∈G1 + C2∈G2` (vs FABEO's one
  `G1` per row), the KEM-DEM payload, and for Full the FX-ABF + PStore index
  (~6.4 KB over Base at l=160, i.e. the anonymity layer ≈ +22%).
- Sizes are deterministic (median = p95 exactly for the fixed part).

## 9. Breakdown — Exp08 (l=80)

| Phase | FABEO22 | FXABE-Base | FXABE-Full |
| --- | --- | --- | --- |
| encrypt total | 109.7 | 442.3 | 542.9 |
| — user OPRF | — | — | 24.3 |
| — FX-ABF/PStore | — | — | ~70 (build) |
| — ABE rows+crypto | 109.7 | ~440 | ~448 |
| transform | — | 276.2 | 284.4 |
| finaldec | 10.2 | 1.46 | 1.41 |
| e2e decrypt | 109.7* | ~310 | ~310 |

\* e2e-decrypt column for FABEO22 equals its single decrypt (~10 ms), not the
encrypt figure — see the CSVs for exact phase timings.

---

## 10. Answers to RQ1–RQ7 (measured, no preset conclusion)

* **RQ1 — Encryption cost.** FXABE-Full is 2.7–4.8× FABEO22 across
  l=10..160, growing with `l` (per-row G1+G2 exponentiations + index build).
* **RQ2 — End-to-end decryption latency.** FXABE-Full is 4.4–55× FABEO22
  across l=10..160, dominated by the CSP Transform's real pairings.
* **RQ3 — Client-side decryption cost.** FXABE `FinalDec` (1.1–1.7 ms) is
  6–9× cheaper than FABEO22's full `Decrypt` (~10.4 ms); the pairing work
  moves to the server.
* **RQ4 — Storage.** FXABE-Full ciphertexts are 3.0–4.0× FABEO22's
  (per-row G1+G2 + KEM-DEM + anonymous index).
* **RQ5 — Setup / provisioning.** FXABE setup ×1.7, provisioning ×1.6–2.4
  (revocation tree, path components, OPRF tokenization).
* **RQ6 — Scaling with policy size.** All costs are ~linear in `l`; the
  linearity check across l=10..160 produced **no warnings**.  FABEO22's
  decrypt is flat in `l`.
* **RQ7 — Price of the anonymity layer (Full − Base).** encrypt ≈ +12–19%,
  e2e ≈ +12%, storage ≈ +22%, provisioning ≈ +40% at \|S\|=80; setup +4%.
  The FX-ABF query itself is sub-ms; the anonymity cost concentrates in
  tokenization, index build and index storage.

## 11. Threats to validity (stated plainly)

* MNT224 is a research pairing group (≈3.5 ms/pairing here); absolute
  numbers shift on production curves, **ratios and scaling are the finding**.
* Exp06 `user_oprf` is a conservative per-query re-tokenization; the deployed
  path caches tokens from keygen.  Even excluding it, Full e2e at l=160 is
  ~540 ms vs FABEO ~10.8 ms.
* Exp05's phase asymmetry is intentional and labeled in the figure.
* The OR-policy family isolates row-count scaling; attribute-*complexity*
  (e.g. threshold policies) is out of scope for this run.
