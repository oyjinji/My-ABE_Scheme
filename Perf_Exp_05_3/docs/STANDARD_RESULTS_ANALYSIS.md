# FX-ABE 05.3 Standard Results Analysis

This report is generated from retained raw samples; medians are never fastest-only values.

## Audit status

- Same curve/backend: **PASS** (`MNT224`, `Charm-Crypto/PBC`).
- Correctness/result validation: **PASS**.
- Raw rows: 6966; failed rows: 0.
- Unresolved anomalies: none.

## Required questions

1. **Occurrence reuse Encrypt slope.** At the largest common ell (640), NoOccurrence/Core is **4.352×** FXABE-05.3/Core. This is the measured benefit under MNT224.
2. **G2 component.** Operation rows validate `D_j=c_max` for 05.3 and `D_i=ell` for NoOccurrence; validation would fail otherwise.
3. **Ciphertext storage.** EXP-02 uses `group.serialize` plus canonical framed metadata. The G2 term changes from `ell` elements to `c_max`; no object-size API is used.
4. **Transform pair count.** EXP-03 observed `[(5, 4), (10, 4), (20, 4), (40, 4), (80, 4), (160, 4), (320, 4)]`; EXP-04 observed `[(1, 4), (2, 5), (4, 7), (8, 11)]`, exactly `3+t_I`.
5. **Cost as J grows.** Pairing count is fixed in EXP-03; changes are attributable to FX Query, posting decode, AuthorizedSubset and Python aggregation, shown separately.
6. **t_I.** EXP-04 fixes `ell=J=k=c_max=8`; only occurrence grouping changes. Each extra slot adds exactly one pairing.
7. **c_max padding.** EXP-05 reports Encrypt, total canonical storage and Transform separately. Encrypt/storage grow with padded D count; Transform stays tied to `t_I=1`.
8. **Real FX cost.** EXP-06/07 execute three-position retrieval, peeling/reverse assignment, short check, metadata-bound AES-GCM and canonical posting decode. Retry and load factor remain in raw notes.
9. **Anonymity overhead.** `(ell, absolute ms, percent of EXP-09 Core)` = `[(40, 81.8650045, 91.42008353002265), (160, 334.303712, 134.53993319005426), (640, 1327.851859, 148.3765747901582)]`. At ell=640 the denominator is the EXP-09 workload's own 894.920146 ms Core median, not EXP-01's 813.181325 ms. The timing boundary is the same, but the experiment lifecycle/workload metadata is not sample-identical; see `EXP01_EXP09_ACCOUNTING_AUDIT.md`. This is decomposition, not an invented non-anonymous security baseline.
10. **Revocation.** EXP-10 separately records KUNodes/real KU crypto, cover size, KU bytes, Transform, real Dual/Coupled epoch execution and PrivacyKeyUpt.
11. **FXABE Core vs FABEO.** At ell=640, FXABE-05.3 Core/FABEO Encrypt is **0.975×**, and their bootstrap median confidence intervals overlap. Earlier points change direction across scale. The defensible Standard classification is **COMPARABLE**, not “FXABE outperforms FABEO”; see `FABEO_CORE_STATISTICAL_AUDIT.md`.
12. **Source of gap.** EXP-00 and operation counters separate G1/G2/GT exponentiation and pairing effects; residuals include MSP conversion, serialization and Python orchestration.
13. **Feature interpretation.** `feature_comparison.csv` records that FABEO does not provide anonymous lookup, dual epochs, revocation or outsourced FinalDec; its lighter core is not a feature-equivalent full-system claim.
14. **Unreasonable data.** None detected by structural and >30% monotonic-drop checks.
15. **Paper plots.** Recommend `01_encrypt_core.png`, `03a_core_ciphertext_storage.png`, `03b_fxabe_full_storage_breakdown.png`, `04_transform_vs_J.png`, `05_transform_vs_tI.png`, `07_fx_build.png`, `08_fx_query.png`, `09b_online_decryption_breakdown.png`, and `11b_dual_vs_coupled.png`. The original `03_ciphertext_storage.png` is supplemental full-system storage, not a feature-equivalent ciphertext comparison; the duplicate Encrypt-only FABEO plot is not a second main figure.
16. **Full recommendation.** `FULL_READY = YES`. Full was not run.

## Interpretation boundary

MNT224 is used solely because the audited FABEO repository benchmark fixes it. This is a common-backend performance profile, not a modern security-curve recommendation. The 05.3 construction remains **CANDIDATE — FORMAL PROOF OPEN**.
