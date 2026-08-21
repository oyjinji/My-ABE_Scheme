# Full Results Analysis

All conclusions below require and use the retained 50-repeat Full samples. Median lines use IQR; FABEO/FXABE encryption statistics also include bootstrap median confidence intervals.

1. **Occurrence reuse at ell=1280.** It remains effective: NoOccurrence/05.3 is **4.437x** (6800.159 vs 1532.667 ms).
2. **Speedup trend.** The advantage grows toward the large-policy endpoint because NoOccurrence retains one G2 exponentiation per row while 05.3 retains the fixed c_max term.
3. **05.3 Core vs FABEO.** At ell=1280 the ratio is **0.9466**. The Full curve is scale-dependent: FABEO is measured faster with non-overlapping median CIs at ell=40/80; ell=160/320 overlap; FXABE is measured faster with non-overlapping median CIs at ell=640/1280. Because the direction crosses over, the global characterization is comparable rather than a scheme-wide outperform claim. The scale-specific table is `fabeo_core_statistics.csv`.
4. **Storage vs NoOccurrence.** At ell=1280 Core storage is 70111 vs 220207 bytes, a **68.16%** reduction.
5. **Core storage vs FABEO.** FXABE/FABEO is **1.066x** (70111 vs 65745 bytes); this is the structural ABE-core view.
6. **Full storage.** Excluding the ABE G1/G2 core, the largest additional component at ell=1280 is **PStore** (46080 bytes).
7. **Transform vs J.** From J=5 to 320 the total grows 25.285 ms; FX Query contributes 23.492 ms and AuthorizedSubset 0.426 ms, while attribute/revocation crypto changes -0.201 ms (sampling noise around an essentially flat cryptographic core).
8. **Pair invariant.** `3+t_I` remains **PASS** in all retained Full Transform rows.
9. **c_max trade-off.** The validated Standard mechanism ablation remains applicable: Encrypt/storage follow padded D count; Transform pairings follow t_I, not c_max.
10. **Policy OPRF driver.** EXP-12 fixes ell and obtains R2=0.9995 versus u; the primary driver is **u**.
11. **Full Encrypt bottleneck.** At ell=u=640, Policy OPRF is 1131.953 ms, ABE Core 799.455 ms, and Full 1984.222 ms. OPRF is the largest component at this high-u point, but not universally at lower u.
12. **FX/PStore bottleneck.** It is not dominant in the measured endpoints: build at u=1280 is 88.637 ms; N=64 query is 4.652 ms. Its contribution remains workload-dependent.
13. **Dual Epoch.** Coupled/Dual update-lifecycle median ratio is **11.372x**; this is an update ablation, not two schemes.
14. **Paper-body conclusions.** Use occurrence reuse, common-backend Core comparison with uncertainty, core/full storage split, fixed `3+t_I`, real FX cost, u-sensitive OPRF, and Dual-Epoch lifecycle results.
15. **Ablation/supplement only.** c_max, NoOccurrence, coupled epoch, original full-system cross-scheme storage, and detailed primitive/phase diagnostics remain ablations or supplements.
16. **Formal security status.** **CANDIDATE — FORMAL PROOF OPEN**.
