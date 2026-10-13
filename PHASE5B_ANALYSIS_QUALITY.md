# Phase 5B analysis quality

Input evidence: `PHASE5A_DATA_QUALITY.md` and the five frozen `revalidated-v2` dataset manifests. All 19 run validations and five cohort validations passed before the analysis source was added. The analysis loader rechecks frozen run indices, source hashes, schema, per-configuration coverage, provenance, and trust labels while explicitly pinning the recorded benchmark code-tree hash.

| Cohort | Configurations | Measured rows | Failed |
| --- | ---: | ---: | ---: |
| Exp1/SGX_DEBUG_GRAMINE_V1 | 16 | 320 | 0 |
| Exp3/EMULATED_TEE_PROFILE | 30 | 30 | 0 |
| Exp4/EMULATED_TEE_PROFILE | 9 | 180 | 0 |
| Exp4/SGX_DEBUG_GRAMINE_V1 | 9 | 180 | 0 |
| Exp5/SGX_DEBUG_GRAMINE_V1 | 16 | 320 | 0 |

Total: 1030 rows. Excluded superseded runs: 10; IDs: `20260925T090325Z-d8045832a42e`, `20260925T090645Z-fbd209293640`, `20260925T090945Z-533620ca66f5`, `20260925T091247Z-751d8835da8e`, `20260925T091559Z-5a4ca471cc07`, `20260925T091915Z-38de853e9314`, `20260925T094613Z-74a764fbc14e`, `20260925T101404Z-fb4cbd984ccf`, `20260925T102200Z-202bc3bd3d85`, `20260925T135855Z-87d853a57f18`. They are absent from all summaries, plots, and tables.

Statistical policy: all raw observations retained; per-configuration n, min, linear-interpolated Q1, median, Q3, mean, population std, p90, p95, and max. No trimming, winsorization, IQR deletion, or outlier exclusion. No p-value search. Main latency center is the median; p95 accompanies it. Exp3 uses one canonical artifact per configuration and no latency inference.

CI policy: no inferential CI is reported. Each latency configuration has one run and only three contiguous blocks; these do not support a reliable independent-run cluster bootstrap. The deterministic block-bootstrap primitive is unit tested but deliberately unused in paper estimates.

Missing-field policy: required observed durations and pairing counts were present and positive. EMULATED enclave/RPC fields and non-Exp4 user-batch fields remain explicitly NOT_OBSERVED. No missing observation was imputed. All duration units remain ns in machine summaries; presentation figures convert to ms. Requested and actual J remain separate.

Trust policy: real SGX rows remain DEBUG feasibility with QVL OUT_OF_DATE and strict RA2 blocked. EMULATED_TEST remains a separate cohort. SGX captions and table footnotes disclose this boundary.

Generated figures: 23 candidate figures, each PNG and PDF with figure-data CSV and metadata JSON. Generated paper tables: 5, each with machine table-data CSV. The recommended core set is selected by research-question coverage, not favorable direction. RPC receive/enclave durations are not summed as independent components.

Claim lint: PASS, 6 paper files scanned, 0 forbidden phrase hits. Security and formal-proof limitations remain explicit.

Reproducibility check: independent bundle `20260926T061423Z-f50809947551` passed verification; 74 semantic files (statistics, figure source/specification, tables, and paper text) were byte-identical to `20260926T061408Z-8bb066fbcd25`. Rendered PNG/PDF bytes were excluded because image metadata may vary.

Earlier Phase 5B bundles under this output root were generated before the final Exp4 distribution and traceability additions. The final bundles above supersede them; all use the same frozen benchmark inputs.
