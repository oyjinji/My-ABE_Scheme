# Phase 5A data quality

This report covers only the frozen `revalidated-v2` controlled datasets for Exp1, Exp3, Exp4, and Exp5. It reports coverage and validation, not comparative performance or a paper conclusion. The sole specification is `ABE/Doc/ABE-Scheme-08.md`; formal status remains **CANDIDATE — FORMAL PROOF OPEN**.

| Experiment | Backend/cohort | Runs | Configurations | Measured rows | Failed/timeout | Dataset validation |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| Exp1 | real SGX DEBUG feasibility | 4 | 16 | 320 | 0/0 | PASS |
| Exp3 | EMULATED_TEST | 5 | 30 | 30 | 0/0 | PASS |
| Exp4 | EMULATED_TEST | 4 | 9 | 180 | 0/0 | PASS |
| Exp4 | real SGX DEBUG feasibility | 4 | 9 | 180 | 0/0 | PASS |
| Exp5 | real SGX DEBUG feasibility | 2 | 16 | 320 | 0/0 | PASS |

All 19 run validators pass. Every latency configuration has 20 measured rows; each Exp3 storage configuration has one canonical artifact. All 1,030 raw rows have `sample_status=OK`, a passing correctness precheck, a block environment snapshot, and a workload seed. No failed or timeout sample was removed. No outlier exclusion was applied. The descriptive summaries retain run IDs, configuration IDs, and sample IDs linking back to raw JSONL.

Exp1 covers `ell={5,10,20,40}` and four repeat regimes. Exp3 covers `ell={5,10,20,40,80,160}` and `cmax={1,2,3,4,5}`. Its 30 canonical CT byte totals equal the sum of recorded CT-core, header, AF, DEM, and publication categories; `D_j` counts match each run's `Setup(cmax)`. Revocation-specific ciphertext, tree-key, and public update structures are all recorded as zero for this scheme. Exp4 has nine configurations per backend, including LOW/MEDIUM/HIGH hit regimes; its tokenization, AF, and same-context checks are present on every row. Exp5 covers `N={5,10,20,40}`, requested candidate-size tiers, AND/threshold/repeated policies, actual `k={2,3,5}`, and actual `tI={1,2}`. All measured pairing counters satisfy TEE=1, CSP=1+`tI`, system=2+`tI`, and FinalDec=0.

Required measurement fields have no gaps. All 820 real SGX rows contain enclave-stage, independent RPC send/receive, Transform, and FinalDec timings. Exp4 rows in both backends contain policy/user token-batch and AF metrics. `NOT_OBSERVED` is intentional for enclave/RPC fields in EMULATED rows and for the user-batch metric outside Exp4. Requested and actual candidate counts differ in 102 rows across the five cohorts; both values remain in raw data, and no requested value was substituted for an actual measurement. Exp4 same-context equality is true on all 360 rows; the cross-context observation is false on those rows. This observation is not an unlinkability proof.

All 19 runs have CPU affinity `[0]`, the same environment fingerprint `567895d307e66bfa8ab82617a12b0ec274b497f04c3c6303ece5a81683f9e39c`, code-tree SHA-256 `639f1c66c3a985fa24a81e863ab6db19038b9cbb1e36873d415de20f677ffbef`, specification SHA-256 `d52daf431bfececa4b1b8bf0f77fe34634710c9502d372f405b75b806812df85`, and frozen plan identifier `5101755f310be6aada9581bac7ac5e6ac354075093c3316f0931fe5674c24fed`. The real SGX rows consistently retain `SGX_DEBUG_GRAMINE_V1`, `QVL_VERIFIED_OUTDATED_TCB_DEBUG_FEASIBILITY_V1`, QVL `OUT_OF_DATE`, and strict RA2 `BLOCKED_BY_TCB_POLICY`; the EMULATED rows are a separate cohort. Each real run recorded a nonzero fresh attestation preflight duration outside request latency.

The run validator checked artifact file hashes/sizes, raw JSONL/CSV agreement, schema, units, configuration coverage, prechecks, canaries, and forbidden structured field names. An additional scan of all 181 text files under `revalidated-v2`, including dataset manifests and summaries, found zero known TEST-canary matches and zero forbidden structured-field names. The same scan across all 277 Phase 5A text artifacts, including superseded material, also found zero matches. This is a bounded synthetic-secret audit; it does not claim discovery of unknown secret values.

Before the current code-tree fix, ten earlier runs were marked `SUPERSEDED_BY_CODE_CHANGE` in `artifacts/myabe08/benchmarks/phase5a/superseded_by_code_change.json`. They remain preserved but are excluded from these counts and summaries. Exp2 is still `BLOCKED_COMMON_BACKEND`; Exp6/Exp7 were correctness/privacy gates only and have no formal scaling dataset. No Phase 4F smoke data is included.

Dataset manifests: [Exp1 SGX](artifacts/myabe08/benchmarks/phase5a/revalidated-v2/Exp1/SGX_DEBUG_GRAMINE_V1/dataset_manifest.json), [Exp3 EMULATED](artifacts/myabe08/benchmarks/phase5a/revalidated-v2/Exp3/EMULATED_TEE_PROFILE/dataset_manifest.json), [Exp4 EMULATED](artifacts/myabe08/benchmarks/phase5a/revalidated-v2/Exp4/EMULATED_TEE_PROFILE/dataset_manifest.json), [Exp4 SGX](artifacts/myabe08/benchmarks/phase5a/revalidated-v2/Exp4/SGX_DEBUG_GRAMINE_V1/dataset_manifest.json), [Exp5 SGX](artifacts/myabe08/benchmarks/phase5a/revalidated-v2/Exp5/SGX_DEBUG_GRAMINE_V1/dataset_manifest.json).
