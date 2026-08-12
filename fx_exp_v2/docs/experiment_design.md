# Experiment design

## Primary retrieval-only experiment

`fx_exp_v2/retrieval_exp` is the functionally equivalent algorithm comparison.
Legacy ABF retrieval, four-partition Bloomier retrieval, Cuckoo payload table,
Plain XOR retrieval, and FX-ABF retrieval all map a token directly to the same
fixed-width `j || check` value or miss. No structure uses an exact locator or
PStore. R1-R4 separately report Build/stability, member/nonmember/mixed Query,
canonical serialized space, and correctness after deserialization.

## Supplemental system-level composed indexes

F1 measures real construction, retries, resizing, canonical serialized space,
and AES-GCM PStore work for five indexes. F1-A has one row per token; F1-B has
four rows per token with a reproducible mildly skewed distribution.

F2 uses `Code.fxabe_rev.FXABERev`, Charm MNT224 group elements, and an explicit
counter around every actual `pair()` call. F2-A fixes `N=32,r=8` while policy
rows increase. F2-B fixes policy size and `N=64` while `r` increases. Each
filter receives the same ciphertext row components, transform key, KU, tokens,
and postings for a workload. Index construction is completed before timing.

F3 executes member and nonmember queries against all five authenticated
retrieval chains. A membership candidate is not a final hit: the exact locator
and/or PStore authentication must succeed.

All workloads derive `workload_seed`, `filter_seed`, and `scheme_seed` from a
recorded master seed. Timings use `time.perf_counter_ns`. Summaries report
count, mean, median, sample standard deviation, min, max, p95, and deterministic
bootstrap 95% confidence intervals for timing metrics.
