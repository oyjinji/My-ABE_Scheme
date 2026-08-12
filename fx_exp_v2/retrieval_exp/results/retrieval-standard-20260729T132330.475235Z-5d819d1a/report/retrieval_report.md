# Functionally equivalent retrieval experiment

This is the primary algorithm-level comparison. Every structure directly implements `token -> fixed-width j || check / miss`; no locator, PStore, KDF, AEAD, ABE group operation, or pairing is present.

The previous five-index full run remains an immutable supplemental system-level composed-index experiment.

## Environment

- Python: `3.8.10 (default, Mar 18 2025, 20:04:55) `
- OS: `Linux-6.18.33.1-microsoft-standard-WSL2-x86_64-with-glibc2.29`
- CPU: `Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz`
- CPU affinity: `{'cpu': 0, 'status': 'fixed'}`

## Constructions

- Legacy ABF: greedy three-position XOR assignment.
- Bloomier: four-partition peelable XOR static function.
- Cuckoo payload: two buckets containing fingerprint + full value.
- Plain XOR: three independent global positions and reverse assignment.
- FX-ABF: Binary-Fuse-style consecutive segments and reverse assignment.

## Median results with independent-seed bootstrap 95% CI

| retrieval_name | u | metric | median | ci95_low | ci95_high |
|---|---|---|---|---|---|
| Bloomier retrieval | 128 | build_total_ms | 3.936 | 3.046 | 5.387 |
| Bloomier retrieval | 128 | attempt_count | 1.000 | 1.000 | 2.000 |
| Bloomier retrieval | 128 | success_rate | 1.000 | 1.000 | 1.000 |
| Bloomier retrieval | 128 | mixed_query_ns | 24537.428 | 23660.754 | 25113.453 |
| Bloomier retrieval | 128 | bytes_per_key | 13.297 | 13.297 | 13.297 |
| Bloomier retrieval | 512 | build_total_ms | 29.085 | 20.632 | 46.900 |
| Bloomier retrieval | 512 | attempt_count | 2.500 | 2.000 | 5.000 |
| Bloomier retrieval | 512 | success_rate | 1.000 | 1.000 | 1.000 |
| Bloomier retrieval | 512 | mixed_query_ns | 24886.719 | 23244.184 | 26148.040 |
| Bloomier retrieval | 512 | bytes_per_key | 13.398 | 13.398 | 13.398 |
| Bloomier retrieval | 2048 | build_total_ms | 74.728 | 54.125 | 96.093 |
| Bloomier retrieval | 2048 | attempt_count | 1.500 | 1.000 | 2.000 |
| Bloomier retrieval | 2048 | success_rate | 1.000 | 1.000 | 1.000 |
| Bloomier retrieval | 2048 | mixed_query_ns | 24699.756 | 23304.248 | 26342.871 |
| Bloomier retrieval | 2048 | bytes_per_key | 13.102 | 13.102 | 13.102 |
| Bloomier retrieval | 8192 | build_total_ms | 364.193 | 208.625 | 439.324 |
| Bloomier retrieval | 8192 | attempt_count | 2.000 | 1.000 | 2.500 |
| Bloomier retrieval | 8192 | success_rate | 1.000 | 1.000 | 1.000 |
| Bloomier retrieval | 8192 | mixed_query_ns | 24137.449 | 23771.876 | 24438.671 |
| Bloomier retrieval | 8192 | bytes_per_key | 13.025 | 13.025 | 13.025 |
| Bloomier retrieval | 16384 | build_total_ms | 494.549 | 430.485 | 899.183 |
| Bloomier retrieval | 16384 | attempt_count | 1.000 | 1.000 | 2.500 |
| Bloomier retrieval | 16384 | success_rate | 1.000 | 1.000 | 1.000 |
| Bloomier retrieval | 16384 | mixed_query_ns | 24238.452 | 23977.197 | 26020.634 |
| Bloomier retrieval | 16384 | bytes_per_key | 13.013 | 13.013 | 13.013 |
| Cuckoo payload table | 128 | build_total_ms | 2.148 | 2.080 | 2.835 |
| Cuckoo payload table | 128 | attempt_count | 1.000 | 1.000 | 1.000 |
| Cuckoo payload table | 128 | success_rate | 1.000 | 1.000 | 1.000 |
| Cuckoo payload table | 128 | mixed_query_ns | 15876.026 | 15271.339 | 17405.028 |
| Cuckoo payload table | 128 | bytes_per_key | 26.078 | 26.078 | 26.078 |
| Cuckoo payload table | 512 | build_total_ms | 9.355 | 9.034 | 10.585 |
| Cuckoo payload table | 512 | attempt_count | 1.000 | 1.000 | 1.000 |
| Cuckoo payload table | 512 | success_rate | 1.000 | 1.000 | 1.000 |
| Cuckoo payload table | 512 | mixed_query_ns | 16210.864 | 15811.133 | 17689.502 |
| Cuckoo payload table | 512 | bytes_per_key | 26.525 | 26.525 | 26.525 |
| Cuckoo payload table | 2048 | build_total_ms | 35.612 | 35.152 | 36.390 |
| Cuckoo payload table | 2048 | attempt_count | 1.000 | 1.000 | 1.000 |
| Cuckoo payload table | 2048 | success_rate | 1.000 | 1.000 | 1.000 |
| Cuckoo payload table | 2048 | mixed_query_ns | 15952.222 | 15334.253 | 16712.891 |
| Cuckoo payload table | 2048 | bytes_per_key | 26.133 | 26.133 | 26.133 |
| Cuckoo payload table | 8192 | build_total_ms | 146.580 | 144.288 | 156.655 |
| Cuckoo payload table | 8192 | attempt_count | 1.000 | 1.000 | 1.000 |
| Cuckoo payload table | 8192 | success_rate | 1.000 | 1.000 | 1.000 |
| Cuckoo payload table | 8192 | mixed_query_ns | 15672.192 | 15399.609 | 16105.517 |
| Cuckoo payload table | 8192 | bytes_per_key | 26.033 | 26.033 | 26.033 |
| Cuckoo payload table | 16384 | build_total_ms | 297.757 | 290.777 | 306.359 |
| Cuckoo payload table | 16384 | attempt_count | 1.000 | 1.000 | 1.000 |
| Cuckoo payload table | 16384 | success_rate | 1.000 | 1.000 | 1.000 |
| Cuckoo payload table | 16384 | mixed_query_ns | 15691.992 | 15535.546 | 16636.230 |
| Cuckoo payload table | 16384 | bytes_per_key | 26.017 | 26.017 | 26.017 |
| FX-ABF retrieval | 128 | build_total_ms | 4.004 | 3.516 | 8.633 |
| FX-ABF retrieval | 128 | attempt_count | 1.000 | 1.000 | 3.000 |
| FX-ABF retrieval | 128 | success_rate | 1.000 | 1.000 | 1.000 |
| FX-ABF retrieval | 128 | mixed_query_ns | 29845.802 | 28082.430 | 31333.236 |
| FX-ABF retrieval | 128 | bytes_per_key | 13.781 | 13.781 | 13.781 |
| FX-ABF retrieval | 512 | build_total_ms | 31.172 | 15.850 | 48.219 |
| FX-ABF retrieval | 512 | attempt_count | 2.500 | 1.000 | 5.000 |
| FX-ABF retrieval | 512 | success_rate | 1.000 | 1.000 | 1.000 |
| FX-ABF retrieval | 512 | mixed_query_ns | 28236.248 | 26443.238 | 29583.936 |
| FX-ABF retrieval | 512 | bytes_per_key | 13.521 | 13.521 | 13.521 |
| FX-ABF retrieval | 2048 | build_total_ms | 62.419 | 59.607 | 65.859 |
| FX-ABF retrieval | 2048 | attempt_count | 1.000 | 1.000 | 1.000 |
| FX-ABF retrieval | 2048 | success_rate | 1.000 | 1.000 | 1.000 |
| FX-ABF retrieval | 2048 | mixed_query_ns | 26784.548 | 26153.565 | 28352.344 |
| FX-ABF retrieval | 2048 | bytes_per_key | 13.133 | 13.133 | 13.133 |
| FX-ABF retrieval | 8192 | build_total_ms | 234.845 | 231.696 | 245.007 |
| FX-ABF retrieval | 8192 | attempt_count | 1.000 | 1.000 | 1.000 |
| FX-ABF retrieval | 8192 | success_rate | 1.000 | 1.000 | 1.000 |
| FX-ABF retrieval | 8192 | mixed_query_ns | 26992.871 | 26559.448 | 27604.011 |
| FX-ABF retrieval | 8192 | bytes_per_key | 13.033 | 13.033 | 13.033 |
| FX-ABF retrieval | 16384 | build_total_ms | 480.607 | 471.849 | 496.892 |
| FX-ABF retrieval | 16384 | attempt_count | 1.000 | 1.000 | 1.000 |
| FX-ABF retrieval | 16384 | success_rate | 1.000 | 1.000 | 1.000 |
| FX-ABF retrieval | 16384 | mixed_query_ns | 28593.042 | 27200.537 | 30234.424 |
| FX-ABF retrieval | 16384 | bytes_per_key | 13.017 | 13.017 | 13.017 |
| Legacy ABF retrieval | 128 | build_total_ms | 88.309 | 70.292 | 94.327 |
| Legacy ABF retrieval | 128 | attempt_count | 86.000 | 70.500 | 90.500 |
| Legacy ABF retrieval | 128 | success_rate | 1.000 | 1.000 | 1.000 |
| Legacy ABF retrieval | 128 | mixed_query_ns | 21738.721 | 20844.094 | 22560.217 |
| Legacy ABF retrieval | 128 | bytes_per_key | 51.367 | 42.648 | 53.758 |
| Legacy ABF retrieval | 512 | build_total_ms | 454.196 | 425.221 | 476.877 |
| Legacy ABF retrieval | 512 | attempt_count | 136.000 | 127.500 | 136.000 |
| Legacy ABF retrieval | 512 | success_rate | 0.000 | 0.000 | 1.000 |
| Legacy ABF retrieval | 512 | mixed_query_ns | 0.000 | 0.000 | 19670.991 |
| Legacy ABF retrieval | 512 | bytes_per_key | 0.000 | 0.000 | 84.312 |
| Legacy ABF retrieval | 2048 | build_total_ms | 1300.152 | 1274.210 | 1338.955 |
| Legacy ABF retrieval | 2048 | attempt_count | 136.000 | 136.000 | 136.000 |
| Legacy ABF retrieval | 2048 | success_rate | 0.000 | 0.000 | 0.000 |
| Legacy ABF retrieval | 2048 | mixed_query_ns | 0.000 | 0.000 | 0.000 |
| Legacy ABF retrieval | 2048 | bytes_per_key | 0.000 | 0.000 | 0.000 |
| Legacy ABF retrieval | 8192 | build_total_ms | 3687.858 | 3625.412 | 3769.819 |
| Legacy ABF retrieval | 8192 | attempt_count | 136.000 | 136.000 | 136.000 |
| Legacy ABF retrieval | 8192 | success_rate | 0.000 | 0.000 | 0.000 |
| Legacy ABF retrieval | 8192 | mixed_query_ns | 0.000 | 0.000 | 0.000 |
| Legacy ABF retrieval | 8192 | bytes_per_key | 0.000 | 0.000 | 0.000 |
| Legacy ABF retrieval | 16384 | build_total_ms | 6174.591 | 6040.794 | 6365.136 |
| Legacy ABF retrieval | 16384 | attempt_count | 136.000 | 136.000 | 136.000 |
| Legacy ABF retrieval | 16384 | success_rate | 0.000 | 0.000 | 0.000 |
| Legacy ABF retrieval | 16384 | mixed_query_ns | 0.000 | 0.000 | 0.000 |
| Legacy ABF retrieval | 16384 | bytes_per_key | 0.000 | 0.000 | 0.000 |
| Plain XOR retrieval | 128 | build_total_ms | 3.375 | 2.760 | 4.737 |
| Plain XOR retrieval | 128 | attempt_count | 1.000 | 1.000 | 2.000 |
| Plain XOR retrieval | 128 | success_rate | 1.000 | 1.000 | 1.000 |
| Plain XOR retrieval | 128 | mixed_query_ns | 21902.833 | 20831.359 | 22387.360 |
| Plain XOR retrieval | 128 | bytes_per_key | 13.188 | 13.188 | 13.188 |
| Plain XOR retrieval | 512 | build_total_ms | 13.012 | 10.785 | 15.010 |
| Plain XOR retrieval | 512 | attempt_count | 1.000 | 1.000 | 1.000 |
| Plain XOR retrieval | 512 | success_rate | 1.000 | 1.000 | 1.000 |
| Plain XOR retrieval | 512 | mixed_query_ns | 19930.684 | 19351.416 | 20766.797 |
| Plain XOR retrieval | 512 | bytes_per_key | 13.371 | 13.371 | 13.371 |
| Plain XOR retrieval | 2048 | build_total_ms | 45.058 | 43.731 | 49.382 |
| Plain XOR retrieval | 2048 | attempt_count | 1.000 | 1.000 | 1.000 |
| Plain XOR retrieval | 2048 | success_rate | 1.000 | 1.000 | 1.000 |
| Plain XOR retrieval | 2048 | mixed_query_ns | 19785.962 | 19314.624 | 20889.781 |
| Plain XOR retrieval | 2048 | bytes_per_key | 13.095 | 13.095 | 13.095 |
| Plain XOR retrieval | 8192 | build_total_ms | 191.541 | 184.601 | 200.344 |
| Plain XOR retrieval | 8192 | attempt_count | 1.000 | 1.000 | 1.000 |
| Plain XOR retrieval | 8192 | success_rate | 1.000 | 1.000 | 1.000 |
| Plain XOR retrieval | 8192 | mixed_query_ns | 19871.655 | 19719.922 | 20795.142 |
| Plain XOR retrieval | 8192 | bytes_per_key | 13.024 | 13.024 | 13.024 |
| Plain XOR retrieval | 16384 | build_total_ms | 372.025 | 363.256 | 382.441 |
| Plain XOR retrieval | 16384 | attempt_count | 1.000 | 1.000 | 1.000 |
| Plain XOR retrieval | 16384 | success_rate | 1.000 | 1.000 | 1.000 |
| Plain XOR retrieval | 16384 | mixed_query_ns | 20859.156 | 20308.594 | 21340.722 |
| Plain XOR retrieval | 16384 | bytes_per_key | 13.012 | 13.012 | 13.012 |

## Correctness boundary

Validation requires zero member false negatives, zero observed final false accepts, successful deserialization queries, identical payload widths, and no locator/PStore/token mapping retained.

No conclusion that FX-ABF must be fastest is assumed; interpretation must follow the measured build, query, stability, and space results.
