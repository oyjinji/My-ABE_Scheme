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
| Bloomier retrieval | 128 | build_total_ms | 3.200 | 3.129 | 5.476 |
| Bloomier retrieval | 128 | attempt_count | 1.000 | 1.000 | 2.000 |
| Bloomier retrieval | 128 | success_rate | 1.000 | 1.000 | 1.000 |
| Bloomier retrieval | 128 | mixed_query_ns | 24965.402 | 24520.301 | 26553.202 |
| Bloomier retrieval | 128 | bytes_per_key | 13.297 | 13.297 | 13.297 |
| Bloomier retrieval | 512 | build_total_ms | 44.427 | 21.354 | 44.636 |
| Bloomier retrieval | 512 | attempt_count | 3.000 | 2.000 | 4.000 |
| Bloomier retrieval | 512 | success_rate | 1.000 | 1.000 | 1.000 |
| Bloomier retrieval | 512 | mixed_query_ns | 23639.901 | 22874.502 | 33642.902 |
| Bloomier retrieval | 512 | bytes_per_key | 13.398 | 13.398 | 13.398 |
| Cuckoo payload table | 128 | build_total_ms | 2.245 | 2.130 | 2.945 |
| Cuckoo payload table | 128 | attempt_count | 1.000 | 1.000 | 1.000 |
| Cuckoo payload table | 128 | success_rate | 1.000 | 1.000 | 1.000 |
| Cuckoo payload table | 128 | mixed_query_ns | 15301.901 | 15178.101 | 15361.301 |
| Cuckoo payload table | 128 | bytes_per_key | 26.078 | 26.078 | 26.078 |
| Cuckoo payload table | 512 | build_total_ms | 9.927 | 9.609 | 10.147 |
| Cuckoo payload table | 512 | attempt_count | 1.000 | 1.000 | 1.000 |
| Cuckoo payload table | 512 | success_rate | 1.000 | 1.000 | 1.000 |
| Cuckoo payload table | 512 | mixed_query_ns | 16369.901 | 15739.501 | 22734.401 |
| Cuckoo payload table | 512 | bytes_per_key | 26.525 | 26.525 | 26.525 |
| FX-ABF retrieval | 128 | build_total_ms | 3.710 | 3.288 | 4.592 |
| FX-ABF retrieval | 128 | attempt_count | 1.000 | 1.000 | 1.000 |
| FX-ABF retrieval | 128 | success_rate | 1.000 | 1.000 | 1.000 |
| FX-ABF retrieval | 128 | mixed_query_ns | 27554.401 | 27522.901 | 29353.802 |
| FX-ABF retrieval | 128 | bytes_per_key | 13.781 | 13.781 | 13.781 |
| FX-ABF retrieval | 512 | build_total_ms | 26.595 | 25.810 | 87.283 |
| FX-ABF retrieval | 512 | attempt_count | 2.000 | 2.000 | 8.000 |
| FX-ABF retrieval | 512 | success_rate | 1.000 | 1.000 | 1.000 |
| FX-ABF retrieval | 512 | mixed_query_ns | 27504.002 | 26592.702 | 30207.302 |
| FX-ABF retrieval | 512 | bytes_per_key | 13.521 | 13.521 | 13.521 |
| Legacy ABF retrieval | 128 | build_total_ms | 85.066 | 56.398 | 87.501 |
| Legacy ABF retrieval | 128 | attempt_count | 89.000 | 60.000 | 89.000 |
| Legacy ABF retrieval | 128 | success_rate | 1.000 | 1.000 | 1.000 |
| Legacy ABF retrieval | 128 | mixed_query_ns | 21670.101 | 21030.201 | 23079.701 |
| Legacy ABF retrieval | 128 | bytes_per_key | 53.758 | 37.094 | 53.758 |
| Legacy ABF retrieval | 512 | build_total_ms | 421.842 | 413.426 | 445.909 |
| Legacy ABF retrieval | 512 | attempt_count | 129.000 | 121.000 | 134.000 |
| Legacy ABF retrieval | 512 | success_rate | 1.000 | 1.000 | 1.000 |
| Legacy ABF retrieval | 512 | mixed_query_ns | 20684.201 | 19984.501 | 21229.301 |
| Legacy ABF retrieval | 512 | bytes_per_key | 92.586 | 84.207 | 92.586 |
| Plain XOR retrieval | 128 | build_total_ms | 2.534 | 2.527 | 2.837 |
| Plain XOR retrieval | 128 | attempt_count | 1.000 | 1.000 | 1.000 |
| Plain XOR retrieval | 128 | success_rate | 1.000 | 1.000 | 1.000 |
| Plain XOR retrieval | 128 | mixed_query_ns | 21626.102 | 20694.201 | 23593.402 |
| Plain XOR retrieval | 128 | bytes_per_key | 13.188 | 13.188 | 13.188 |
| Plain XOR retrieval | 512 | build_total_ms | 10.661 | 10.401 | 16.379 |
| Plain XOR retrieval | 512 | attempt_count | 1.000 | 1.000 | 1.000 |
| Plain XOR retrieval | 512 | success_rate | 1.000 | 1.000 | 1.000 |
| Plain XOR retrieval | 512 | mixed_query_ns | 20052.002 | 19534.801 | 24033.701 |
| Plain XOR retrieval | 512 | bytes_per_key | 13.371 | 13.371 | 13.371 |

## Correctness boundary

Validation requires zero member false negatives, zero observed final false accepts, successful deserialization queries, identical payload widths, and no locator/PStore/token mapping retained.

No conclusion that FX-ABF must be fastest is assumed; interpretation must follow the measured build, query, stability, and space results.
