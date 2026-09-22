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
| Bloomier retrieval | 128 | build_total_ms | 3.576 | 3.083 | 5.100 |
| Bloomier retrieval | 128 | attempt_count | 1.000 | 1.000 | 2.000 |
| Bloomier retrieval | 128 | success_rate | 1.000 | 1.000 | 1.000 |
| Bloomier retrieval | 128 | mixed_query_ns | 24481.898 | 23999.698 | 24580.898 |
| Bloomier retrieval | 128 | bytes_per_key | 13.297 | 13.297 | 13.297 |
| Bloomier retrieval | 512 | build_total_ms | 31.249 | 21.032 | 40.501 |
| Bloomier retrieval | 512 | attempt_count | 3.000 | 2.000 | 4.000 |
| Bloomier retrieval | 512 | success_rate | 1.000 | 1.000 | 1.000 |
| Bloomier retrieval | 512 | mixed_query_ns | 22746.898 | 22482.296 | 23241.098 |
| Bloomier retrieval | 512 | bytes_per_key | 13.398 | 13.398 | 13.398 |
| Cuckoo payload table | 128 | build_total_ms | 2.390 | 2.148 | 2.932 |
| Cuckoo payload table | 128 | attempt_count | 1.000 | 1.000 | 1.000 |
| Cuckoo payload table | 128 | success_rate | 1.000 | 1.000 | 1.000 |
| Cuckoo payload table | 128 | mixed_query_ns | 15118.699 | 14975.499 | 15357.398 |
| Cuckoo payload table | 128 | bytes_per_key | 26.078 | 26.078 | 26.078 |
| Cuckoo payload table | 512 | build_total_ms | 8.590 | 8.503 | 8.765 |
| Cuckoo payload table | 512 | attempt_count | 1.000 | 1.000 | 1.000 |
| Cuckoo payload table | 512 | success_rate | 1.000 | 1.000 | 1.000 |
| Cuckoo payload table | 512 | mixed_query_ns | 15333.698 | 14815.198 | 15980.398 |
| Cuckoo payload table | 512 | bytes_per_key | 26.525 | 26.525 | 26.525 |
| FX-ABF retrieval | 128 | build_total_ms | 3.814 | 3.697 | 4.750 |
| FX-ABF retrieval | 128 | attempt_count | 1.000 | 1.000 | 1.000 |
| FX-ABF retrieval | 128 | success_rate | 1.000 | 1.000 | 1.000 |
| FX-ABF retrieval | 128 | mixed_query_ns | 31338.997 | 30966.797 | 31371.197 |
| FX-ABF retrieval | 128 | bytes_per_key | 13.781 | 13.781 | 13.781 |
| FX-ABF retrieval | 512 | build_total_ms | 29.058 | 26.380 | 100.418 |
| FX-ABF retrieval | 512 | attempt_count | 2.000 | 2.000 | 8.000 |
| FX-ABF retrieval | 512 | success_rate | 1.000 | 1.000 | 1.000 |
| FX-ABF retrieval | 512 | mixed_query_ns | 30462.997 | 29782.197 | 30863.895 |
| FX-ABF retrieval | 512 | bytes_per_key | 13.521 | 13.521 | 13.521 |
| Legacy ABF retrieval | 128 | build_total_ms | 83.773 | 59.681 | 88.669 |
| Legacy ABF retrieval | 128 | attempt_count | 89.000 | 60.000 | 89.000 |
| Legacy ABF retrieval | 128 | success_rate | 1.000 | 1.000 | 1.000 |
| Legacy ABF retrieval | 128 | mixed_query_ns | 20618.198 | 19765.398 | 22019.898 |
| Legacy ABF retrieval | 128 | bytes_per_key | 53.758 | 37.094 | 53.758 |
| Legacy ABF retrieval | 512 | build_total_ms | 405.307 | 391.736 | 415.197 |
| Legacy ABF retrieval | 512 | attempt_count | 129.000 | 121.000 | 134.000 |
| Legacy ABF retrieval | 512 | success_rate | 1.000 | 1.000 | 1.000 |
| Legacy ABF retrieval | 512 | mixed_query_ns | 19227.298 | 19089.297 | 19537.298 |
| Legacy ABF retrieval | 512 | bytes_per_key | 92.586 | 84.207 | 92.586 |
| Plain XOR retrieval | 128 | build_total_ms | 2.723 | 2.541 | 2.759 |
| Plain XOR retrieval | 128 | attempt_count | 1.000 | 1.000 | 1.000 |
| Plain XOR retrieval | 128 | success_rate | 1.000 | 1.000 | 1.000 |
| Plain XOR retrieval | 128 | mixed_query_ns | 20264.498 | 19795.398 | 20511.398 |
| Plain XOR retrieval | 128 | bytes_per_key | 13.188 | 13.188 | 13.188 |
| Plain XOR retrieval | 512 | build_total_ms | 10.906 | 10.696 | 11.926 |
| Plain XOR retrieval | 512 | attempt_count | 1.000 | 1.000 | 1.000 |
| Plain XOR retrieval | 512 | success_rate | 1.000 | 1.000 | 1.000 |
| Plain XOR retrieval | 512 | mixed_query_ns | 18782.497 | 18720.799 | 19639.698 |
| Plain XOR retrieval | 512 | bytes_per_key | 13.371 | 13.371 | 13.371 |

## Correctness boundary

Validation requires zero member false negatives, zero observed final false accepts, successful deserialization queries, identical payload widths, and no locator/PStore/token mapping retained.

No conclusion that FX-ABF must be fastest is assumed; interpretation must follow the measured build, query, stability, and space results.
