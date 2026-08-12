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
| Bloomier retrieval | 128 | build_total_ms | 2.880 | 2.843 | 5.385 |
| Bloomier retrieval | 128 | attempt_count | 1.000 | 1.000 | 2.000 |
| Bloomier retrieval | 128 | success_rate | 1.000 | 1.000 | 1.000 |
| Bloomier retrieval | 128 | mixed_query_ns | 24458.100 | 24384.500 | 24538.500 |
| Bloomier retrieval | 128 | bytes_per_key | 13.297 | 13.297 | 13.297 |
| Bloomier retrieval | 512 | build_total_ms | 29.336 | 24.665 | 39.850 |
| Bloomier retrieval | 512 | attempt_count | 3.000 | 2.000 | 4.000 |
| Bloomier retrieval | 512 | success_rate | 1.000 | 1.000 | 1.000 |
| Bloomier retrieval | 512 | mixed_query_ns | 22245.601 | 22212.601 | 22512.500 |
| Bloomier retrieval | 512 | bytes_per_key | 13.398 | 13.398 | 13.398 |
| Cuckoo payload table | 128 | build_total_ms | 2.199 | 2.077 | 2.771 |
| Cuckoo payload table | 128 | attempt_count | 1.000 | 1.000 | 1.000 |
| Cuckoo payload table | 128 | success_rate | 1.000 | 1.000 | 1.000 |
| Cuckoo payload table | 128 | mixed_query_ns | 14755.800 | 14691.601 | 15247.400 |
| Cuckoo payload table | 128 | bytes_per_key | 26.078 | 26.078 | 26.078 |
| Cuckoo payload table | 512 | build_total_ms | 9.169 | 8.688 | 9.339 |
| Cuckoo payload table | 512 | attempt_count | 1.000 | 1.000 | 1.000 |
| Cuckoo payload table | 512 | success_rate | 1.000 | 1.000 | 1.000 |
| Cuckoo payload table | 512 | mixed_query_ns | 15455.000 | 15217.201 | 16740.200 |
| Cuckoo payload table | 512 | bytes_per_key | 26.525 | 26.525 | 26.525 |
| FX-ABF retrieval | 128 | build_total_ms | 3.642 | 3.569 | 4.151 |
| FX-ABF retrieval | 128 | attempt_count | 1.000 | 1.000 | 1.000 |
| FX-ABF retrieval | 128 | success_rate | 1.000 | 1.000 | 1.000 |
| FX-ABF retrieval | 128 | mixed_query_ns | 30770.500 | 30479.501 | 31558.001 |
| FX-ABF retrieval | 128 | bytes_per_key | 13.781 | 13.781 | 13.781 |
| FX-ABF retrieval | 512 | build_total_ms | 26.389 | 25.390 | 103.945 |
| FX-ABF retrieval | 512 | attempt_count | 2.000 | 2.000 | 8.000 |
| FX-ABF retrieval | 512 | success_rate | 1.000 | 1.000 | 1.000 |
| FX-ABF retrieval | 512 | mixed_query_ns | 29203.001 | 28914.101 | 29312.401 |
| FX-ABF retrieval | 512 | bytes_per_key | 13.521 | 13.521 | 13.521 |
| Legacy ABF retrieval | 128 | build_total_ms | 84.674 | 53.734 | 85.709 |
| Legacy ABF retrieval | 128 | attempt_count | 89.000 | 60.000 | 89.000 |
| Legacy ABF retrieval | 128 | success_rate | 1.000 | 1.000 | 1.000 |
| Legacy ABF retrieval | 128 | mixed_query_ns | 20645.700 | 20546.800 | 21506.000 |
| Legacy ABF retrieval | 128 | bytes_per_key | 53.758 | 37.094 | 53.758 |
| Legacy ABF retrieval | 512 | build_total_ms | 407.970 | 369.193 | 411.514 |
| Legacy ABF retrieval | 512 | attempt_count | 129.000 | 121.000 | 134.000 |
| Legacy ABF retrieval | 512 | success_rate | 1.000 | 1.000 | 1.000 |
| Legacy ABF retrieval | 512 | mixed_query_ns | 19123.100 | 18998.501 | 19300.701 |
| Legacy ABF retrieval | 512 | bytes_per_key | 92.586 | 84.207 | 92.586 |
| Plain XOR retrieval | 128 | build_total_ms | 2.525 | 2.496 | 2.549 |
| Plain XOR retrieval | 128 | attempt_count | 1.000 | 1.000 | 1.000 |
| Plain XOR retrieval | 128 | success_rate | 1.000 | 1.000 | 1.000 |
| Plain XOR retrieval | 128 | mixed_query_ns | 20174.601 | 20050.201 | 21377.400 |
| Plain XOR retrieval | 128 | bytes_per_key | 13.188 | 13.188 | 13.188 |
| Plain XOR retrieval | 512 | build_total_ms | 10.509 | 10.487 | 12.548 |
| Plain XOR retrieval | 512 | attempt_count | 1.000 | 1.000 | 1.000 |
| Plain XOR retrieval | 512 | success_rate | 1.000 | 1.000 | 1.000 |
| Plain XOR retrieval | 512 | mixed_query_ns | 19045.001 | 18903.801 | 19307.901 |
| Plain XOR retrieval | 512 | bytes_per_key | 13.371 | 13.371 | 13.371 |

## Correctness boundary

Validation requires zero member false negatives, zero observed final false accepts, successful deserialization queries, identical payload widths, and no locator/PStore/token mapping retained.

No conclusion that FX-ABF must be fastest is assumed; interpretation must follow the measured build, query, stability, and space results.
