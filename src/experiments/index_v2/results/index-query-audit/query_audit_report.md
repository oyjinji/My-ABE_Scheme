# Anonymous-index query audit report

This report is generated from the dedicated audit run. Times are medians across 30 independent workloads and are per mixed batch of 32 queries (8 members, 24 nonmembers). The diagnostic does not modify or replace the existing full run.

## A. System-level integrated query

`system_reported` sums the timers returned by the production query implementation. `system_wall` additionally includes Python dispatch, result/metrics construction, and timing overhead.

| ell | index_name | system_reported_integrated_query_us | system_wall_query_us |
|---|---|---|---|
| 32 | Legacy ABF | 873.85 | 950.13 |
| 32 | Bloom+Locator | 1254.60 | 1351.80 |
| 32 | Cuckoo+Locator | 466.25 | 551.45 |
| 32 | Xor+Locator | 719.62 | 809.12 |
| 32 | FX-ABF | 1342.15 | 1429.92 |
| 32 | ExactHashMap+PStore | 350.68 | 431.88 |
| 128 | Legacy ABF | 875.33 | 952.27 |
| 128 | Bloom+Locator | 1255.75 | 1354.98 |
| 128 | Cuckoo+Locator | 471.80 | 556.25 |
| 128 | Xor+Locator | 721.05 | 811.55 |
| 128 | FX-ABF | 1355.72 | 1445.33 |
| 128 | ExactHashMap+PStore | 351.98 | 437.20 |
| 512 | Legacy ABF | 872.65 | 948.48 |
| 512 | Bloom+Locator | 1251.53 | 1348.80 |
| 512 | Cuckoo+Locator | 470.38 | 555.05 |
| 512 | Xor+Locator | 717.42 | 808.15 |
| 512 | FX-ABF | 1354.65 | 1444.38 |
| 512 | ExactHashMap+PStore | 350.25 | 431.68 |

## B. Common-security-envelope breakdown

Every successful member path uses the same context-digest check, posting KDF, AES-GCM backend, canonical posting decoder, strictly-increasing/duplicate/range checks, and miss-on-authentication-failure rule. The retrieval/locator/identifier column isolates the index-specific work.

| ell | index_name | token_preparation_us | common_retrieval_locator_identifier_us | common_security_envelope_us | common_envelope_integrated_query_us |
|---|---|---|---|---|---|
| 32 | Legacy ABF | 0.40 | 758.33 | 252.90 | 1011.15 |
| 32 | Bloom+Locator | 0.40 | 554.80 | 256.80 | 812.02 |
| 32 | Cuckoo+Locator | 0.40 | 260.80 | 248.72 | 509.35 |
| 32 | Xor+Locator | 0.40 | 578.75 | 251.50 | 830.50 |
| 32 | FX-ABF | 0.40 | 1225.00 | 264.75 | 1489.80 |
| 32 | ExactHashMap+PStore | 0.30 | 141.35 | 242.12 | 384.02 |
| 128 | Legacy ABF | 0.40 | 758.65 | 252.80 | 1013.17 |
| 128 | Bloom+Locator | 0.40 | 565.52 | 258.02 | 825.12 |
| 128 | Cuckoo+Locator | 0.40 | 264.35 | 249.65 | 515.43 |
| 128 | Xor+Locator | 0.40 | 579.75 | 253.43 | 833.67 |
| 128 | FX-ABF | 0.40 | 1229.35 | 266.80 | 1495.15 |
| 128 | ExactHashMap+PStore | 0.30 | 142.82 | 243.85 | 386.52 |
| 512 | Legacy ABF | 0.40 | 754.23 | 255.22 | 1012.75 |
| 512 | Bloom+Locator | 0.40 | 547.42 | 257.70 | 804.83 |
| 512 | Cuckoo+Locator | 0.40 | 262.02 | 249.78 | 512.67 |
| 512 | Xor+Locator | 0.40 | 574.98 | 252.75 | 828.23 |
| 512 | FX-ABF | 0.40 | 1236.60 | 267.10 | 1504.05 |
| 512 | ExactHashMap+PStore | 0.30 | 142.10 | 244.00 | 386.95 |

## Detailed phase medians

| ell | index_name | membership_or_retrieval_us | locator_lookup_us | identifier_check_us | pstore_kdf_us | pstore_aead_us | posting_decode_validate_us |
|---|---|---|---|---|---|---|---|
| 32 | Legacy ABF | 547.28 | 0.00 | 212.80 | 57.45 | 164.20 | 30.95 |
| 32 | Bloom+Locator | 520.65 | 34.20 | 0.00 | 58.33 | 166.38 | 31.45 |
| 32 | Cuckoo+Locator | 225.55 | 35.23 | 0.00 | 56.17 | 162.25 | 30.10 |
| 32 | Xor+Locator | 543.62 | 35.25 | 0.00 | 56.42 | 164.12 | 30.95 |
| 32 | FX-ABF | 885.80 | 0.00 | 340.05 | 59.55 | 172.82 | 32.38 |
| 32 | ExactHashMap+PStore | 6.20 | 135.12 | 0.00 | 57.42 | 155.85 | 29.00 |
| 128 | Legacy ABF | 544.35 | 0.00 | 214.03 | 57.88 | 164.35 | 31.00 |
| 128 | Bloom+Locator | 530.75 | 34.65 | 0.00 | 58.67 | 167.62 | 31.60 |
| 128 | Cuckoo+Locator | 228.78 | 35.55 | 0.00 | 56.38 | 163.18 | 30.18 |
| 128 | Xor+Locator | 544.15 | 35.55 | 0.00 | 56.80 | 165.00 | 31.12 |
| 128 | FX-ABF | 888.58 | 0.00 | 340.02 | 59.80 | 174.62 | 32.35 |
| 128 | ExactHashMap+PStore | 6.25 | 136.63 | 0.00 | 57.83 | 156.90 | 29.25 |
| 512 | Legacy ABF | 538.67 | 0.00 | 214.05 | 57.62 | 166.07 | 31.18 |
| 512 | Bloom+Locator | 513.08 | 34.50 | 0.00 | 58.58 | 167.50 | 31.65 |
| 512 | Cuckoo+Locator | 226.57 | 35.38 | 0.00 | 56.25 | 163.28 | 30.12 |
| 512 | Xor+Locator | 539.55 | 35.48 | 0.00 | 56.60 | 164.75 | 31.02 |
| 512 | FX-ABF | 895.08 | 0.00 | 342.60 | 59.70 | 174.65 | 32.33 |
| 512 | ExactHashMap+PStore | 6.25 | 135.80 | 0.00 | 57.52 | 156.97 | 29.27 |

## Logical operation counts at ell=128

Counts are means per query. Non-integer values reflect collision retries, membership-filter short-circuiting, or rare candidate positives across the 30 workloads. Temporary allocations are an explicit-operation proxy, not a CPython allocator trace.

| index_name | query_type | encode_count | sha256_count | dict_lookup_count | array_read_count | xor_count | range_reduce_count | rejection_loop_count | constant_time_compare_count | kdf_count | aead_count | decode_count | temporary_allocation_count |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Legacy ABF | member | 6.008 | 7.008 | 0.000 | 4.000 | 3 | 3.008 | 3.008 | 1 | 1 | 1 | 1 | 21.017 |
| Legacy ABF | nonmember | 4.003 | 5.003 | 0.000 | 3.000 | 3 | 3.003 | 3.003 | 1 | 0 | 0 | 0 | 13.006 |
| Bloom+Locator | member | 11.000 | 11.000 | 1.000 | 9.000 | 0 | 8.000 | 0.000 | 0 | 1 | 1 | 1 | 26.000 |
| Bloom+Locator | nonmember | 2.004 | 2.004 | 0.003 | 2.001 | 0 | 2.001 | 0.000 | 0 | 0 | 0 | 0 | 4.008 |
| Cuckoo+Locator | member | 4.000 | 6.000 | 1.000 | 2.004 | 0 | 2.000 | 0.000 | 0 | 1 | 1 | 1 | 15.000 |
| Cuckoo+Locator | nonmember | 1.000 | 3.000 | 0.000 | 2.000 | 0 | 2.000 | 0.000 | 0 | 0 | 0 | 0 | 5.000 |
| Xor+Locator | member | 6.021 | 7.021 | 1.000 | 4.000 | 3 | 3.021 | 3.021 | 0 | 1 | 1 | 1 | 19.042 |
| Xor+Locator | nonmember | 3.022 | 4.022 | 0.000 | 3.000 | 3 | 3.022 | 3.022 | 0 | 0 | 0 | 0 | 9.044 |
| FX-ABF | member | 7.000 | 8.000 | 0.000 | 4.000 | 3 | 4.000 | 4.000 | 1 | 1 | 1 | 1 | 23.000 |
| FX-ABF | nonmember | 5.000 | 6.000 | 0.000 | 3.000 | 3 | 4.000 | 4.000 | 1 | 0 | 0 | 0 | 15.000 |
| ExactHashMap+PStore | member | 3.000 | 3.000 | 1.000 | 1.000 | 0 | 0.000 | 0.000 | 0 | 1 | 1 | 1 | 10.000 |
| ExactHashMap+PStore | nonmember | 1.000 | 1.000 | 1.000 | 0.000 | 0 | 0.000 | 0.000 | 0 | 0 | 0 | 0 | 2.000 |

## Correctness and interpretation

- Member false negatives: **0**.
- Final false accepts: **0**.
- `ExactHashMap+PStore` is analysis-only and shares Bloom+Locator's locator and encrypted PStore byte-for-byte.
- The full-run integrated-query plot remains a valid system-level measurement of these Python prototypes. It is not, by itself, a pure algorithm-complexity ranking because CPython dictionary probes execute in optimized C while FusePos, rejection loops, segment arithmetic, and XOR orchestration execute mainly as Python bytecode.
- The security-envelope phases are close; the observed ranking is primarily retrieval implementation and required structural work, not different AEAD or KDF backends.
