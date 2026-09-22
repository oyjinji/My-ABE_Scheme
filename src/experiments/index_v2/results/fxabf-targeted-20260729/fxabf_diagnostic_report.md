# FX-ABF targeted Build diagnostic report

Status: **PASS**

## ABF baseline audit

The current compatibility class `ABFIndex` is an ordinary k-hash Bloom membership bitmap followed by an SHA-256 exact locator and the common encrypted PStore. It is now displayed as `Bloom+Locator`. It is not the legacy greedy XOR retrieval ABF in `fx_exp/filters/original_abf.py`; no traditional ABF comparison is claimed.

## Code-level root cause

The pre-fix profile held segment length at 64. The segment count therefore grew from 167 to 333 when u doubled. Each edge was confined to one of many local three-segment windows, so the probability that every local region peeled fell from 38.2% to 14.1% per attempt. Attempts and resize long tails, rather than a uniform fourfold cost per attempt, produced the wide CI and median jump.

The old Build also computed all FusePos values twice per attempt: one timed pre-pass and then again while constructing the hypergraph. The fix generates edges once and uses degree plus XOR-of-edge-id arrays with a deque. PStore was built once before attempts; it was not repeated, but has been moved after the successful seed as required. Values/checks remain computed once outside retries.

No `list.pop(0)`, `insert(0)`, `list.remove`, or `list.index` was present. The old adjacency scan was aggregate linear, not O(n^2), but it has been replaced by direct XOR edge recovery. Range reduction uses 64-bit rejection sampling and the base plus three position lanes have separate domain indices. Three-position collisions were zero.

The slow behavior was not stable across all seeds (one-attempt u=16384 builds were about 1.35 seconds while long-tail builds exceeded 20 seconds), so the rule requiring cProfile only for a stable uniform fourfold slowdown did not trigger.

## Before/after Build summary

| phase | u | build_median_ms | build_mean_ms | build_p95_ms | attempts_median | attempts_mean | attempts_max | resize_rate | position_median_ms | peeling_median_ms | pstore_median_ms | residual_median_ms |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| after | 8192 | 551.4645 | 559.9268 | 594.7232 | 1.0000 | 1.0400 | 2 | 0.0000 | 201.0219 | 6.9158 | 263.3033 | 2.1787 |
| after | 16384 | 1116.7021 | 1135.1723 | 1181.8816 | 1.0000 | 1.0400 | 2 | 0.0000 | 408.3308 | 14.5171 | 537.5338 | 4.2364 |
| before | 8192 | 1024.7809 | 1272.0399 | 2599.3670 | 2.0000 | 2.6200 | 8 | 0.0000 | 662.4767 | 18.0182 | 273.2734 | 62.6074 |
| before | 16384 | 4151.5633 | 5687.1115 | 14808.2448 | 5.0000 | 7.0800 | 30 | 0.3200 | 3295.9417 | 114.7434 | 540.8153 | 124.6712 |

## FusePos and degree distribution

| phase | u | peeling_success_rate | segment_length | segment_count | tail_length | min_occupancy | max_occupancy | occupancy_cv_median | position_collisions | degree_0_median | degree_1_median | degree_2_median | degree_3plus_median |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| after | 8192 | 0.9615 | 512 | 21 | 410 | 388 | 1404 | 0.2329 | 0 | 1252.0000 | 2416.5000 | 2638.5000 | 4344.5000 |
| after | 16384 | 0.9615 | 1024 | 21 | 820 | 801 | 2723 | 0.2334 | 0 | 2504.0000 | 4832.5000 | 5303.5000 | 8669.0000 |
| before | 8192 | 0.3817 | 64 | 167 | 26 | 33 | 195 | 0.1147 | 0 | 1075.0000 | 2443.0000 | 2805.0000 | 4332.0000 |
| before | 16384 | 0.1412 | 64 | 333,360,389,420 | 13,17,28,52 | 27 | 204 | 0.1009 | 0 | 2168.5000 | 4913.5000 | 5657.0000 | 8635.0000 |

## Timing accounting

Component sum includes validation/layout/payload work in the fixed implementation, all attempt position and peeling time, successful assignment, and the single PStore build. `retry_ms` is a subset for failed attempts and is never added to the component sum again. Every residual is within `max(10 ms, 15% of build_total)`; the production F1 validator applies the stricter 10% limit to new runs.

## Validation

- 50 seeds exist for every before/after size.
- PStore build count is exactly one for every build.
- Member false negatives are zero.
- FusePos collisions and edge-accounting mismatches are zero.
- Fixed runs have no resize and pass timing-residual validation.

## Parameter recommendation

Keep `c_FX=1.30`, `Rmax=8`, and `gamma=1.08` at the existing fallback values. With adaptive segment lengths 512 and 1024, observed peeling success is 96.15% at both sizes and no build resized. Raising c_FX would impose permanent space cost; lowering Rmax or changing gamma would only alter rare fallback behavior and does not address the identified fixed-segment root cause.
