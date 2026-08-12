# FX anonymous-index component experiment report

## Environment

- Timestamp: `2026-07-28T14:10:36.260035+00:00`
- Git commit: `f2b402afb8776dd9256f268ed5d44fcc5caf1cc4` (dirty=True)
- Python: `3.8.10 (default, Mar 18 2025, 20:04:55) `
- OS: `Linux-6.18.33.1-microsoft-standard-WSL2-x86_64-with-glibc2.29`
- CPU: `Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz`
- Pairing backend: `MNT224`
- CPU affinity: `{'cpu': 0, 'status': 'fixed'}`

## Test configuration

```yaml
mode: standard
master_seed: 20260728
pairing_group: MNT224
filters:
- ABF
- Cuckoo
- Xor
- FX-ABF
f1:
  u:
  - 128
  - 512
  - 2048
  - 8192
  independent_seeds: 10
  warmup_builds: 2
  measured_builds_per_seed: 3
f2:
  ell_scaling:
  - 32
  - 64
  - 128
  - 256
  - 512
  fixed_N_a: 32
  fixed_r_a: 8
  fixed_ell_b: 256
  fixed_N_b: 64
  r_scaling:
  - 4
  - 8
  - 16
  - 32
  - 64
  independent_workloads: 10
  warmup_queries: 10
  measured_queries: 30
f3:
  u: 2048
  member_queries: 10000
  nonmember_queries: 100000
  independent_workloads: 10
bootstrap_resamples: 2000
threads: 1
```

## Build time summary (F1-A, ms)

| filter_name | workload | u | ell | median | ci95_low | ci95_high | count |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ABF | F1-A | 128 | 128 | 9.3425 | 8.8461 | 9.6545 | 30 |
| ABF | F1-A | 512 | 512 | 34.7227 | 34.2813 | 35.5413 | 30 |
| ABF | F1-A | 2048 | 2048 | 144.5651 | 140.6961 | 149.5976 | 30 |
| ABF | F1-A | 8192 | 8192 | 559.2738 | 557.1504 | 574.6659 | 30 |
| Cuckoo | F1-A | 128 | 128 | 5.4844 | 5.1495 | 5.7693 | 30 |
| Cuckoo | F1-A | 512 | 512 | 20.4506 | 20.2722 | 20.8645 | 30 |
| Cuckoo | F1-A | 2048 | 2048 | 85.8208 | 83.8956 | 89.8113 | 30 |
| Cuckoo | F1-A | 8192 | 8192 | 339.2434 | 336.0872 | 343.5307 | 30 |
| FX-ABF | F1-A | 128 | 128 | 57.3543 | 50.8957 | 65.4372 | 30 |
| FX-ABF | F1-A | 512 | 512 | 47.0680 | 42.6551 | 61.9225 | 30 |
| FX-ABF | F1-A | 2048 | 2048 | 171.5582 | 166.2590 | 178.2079 | 30 |
| FX-ABF | F1-A | 8192 | 8192 | 1010.0206 | 837.2390 | 1038.3013 | 30 |
| Xor | F1-A | 128 | 128 | 7.0424 | 6.8402 | 7.4225 | 30 |
| Xor | F1-A | 512 | 512 | 25.3117 | 24.9959 | 25.8845 | 30 |
| Xor | F1-A | 2048 | 2048 | 102.2878 | 100.9106 | 105.7633 | 30 |
| Xor | F1-A | 8192 | 8192 | 419.3190 | 412.8327 | 425.5694 | 30 |

## Integrated index space (F1-A, bytes/token)

| filter_name | workload | u | ell | median | ci95_low | ci95_high | count |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ABF | F1-A | 128 | 128 | 71.1172 | 71.1172 | 71.1172 | 30 |
| ABF | F1-A | 512 | 512 | 71.6543 | 71.6543 | 71.6543 | 30 |
| ABF | F1-A | 2048 | 2048 | 71.5386 | 71.5386 | 71.5386 | 30 |
| ABF | F1-A | 8192 | 8192 | 71.5098 | 71.5098 | 71.5098 | 30 |
| Cuckoo | F1-A | 128 | 128 | 73.7969 | 73.7969 | 73.7969 | 30 |
| Cuckoo | F1-A | 512 | 512 | 74.2012 | 74.2012 | 74.2012 | 30 |
| Cuckoo | F1-A | 2048 | 2048 | 74.0503 | 74.0503 | 74.0503 | 30 |
| Cuckoo | F1-A | 8192 | 8192 | 74.0126 | 74.0126 | 74.0126 | 30 |
| FX-ABF | F1-A | 128 | 128 | 50.1406 | 49.6484 | 50.1406 | 30 |
| FX-ABF | F1-A | 512 | 512 | 49.3633 | 49.3633 | 49.3633 | 30 |
| FX-ABF | F1-A | 2048 | 2048 | 49.0918 | 49.0918 | 49.0918 | 30 |
| FX-ABF | F1-A | 8192 | 8192 | 49.0227 | 49.0227 | 49.0227 | 30 |
| Xor | F1-A | 128 | 128 | 72.2422 | 72.2422 | 72.2422 | 30 |
| Xor | F1-A | 512 | 512 | 72.7617 | 72.7617 | 72.7617 | 30 |
| Xor | F1-A | 2048 | 2048 | 72.6406 | 72.6406 | 72.6406 | 30 |
| Xor | F1-A | 8192 | 8192 | 72.6101 | 72.6101 | 72.6101 | 30 |

## Transform scaling (total, ms)

| filter_name | experiment | ell | r | median | ci95_low | ci95_high | count |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ABF | F2-A | 32 | 8 | 62.8841 | 61.7550 | 67.5198 | 10 |
| ABF | F2-A | 64 | 8 | 62.5584 | 62.1516 | 69.8673 | 10 |
| ABF | F2-A | 128 | 8 | 62.7099 | 61.8051 | 66.1560 | 10 |
| ABF | F2-A | 256 | 8 | 64.1429 | 62.3157 | 67.0632 | 10 |
| ABF | F2-A | 512 | 8 | 62.9866 | 62.5542 | 66.3799 | 10 |
| ABF | F2-B | 256 | 4 | 37.3019 | 36.6093 | 42.2229 | 10 |
| ABF | F2-B | 256 | 8 | 64.0294 | 63.1860 | 72.1662 | 10 |
| ABF | F2-B | 256 | 16 | 119.9352 | 116.7073 | 130.3703 | 10 |
| ABF | F2-B | 256 | 32 | 237.4954 | 226.4276 | 246.4899 | 10 |
| ABF | F2-B | 256 | 64 | 467.2148 | 449.5249 | 475.6673 | 10 |
| Cuckoo | F2-A | 32 | 8 | 62.7281 | 61.4585 | 65.2248 | 10 |
| Cuckoo | F2-A | 64 | 8 | 61.4143 | 61.0217 | 68.0069 | 10 |
| Cuckoo | F2-A | 128 | 8 | 61.9118 | 61.0765 | 63.6750 | 10 |
| Cuckoo | F2-A | 256 | 8 | 66.0397 | 61.2634 | 67.9615 | 10 |
| Cuckoo | F2-A | 512 | 8 | 64.7038 | 61.7006 | 68.9364 | 10 |
| Cuckoo | F2-B | 256 | 4 | 35.8052 | 34.7713 | 38.9865 | 10 |
| Cuckoo | F2-B | 256 | 8 | 61.8949 | 60.9767 | 65.2068 | 10 |
| Cuckoo | F2-B | 256 | 16 | 118.4758 | 116.1437 | 128.2740 | 10 |
| Cuckoo | F2-B | 256 | 32 | 235.8147 | 228.2748 | 246.2548 | 10 |
| Cuckoo | F2-B | 256 | 64 | 472.0763 | 446.0888 | 483.2985 | 10 |
| FX-ABF | F2-A | 32 | 8 | 62.2279 | 61.6316 | 66.0868 | 10 |
| FX-ABF | F2-A | 64 | 8 | 62.3805 | 62.0144 | 64.8714 | 10 |
| FX-ABF | F2-A | 128 | 8 | 64.3561 | 62.5768 | 66.7154 | 10 |
| FX-ABF | F2-A | 256 | 8 | 63.2337 | 62.2774 | 66.5197 | 10 |
| FX-ABF | F2-A | 512 | 8 | 64.1289 | 63.0816 | 74.8748 | 10 |
| FX-ABF | F2-B | 256 | 4 | 38.2333 | 37.0940 | 41.6231 | 10 |
| FX-ABF | F2-B | 256 | 8 | 66.7876 | 63.8954 | 69.4702 | 10 |
| FX-ABF | F2-B | 256 | 16 | 122.6017 | 118.9459 | 125.3464 | 10 |
| FX-ABF | F2-B | 256 | 32 | 234.1445 | 227.3283 | 239.9174 | 10 |
| FX-ABF | F2-B | 256 | 64 | 473.2996 | 443.6126 | 498.6581 | 10 |
| Xor | F2-A | 32 | 8 | 61.8262 | 61.1060 | 64.8347 | 10 |
| Xor | F2-A | 64 | 8 | 61.8832 | 61.4278 | 65.3560 | 10 |
| Xor | F2-A | 128 | 8 | 62.0721 | 61.4898 | 64.6707 | 10 |
| Xor | F2-A | 256 | 8 | 65.2151 | 61.9616 | 68.0416 | 10 |
| Xor | F2-A | 512 | 8 | 63.9549 | 62.2007 | 68.0340 | 10 |
| Xor | F2-B | 256 | 4 | 36.5425 | 35.2691 | 39.0138 | 10 |
| Xor | F2-B | 256 | 8 | 63.8517 | 62.3120 | 65.8311 | 10 |
| Xor | F2-B | 256 | 16 | 122.2067 | 115.8984 | 124.5170 | 10 |
| Xor | F2-B | 256 | 32 | 239.0354 | 230.4367 | 249.2439 | 10 |
| Xor | F2-B | 256 | 64 | 470.9924 | 445.4752 | 496.5478 | 10 |

## Correctness summary

| filter_name | u | median | ci95_low | ci95_high | count |
| --- | --- | --- | --- | --- | --- |
| ABF | 2048 | 0.0000 | 0.0000 | 0.0000 | 10 |
| Cuckoo | 2048 | 0.0000 | 0.0000 | 0.0000 | 10 |
| FX-ABF | 2048 | 0.0000 | 0.0000 | 0.0000 | 10 |
| Xor | 2048 | 0.0000 | 0.0000 | 0.0000 | 10 |

| filter_name | u | median | ci95_low | ci95_high | count |
| --- | --- | --- | --- | --- | --- |
| ABF | 2048 | 0.0000 | 0.0000 | 0.0000 | 10 |
| Cuckoo | 2048 | 0.0000 | 0.0000 | 0.0000 | 10 |
| FX-ABF | 2048 | 0.0000 | 0.0000 | 0.0000 | 10 |
| Xor | 2048 | 0.0000 | 0.0000 | 0.0000 | 10 |

## Build failures and retries

Measured build failures: **0**.
Retry and resize statistics are retained in raw F1 and its summary.

## Anomalies

Validation status: **PASS**. No validation errors were found.

## Preliminary observations

The tables report observed medians and bootstrap intervals without assuming that FX-ABF must be fastest. Membership-filter space is interpreted only through the integrated index metric, which includes locator and authenticated PStore bytes. Core Transform measurements are an ABE/pairing baseline, not evidence for filter speed; filter effects are assessed through index-query and total-Transform time.
