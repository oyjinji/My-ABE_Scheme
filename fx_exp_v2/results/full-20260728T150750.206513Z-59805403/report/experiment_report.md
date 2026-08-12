# FX anonymous-index component experiment report

## Environment

- Timestamp: `2026-07-28T15:07:50.232162+00:00`
- Git commit: `f2b402afb8776dd9256f268ed5d44fcc5caf1cc4` (dirty=True)
- Python: `3.8.10 (default, Mar 18 2025, 20:04:55) `
- OS: `Linux-6.18.33.1-microsoft-standard-WSL2-x86_64-with-glibc2.29`
- CPU: `Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz`
- Pairing backend: `MNT224`
- CPU affinity: `{'cpu': 0, 'status': 'fixed'}`

## Test configuration

```yaml
mode: full
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
  - 16384
  independent_seeds: 20
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
  independent_workloads: 20
  warmup_queries: 10
  measured_queries: 30
f3:
  u: 4096
  member_queries: 20000
  nonmember_queries: 200000
  independent_workloads: 20
bootstrap_resamples: 4000
threads: 1
```

## Build time summary (F1-A, ms)

| filter_name | workload | u | ell | median | ci95_low | ci95_high | count |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ABF | F1-A | 128 | 128 | 9.2566 | 9.1231 | 9.4767 | 60 |
| ABF | F1-A | 512 | 512 | 35.4236 | 34.5439 | 37.0378 | 60 |
| ABF | F1-A | 2048 | 2048 | 142.9471 | 141.2296 | 145.1649 | 60 |
| ABF | F1-A | 8192 | 8192 | 537.1366 | 532.2202 | 541.7754 | 60 |
| ABF | F1-A | 16384 | 16384 | 1059.9300 | 1057.4816 | 1063.0879 | 60 |
| Cuckoo | F1-A | 128 | 128 | 5.6074 | 5.4767 | 5.7555 | 60 |
| Cuckoo | F1-A | 512 | 512 | 21.7104 | 20.6618 | 22.4108 | 60 |
| Cuckoo | F1-A | 2048 | 2048 | 85.7640 | 83.1616 | 89.4895 | 60 |
| Cuckoo | F1-A | 8192 | 8192 | 324.6793 | 320.7565 | 329.0415 | 60 |
| Cuckoo | F1-A | 16384 | 16384 | 642.7029 | 640.8632 | 645.0167 | 60 |
| FX-ABF | F1-A | 128 | 128 | 58.0389 | 54.5615 | 65.9092 | 60 |
| FX-ABF | F1-A | 512 | 512 | 45.1452 | 44.2611 | 49.0098 | 60 |
| FX-ABF | F1-A | 2048 | 2048 | 174.6534 | 169.7280 | 209.9621 | 60 |
| FX-ABF | F1-A | 8192 | 8192 | 952.7135 | 933.3806 | 1056.4848 | 60 |
| FX-ABF | F1-A | 16384 | 16384 | 3832.1515 | 2876.6246 | 5711.2654 | 60 |
| Xor | F1-A | 128 | 128 | 6.9660 | 6.7343 | 7.1711 | 60 |
| Xor | F1-A | 512 | 512 | 27.4531 | 27.0045 | 27.7874 | 60 |
| Xor | F1-A | 2048 | 2048 | 104.9981 | 102.4002 | 108.1958 | 60 |
| Xor | F1-A | 8192 | 8192 | 400.2407 | 394.9308 | 402.2283 | 60 |
| Xor | F1-A | 16384 | 16384 | 796.1218 | 794.0485 | 797.7831 | 60 |

## Integrated index space (F1-A, bytes/token)

| filter_name | workload | u | ell | median | ci95_low | ci95_high | count |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ABF | F1-A | 128 | 128 | 71.1172 | 71.1172 | 71.1172 | 60 |
| ABF | F1-A | 512 | 512 | 71.6543 | 71.6543 | 71.6543 | 60 |
| ABF | F1-A | 2048 | 2048 | 71.5386 | 71.5386 | 71.5386 | 60 |
| ABF | F1-A | 8192 | 8192 | 71.5098 | 71.5098 | 71.5098 | 60 |
| ABF | F1-A | 16384 | 16384 | 71.5049 | 71.5049 | 71.5049 | 60 |
| Cuckoo | F1-A | 128 | 128 | 73.7969 | 73.7969 | 73.7969 | 60 |
| Cuckoo | F1-A | 512 | 512 | 74.2012 | 74.2012 | 74.2012 | 60 |
| Cuckoo | F1-A | 2048 | 2048 | 74.0503 | 74.0503 | 74.0503 | 60 |
| Cuckoo | F1-A | 8192 | 8192 | 74.0126 | 74.0126 | 74.0126 | 60 |
| Cuckoo | F1-A | 16384 | 16384 | 74.0063 | 74.0063 | 74.0063 | 60 |
| FX-ABF | F1-A | 128 | 128 | 50.1406 | 50.1406 | 50.1406 | 60 |
| FX-ABF | F1-A | 512 | 512 | 49.3633 | 49.3633 | 49.3633 | 60 |
| FX-ABF | F1-A | 2048 | 2048 | 49.0918 | 49.0918 | 49.0918 | 60 |
| FX-ABF | F1-A | 8192 | 8192 | 49.0227 | 49.0227 | 49.0227 | 60 |
| FX-ABF | F1-A | 16384 | 16384 | 49.0117 | 49.0117 | 49.0117 | 60 |
| Xor | F1-A | 128 | 128 | 72.2422 | 72.2422 | 72.2422 | 60 |
| Xor | F1-A | 512 | 512 | 72.7617 | 72.7617 | 72.7617 | 60 |
| Xor | F1-A | 2048 | 2048 | 72.6406 | 72.6406 | 72.6406 | 60 |
| Xor | F1-A | 8192 | 8192 | 72.6101 | 72.6101 | 72.6101 | 60 |
| Xor | F1-A | 16384 | 16384 | 72.6051 | 72.6051 | 72.6051 | 60 |

## Transform scaling (total, ms)

| filter_name | experiment | ell | r | median | ci95_low | ci95_high | count |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ABF | F2-A | 32 | 8 | 59.6234 | 59.4573 | 59.8429 | 20 |
| ABF | F2-A | 64 | 8 | 59.7758 | 59.7186 | 59.8840 | 20 |
| ABF | F2-A | 128 | 8 | 60.2660 | 59.8347 | 60.5098 | 20 |
| ABF | F2-A | 256 | 8 | 60.1373 | 59.9948 | 60.3681 | 20 |
| ABF | F2-A | 512 | 8 | 60.2269 | 59.9892 | 60.6084 | 20 |
| ABF | F2-B | 256 | 4 | 35.2630 | 35.1892 | 35.4869 | 20 |
| ABF | F2-B | 256 | 8 | 61.2328 | 60.8752 | 61.5576 | 20 |
| ABF | F2-B | 256 | 16 | 113.1777 | 112.6163 | 113.4486 | 20 |
| ABF | F2-B | 256 | 32 | 217.2127 | 216.3089 | 217.7513 | 20 |
| ABF | F2-B | 256 | 64 | 424.5551 | 423.7178 | 426.7304 | 20 |
| Cuckoo | F2-A | 32 | 8 | 58.7934 | 58.6451 | 58.9742 | 20 |
| Cuckoo | F2-A | 64 | 8 | 58.9873 | 58.7058 | 59.2638 | 20 |
| Cuckoo | F2-A | 128 | 8 | 59.2890 | 58.9410 | 59.7044 | 20 |
| Cuckoo | F2-A | 256 | 8 | 59.3213 | 59.1128 | 59.5077 | 20 |
| Cuckoo | F2-A | 512 | 8 | 59.4954 | 59.2822 | 59.7135 | 20 |
| Cuckoo | F2-B | 256 | 4 | 33.4757 | 33.3930 | 33.6664 | 20 |
| Cuckoo | F2-B | 256 | 8 | 59.4771 | 59.3351 | 59.6282 | 20 |
| Cuckoo | F2-B | 256 | 16 | 111.5590 | 111.0486 | 111.7805 | 20 |
| Cuckoo | F2-B | 256 | 32 | 215.1860 | 214.6680 | 215.7578 | 20 |
| Cuckoo | F2-B | 256 | 64 | 423.5594 | 422.6515 | 423.8497 | 20 |
| FX-ABF | F2-A | 32 | 8 | 59.9693 | 59.6285 | 60.1692 | 20 |
| FX-ABF | F2-A | 64 | 8 | 59.9581 | 59.7778 | 60.2449 | 20 |
| FX-ABF | F2-A | 128 | 8 | 60.1060 | 59.9365 | 60.3081 | 20 |
| FX-ABF | F2-A | 256 | 8 | 60.5471 | 60.2616 | 60.7190 | 20 |
| FX-ABF | F2-A | 512 | 8 | 60.8949 | 60.6366 | 61.0975 | 20 |
| FX-ABF | F2-B | 256 | 4 | 35.9378 | 35.7995 | 36.1298 | 20 |
| FX-ABF | F2-B | 256 | 8 | 61.9063 | 61.6537 | 62.1007 | 20 |
| FX-ABF | F2-B | 256 | 16 | 113.6929 | 113.4567 | 114.1269 | 20 |
| FX-ABF | F2-B | 256 | 32 | 217.4518 | 216.9542 | 218.2646 | 20 |
| FX-ABF | F2-B | 256 | 64 | 424.5974 | 423.2345 | 425.9811 | 20 |
| Xor | F2-A | 32 | 8 | 59.2236 | 58.9106 | 59.5094 | 20 |
| Xor | F2-A | 64 | 8 | 59.2679 | 59.0944 | 59.8872 | 20 |
| Xor | F2-A | 128 | 8 | 59.6762 | 59.3090 | 59.9447 | 20 |
| Xor | F2-A | 256 | 8 | 59.6465 | 59.4590 | 59.8431 | 20 |
| Xor | F2-A | 512 | 8 | 59.7699 | 59.5784 | 59.8933 | 20 |
| Xor | F2-B | 256 | 4 | 33.9533 | 33.8864 | 34.0833 | 20 |
| Xor | F2-B | 256 | 8 | 59.9140 | 59.7067 | 60.1576 | 20 |
| Xor | F2-B | 256 | 16 | 112.1278 | 111.9740 | 112.4934 | 20 |
| Xor | F2-B | 256 | 32 | 215.7606 | 214.6920 | 216.1935 | 20 |
| Xor | F2-B | 256 | 64 | 423.3207 | 421.6729 | 424.8022 | 20 |

## Correctness summary

| filter_name | u | median | ci95_low | ci95_high | count |
| --- | --- | --- | --- | --- | --- |
| ABF | 4096 | 0.0000 | 0.0000 | 0.0000 | 20 |
| Cuckoo | 4096 | 0.0000 | 0.0000 | 0.0000 | 20 |
| FX-ABF | 4096 | 0.0000 | 0.0000 | 0.0000 | 20 |
| Xor | 4096 | 0.0000 | 0.0000 | 0.0000 | 20 |

| filter_name | u | median | ci95_low | ci95_high | count |
| --- | --- | --- | --- | --- | --- |
| ABF | 4096 | 0.0000 | 0.0000 | 0.0000 | 20 |
| Cuckoo | 4096 | 0.0000 | 0.0000 | 0.0000 | 20 |
| FX-ABF | 4096 | 0.0000 | 0.0000 | 0.0000 | 20 |
| Xor | 4096 | 0.0000 | 0.0000 | 0.0000 | 20 |

## Build failures and retries

Measured build failures: **0**.
Retry and resize statistics are retained in raw F1 and its summary.

## Anomalies

Validation status: **PASS**. No validation errors were found.

## Preliminary observations

The tables report observed medians and bootstrap intervals without assuming that FX-ABF must be fastest. Membership-filter space is interpreted only through the integrated index metric, which includes locator and authenticated PStore bytes. Core Transform measurements are an ABE/pairing baseline, not evidence for filter speed; filter effects are assessed through index-query and total-Transform time.
