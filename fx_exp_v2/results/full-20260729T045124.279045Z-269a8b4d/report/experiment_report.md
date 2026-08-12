# FX anonymous-index component experiment report

## Environment

- Timestamp: `2026-07-29T04:51:24.295062+00:00`
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
- Legacy ABF
- Bloom+Locator
- Cuckoo+Locator
- Xor+Locator
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
| Bloom+Locator | F1-A | 128 | 128 | 8.9085 | 8.5446 | 9.3430 | 60 |
| Bloom+Locator | F1-A | 512 | 512 | 33.1404 | 32.9321 | 33.3019 | 60 |
| Bloom+Locator | F1-A | 2048 | 2048 | 132.2686 | 131.9384 | 133.3916 | 60 |
| Bloom+Locator | F1-A | 8192 | 8192 | 532.0316 | 529.4306 | 533.7217 | 60 |
| Bloom+Locator | F1-A | 16384 | 16384 | 1067.7707 | 1066.5139 | 1070.7069 | 60 |
| Cuckoo+Locator | F1-A | 128 | 128 | 5.2962 | 5.0356 | 5.4232 | 60 |
| Cuckoo+Locator | F1-A | 512 | 512 | 19.8611 | 19.6769 | 20.0833 | 60 |
| Cuckoo+Locator | F1-A | 2048 | 2048 | 78.8654 | 78.4885 | 79.3349 | 60 |
| Cuckoo+Locator | F1-A | 8192 | 8192 | 321.4077 | 319.3129 | 323.5625 | 60 |
| Cuckoo+Locator | F1-A | 16384 | 16384 | 644.1204 | 642.7712 | 645.7899 | 60 |
| FX-ABF | F1-A | 128 | 128 | 9.8265 | 9.1253 | 10.8091 | 60 |
| FX-ABF | F1-A | 512 | 512 | 45.7678 | 43.2669 | 60.4009 | 60 |
| FX-ABF | F1-A | 2048 | 2048 | 126.8790 | 125.5942 | 128.3232 | 60 |
| FX-ABF | F1-A | 8192 | 8192 | 513.2238 | 510.4354 | 515.5500 | 60 |
| FX-ABF | F1-A | 16384 | 16384 | 1031.7639 | 1028.1185 | 1033.3425 | 60 |
| Legacy ABF | F1-A | 128 | 128 | 92.1990 | 86.3537 | 95.9573 | 60 |
| Legacy ABF | F1-A | 512 | 512 | 406.2683 | 393.1420 | 424.1625 | 60 |
| Legacy ABF | F1-A | 2048 | 2048 | 1891.7971 | 1857.3982 | 1940.3341 | 60 |
| Legacy ABF | F1-A | 8192 | 8192 | 8482.3261 | 8182.4155 | 8851.2464 | 60 |
| Legacy ABF | F1-A | 16384 | 16384 | 17906.9532 | 17496.2008 | 18409.1532 | 60 |
| Xor+Locator | F1-A | 128 | 128 | 6.6444 | 6.2750 | 7.2040 | 60 |
| Xor+Locator | F1-A | 512 | 512 | 24.2090 | 23.9587 | 24.3830 | 60 |
| Xor+Locator | F1-A | 2048 | 2048 | 96.4836 | 96.2043 | 97.0209 | 60 |
| Xor+Locator | F1-A | 8192 | 8192 | 393.0394 | 391.4973 | 394.4757 | 60 |
| Xor+Locator | F1-A | 16384 | 16384 | 801.2825 | 798.8146 | 803.1129 | 60 |

## Integrated build phase breakdown (F1-A)

At `u=16384`, milliseconds; structure is the wall-time remainder after the separately measured locator, PStore, and metadata phases.

| filter_name | structure_build_ms | locator_build_ms | pstore_build_ms | metadata_build_ms | integrated_build_ms |
| --- | --- | --- | --- | --- | --- |
| Bloom+Locator | 515.8111 | 48.5881 | 502.5501 | 0.0149 | 1067.7707 |
| Cuckoo+Locator | 93.4217 | 48.1917 | 500.6132 | 0.0146 | 644.1204 |
| FX-ABF | 534.5454 | 0.0000 | 496.0367 | 0.0178 | 1031.7639 |
| Legacy ABF | 17394.3219 | 0.0000 | 516.8224 | 0.0188 | 17906.9532 |
| Xor+Locator | 247.4381 | 48.0985 | 503.7319 | 0.0303 | 801.2825 |

## Integrated index space (F1-A, bytes/token)

| filter_name | workload | u | ell | median | ci95_low | ci95_high | count |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Bloom+Locator | F1-A | 128 | 128 | 71.1953 | 71.1953 | 71.1953 | 60 |
| Bloom+Locator | F1-A | 512 | 512 | 71.6738 | 71.6738 | 71.6738 | 60 |
| Bloom+Locator | F1-A | 2048 | 2048 | 71.5435 | 71.5435 | 71.5435 | 60 |
| Bloom+Locator | F1-A | 8192 | 8192 | 71.5110 | 71.5110 | 71.5110 | 60 |
| Bloom+Locator | F1-A | 16384 | 16384 | 71.5055 | 71.5055 | 71.5055 | 60 |
| Cuckoo+Locator | F1-A | 128 | 128 | 73.8594 | 73.8594 | 73.8594 | 60 |
| Cuckoo+Locator | F1-A | 512 | 512 | 74.2168 | 74.2168 | 74.2168 | 60 |
| Cuckoo+Locator | F1-A | 2048 | 2048 | 74.0542 | 74.0542 | 74.0542 | 60 |
| Cuckoo+Locator | F1-A | 8192 | 8192 | 74.0135 | 74.0135 | 74.0135 | 60 |
| Cuckoo+Locator | F1-A | 16384 | 16384 | 74.0068 | 74.0068 | 74.0068 | 60 |
| FX-ABF | F1-A | 128 | 128 | 49.2266 | 49.2266 | 49.2266 | 60 |
| FX-ABF | F1-A | 512 | 512 | 49.3809 | 49.3809 | 49.3809 | 60 |
| FX-ABF | F1-A | 2048 | 2048 | 49.0967 | 49.0967 | 49.0967 | 60 |
| FX-ABF | F1-A | 8192 | 8192 | 49.0239 | 49.0239 | 49.0239 | 60 |
| FX-ABF | F1-A | 16384 | 16384 | 49.0122 | 49.0122 | 49.0122 | 60 |
| Legacy ABF | F1-A | 128 | 128 | 89.4062 | 84.6250 | 89.4062 | 60 |
| Legacy ABF | F1-A | 512 | 512 | 128.4941 | 128.4941 | 137.7129 | 60 |
| Legacy ABF | F1-A | 2048 | 2048 | 199.0503 | 184.2310 | 199.0503 | 60 |
| Legacy ABF | F1-A | 8192 | 8192 | 298.3069 | 298.3069 | 324.5361 | 60 |
| Legacy ABF | F1-A | 16384 | 16384 | 385.0361 | 353.3064 | 385.0361 | 60 |
| Xor+Locator | F1-A | 128 | 128 | 72.3047 | 72.3047 | 72.3047 | 60 |
| Xor+Locator | F1-A | 512 | 512 | 72.7773 | 72.7773 | 72.7773 | 60 |
| Xor+Locator | F1-A | 2048 | 2048 | 72.6445 | 72.6445 | 72.6445 | 60 |
| Xor+Locator | F1-A | 8192 | 8192 | 72.6111 | 72.6111 | 72.6111 | 60 |
| Xor+Locator | F1-A | 16384 | 16384 | 72.6056 | 72.6056 | 72.6056 | 60 |

## Integrated index query (F2-A, ms; excludes pairing)

| filter_name | experiment | ell | r | median | ci95_low | ci95_high | count |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Bloom+Locator | F2-A | 32 | 8 | 1.5107 | 1.4849 | 1.5514 | 20 |
| Bloom+Locator | F2-A | 64 | 8 | 1.5883 | 1.5220 | 1.6835 | 20 |
| Bloom+Locator | F2-A | 128 | 8 | 1.6266 | 1.5720 | 1.6876 | 20 |
| Bloom+Locator | F2-A | 256 | 8 | 1.6989 | 1.6531 | 1.7911 | 20 |
| Bloom+Locator | F2-A | 512 | 8 | 1.8824 | 1.7821 | 1.9350 | 20 |
| Cuckoo+Locator | F2-A | 32 | 8 | 0.6632 | 0.6366 | 0.6746 | 20 |
| Cuckoo+Locator | F2-A | 64 | 8 | 0.6933 | 0.6757 | 0.7297 | 20 |
| Cuckoo+Locator | F2-A | 128 | 8 | 0.7493 | 0.7193 | 0.7861 | 20 |
| Cuckoo+Locator | F2-A | 256 | 8 | 0.8202 | 0.7907 | 0.8449 | 20 |
| Cuckoo+Locator | F2-A | 512 | 8 | 0.9894 | 0.9610 | 1.0219 | 20 |
| FX-ABF | F2-A | 32 | 8 | 1.7118 | 1.6451 | 1.7974 | 20 |
| FX-ABF | F2-A | 64 | 8 | 1.8724 | 1.7819 | 1.9344 | 20 |
| FX-ABF | F2-A | 128 | 8 | 2.0405 | 1.8933 | 2.1473 | 20 |
| FX-ABF | F2-A | 256 | 8 | 2.2674 | 2.2011 | 2.3198 | 20 |
| FX-ABF | F2-A | 512 | 8 | 2.7747 | 2.6133 | 2.9370 | 20 |
| Legacy ABF | F2-A | 32 | 8 | 1.1547 | 1.1403 | 1.3101 | 20 |
| Legacy ABF | F2-A | 64 | 8 | 1.2720 | 1.2149 | 1.3306 | 20 |
| Legacy ABF | F2-A | 128 | 8 | 1.3936 | 1.3350 | 1.4710 | 20 |
| Legacy ABF | F2-A | 256 | 8 | 1.6430 | 1.5717 | 1.6751 | 20 |
| Legacy ABF | F2-A | 512 | 8 | 2.1546 | 2.0737 | 2.2058 | 20 |
| Xor+Locator | F2-A | 32 | 8 | 0.9527 | 0.9123 | 0.9764 | 20 |
| Xor+Locator | F2-A | 64 | 8 | 0.9786 | 0.9488 | 1.0153 | 20 |
| Xor+Locator | F2-A | 128 | 8 | 0.9996 | 0.9908 | 1.0403 | 20 |
| Xor+Locator | F2-A | 256 | 8 | 1.1221 | 1.0874 | 1.1461 | 20 |
| Xor+Locator | F2-A | 512 | 8 | 1.2762 | 1.2276 | 1.3216 | 20 |

## Supplemental Transform scaling (total, ms)

| filter_name | experiment | ell | r | median | ci95_low | ci95_high | count |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Bloom+Locator | F2-A | 32 | 8 | 62.8581 | 62.3007 | 65.8527 | 20 |
| Bloom+Locator | F2-A | 64 | 8 | 65.3003 | 62.3092 | 68.1031 | 20 |
| Bloom+Locator | F2-A | 128 | 8 | 64.1526 | 62.6320 | 67.3625 | 20 |
| Bloom+Locator | F2-A | 256 | 8 | 64.4867 | 62.7598 | 67.2444 | 20 |
| Bloom+Locator | F2-A | 512 | 8 | 63.9382 | 62.4509 | 65.0502 | 20 |
| Bloom+Locator | F2-B | 256 | 4 | 37.5415 | 36.4718 | 38.7435 | 20 |
| Bloom+Locator | F2-B | 256 | 8 | 64.0145 | 63.3806 | 65.7833 | 20 |
| Bloom+Locator | F2-B | 256 | 16 | 119.5905 | 117.8431 | 125.1900 | 20 |
| Bloom+Locator | F2-B | 256 | 32 | 227.5399 | 225.9932 | 240.9470 | 20 |
| Bloom+Locator | F2-B | 256 | 64 | 454.9907 | 445.3820 | 463.0103 | 20 |
| Cuckoo+Locator | F2-A | 32 | 8 | 63.8608 | 61.0789 | 65.5351 | 20 |
| Cuckoo+Locator | F2-A | 64 | 8 | 63.2243 | 61.5890 | 66.7600 | 20 |
| Cuckoo+Locator | F2-A | 128 | 8 | 63.8112 | 61.5682 | 66.7001 | 20 |
| Cuckoo+Locator | F2-A | 256 | 8 | 62.5229 | 61.4671 | 64.6690 | 20 |
| Cuckoo+Locator | F2-A | 512 | 8 | 62.9912 | 62.1856 | 66.3151 | 20 |
| Cuckoo+Locator | F2-B | 256 | 4 | 35.8101 | 35.1148 | 37.4435 | 20 |
| Cuckoo+Locator | F2-B | 256 | 8 | 62.5075 | 61.5988 | 64.5643 | 20 |
| Cuckoo+Locator | F2-B | 256 | 16 | 121.5690 | 116.4645 | 129.9675 | 20 |
| Cuckoo+Locator | F2-B | 256 | 32 | 236.9431 | 224.6374 | 241.9279 | 20 |
| Cuckoo+Locator | F2-B | 256 | 64 | 455.0792 | 440.8069 | 464.4596 | 20 |
| FX-ABF | F2-A | 32 | 8 | 63.1425 | 62.1540 | 65.8500 | 20 |
| FX-ABF | F2-A | 64 | 8 | 65.2388 | 62.4844 | 67.7422 | 20 |
| FX-ABF | F2-A | 128 | 8 | 64.8875 | 63.0847 | 68.2764 | 20 |
| FX-ABF | F2-A | 256 | 8 | 65.4651 | 62.8944 | 68.4046 | 20 |
| FX-ABF | F2-A | 512 | 8 | 66.4665 | 63.5864 | 69.5759 | 20 |
| FX-ABF | F2-B | 256 | 4 | 38.4445 | 37.8675 | 40.0799 | 20 |
| FX-ABF | F2-B | 256 | 8 | 66.9780 | 64.9857 | 72.7095 | 20 |
| FX-ABF | F2-B | 256 | 16 | 121.2756 | 118.2448 | 122.7587 | 20 |
| FX-ABF | F2-B | 256 | 32 | 231.7725 | 227.1210 | 240.4588 | 20 |
| FX-ABF | F2-B | 256 | 64 | 452.6191 | 441.9412 | 471.8347 | 20 |
| Legacy ABF | F2-A | 32 | 8 | 63.5483 | 61.8823 | 65.2689 | 20 |
| Legacy ABF | F2-A | 64 | 8 | 64.0219 | 61.8268 | 66.4847 | 20 |
| Legacy ABF | F2-A | 128 | 8 | 64.1386 | 62.3720 | 66.7276 | 20 |
| Legacy ABF | F2-A | 256 | 8 | 63.9736 | 62.5917 | 65.4209 | 20 |
| Legacy ABF | F2-A | 512 | 8 | 64.2245 | 62.6448 | 66.1678 | 20 |
| Legacy ABF | F2-B | 256 | 4 | 37.6800 | 37.0564 | 40.0183 | 20 |
| Legacy ABF | F2-B | 256 | 8 | 64.6750 | 63.4664 | 68.4680 | 20 |
| Legacy ABF | F2-B | 256 | 16 | 119.5828 | 117.4383 | 126.8347 | 20 |
| Legacy ABF | F2-B | 256 | 32 | 233.8462 | 226.0465 | 239.4419 | 20 |
| Legacy ABF | F2-B | 256 | 64 | 453.6936 | 443.6517 | 465.1950 | 20 |
| Xor+Locator | F2-A | 32 | 8 | 62.3735 | 61.6208 | 66.0830 | 20 |
| Xor+Locator | F2-A | 64 | 8 | 64.4923 | 62.2979 | 65.7697 | 20 |
| Xor+Locator | F2-A | 128 | 8 | 64.6283 | 63.2038 | 66.1700 | 20 |
| Xor+Locator | F2-A | 256 | 8 | 62.5311 | 61.6769 | 65.6088 | 20 |
| Xor+Locator | F2-A | 512 | 8 | 64.5829 | 62.3708 | 67.8068 | 20 |
| Xor+Locator | F2-B | 256 | 4 | 35.9723 | 35.4069 | 38.2806 | 20 |
| Xor+Locator | F2-B | 256 | 8 | 63.1386 | 62.3796 | 67.5737 | 20 |
| Xor+Locator | F2-B | 256 | 16 | 118.9342 | 116.2303 | 122.1536 | 20 |
| Xor+Locator | F2-B | 256 | 32 | 230.3017 | 226.0418 | 242.2292 | 20 |
| Xor+Locator | F2-B | 256 | 64 | 455.9213 | 443.8472 | 471.4818 | 20 |

## Correctness summary

| filter_name | u | median | ci95_low | ci95_high | count |
| --- | --- | --- | --- | --- | --- |
| Bloom+Locator | 4096 | 0.0000 | 0.0000 | 0.0000 | 20 |
| Cuckoo+Locator | 4096 | 0.0000 | 0.0000 | 0.0000 | 20 |
| FX-ABF | 4096 | 0.0000 | 0.0000 | 0.0000 | 20 |
| Legacy ABF | 4096 | 0.0000 | 0.0000 | 0.0000 | 20 |
| Xor+Locator | 4096 | 0.0000 | 0.0000 | 0.0000 | 20 |

| filter_name | u | median | ci95_low | ci95_high | count |
| --- | --- | --- | --- | --- | --- |
| Bloom+Locator | 4096 | 0.0000 | 0.0000 | 0.0000 | 20 |
| Cuckoo+Locator | 4096 | 0.0000 | 0.0000 | 0.0000 | 20 |
| FX-ABF | 4096 | 0.0000 | 0.0000 | 0.0000 | 20 |
| Legacy ABF | 4096 | 0.0000 | 0.0000 | 0.0000 | 20 |
| Xor+Locator | 4096 | 0.0000 | 0.0000 | 0.0000 | 20 |

## Build failures and retries

Measured build failures: **0**.
Retry and resize statistics are retained in raw F1 and its summary.

## Anomalies

Validation status: **PASS**. No validation errors were found.

## Preliminary observations

The tables report observed medians and bootstrap intervals without assuming that FX-ABF must be fastest. Membership-filter space is interpreted only through the integrated index metric, which includes locator and authenticated PStore bytes. Core Transform measurements are an ABE/pairing baseline, not evidence for filter speed; filter effects are assessed through integrated-index query time. Total Transform is retained as a supplemental, pairing-dominated metric.
