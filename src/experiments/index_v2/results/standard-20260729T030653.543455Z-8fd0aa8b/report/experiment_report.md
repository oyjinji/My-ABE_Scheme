# FX anonymous-index component experiment report

## Environment

- Timestamp: `2026-07-29T03:06:53.559894+00:00`
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
- Bloom+Locator
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
| Bloom+Locator | F1-A | 128 | 128 | 9.0221 | 8.6936 | 9.5353 | 30 |
| Bloom+Locator | F1-A | 512 | 512 | 35.3484 | 34.3816 | 36.4512 | 30 |
| Bloom+Locator | F1-A | 2048 | 2048 | 137.1932 | 136.4407 | 138.6954 | 30 |
| Bloom+Locator | F1-A | 8192 | 8192 | 551.0694 | 547.6923 | 554.4226 | 30 |
| Cuckoo | F1-A | 128 | 128 | 5.5213 | 5.2859 | 5.7306 | 30 |
| Cuckoo | F1-A | 512 | 512 | 21.9404 | 20.7116 | 22.4049 | 30 |
| Cuckoo | F1-A | 2048 | 2048 | 82.5785 | 81.7477 | 83.5449 | 30 |
| Cuckoo | F1-A | 8192 | 8192 | 330.9630 | 327.5870 | 332.9066 | 30 |
| FX-ABF | F1-A | 128 | 128 | 9.3343 | 8.5451 | 11.5727 | 30 |
| FX-ABF | F1-A | 512 | 512 | 60.3420 | 48.1830 | 71.2331 | 30 |
| FX-ABF | F1-A | 2048 | 2048 | 132.3283 | 131.0773 | 133.0543 | 30 |
| FX-ABF | F1-A | 8192 | 8192 | 529.9168 | 528.0187 | 535.0919 | 30 |
| Xor | F1-A | 128 | 128 | 7.0034 | 6.5766 | 7.5824 | 30 |
| Xor | F1-A | 512 | 512 | 27.0702 | 25.4639 | 28.1172 | 30 |
| Xor | F1-A | 2048 | 2048 | 100.5309 | 99.9447 | 101.2710 | 30 |
| Xor | F1-A | 8192 | 8192 | 407.9079 | 404.2712 | 411.2302 | 30 |

## Integrated index space (F1-A, bytes/token)

| filter_name | workload | u | ell | median | ci95_low | ci95_high | count |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Bloom+Locator | F1-A | 128 | 128 | 71.1953 | 71.1953 | 71.1953 | 30 |
| Bloom+Locator | F1-A | 512 | 512 | 71.6738 | 71.6738 | 71.6738 | 30 |
| Bloom+Locator | F1-A | 2048 | 2048 | 71.5435 | 71.5435 | 71.5435 | 30 |
| Bloom+Locator | F1-A | 8192 | 8192 | 71.5110 | 71.5110 | 71.5110 | 30 |
| Cuckoo | F1-A | 128 | 128 | 73.7969 | 73.7969 | 73.7969 | 30 |
| Cuckoo | F1-A | 512 | 512 | 74.2012 | 74.2012 | 74.2012 | 30 |
| Cuckoo | F1-A | 2048 | 2048 | 74.0503 | 74.0503 | 74.0503 | 30 |
| Cuckoo | F1-A | 8192 | 8192 | 74.0126 | 74.0126 | 74.0126 | 30 |
| FX-ABF | F1-A | 128 | 128 | 49.2266 | 49.2266 | 49.2266 | 30 |
| FX-ABF | F1-A | 512 | 512 | 49.3809 | 49.3809 | 49.3809 | 30 |
| FX-ABF | F1-A | 2048 | 2048 | 49.0967 | 49.0967 | 49.0967 | 30 |
| FX-ABF | F1-A | 8192 | 8192 | 49.0239 | 49.0239 | 49.0239 | 30 |
| Xor | F1-A | 128 | 128 | 72.2422 | 72.2422 | 72.2422 | 30 |
| Xor | F1-A | 512 | 512 | 72.7617 | 72.7617 | 72.7617 | 30 |
| Xor | F1-A | 2048 | 2048 | 72.6406 | 72.6406 | 72.6406 | 30 |
| Xor | F1-A | 8192 | 8192 | 72.6101 | 72.6101 | 72.6101 | 30 |

## Transform scaling (total, ms)

| filter_name | experiment | ell | r | median | ci95_low | ci95_high | count |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Bloom+Locator | F2-A | 32 | 8 | 61.2965 | 61.0829 | 61.7439 | 10 |
| Bloom+Locator | F2-A | 64 | 8 | 61.4987 | 61.3172 | 61.7128 | 10 |
| Bloom+Locator | F2-A | 128 | 8 | 61.5804 | 61.0743 | 62.2140 | 10 |
| Bloom+Locator | F2-A | 256 | 8 | 61.5649 | 61.3805 | 61.8275 | 10 |
| Bloom+Locator | F2-A | 512 | 8 | 61.8991 | 61.7808 | 62.2721 | 10 |
| Bloom+Locator | F2-B | 256 | 4 | 36.0877 | 35.8352 | 36.5382 | 10 |
| Bloom+Locator | F2-B | 256 | 8 | 63.2254 | 62.7942 | 64.6574 | 10 |
| Bloom+Locator | F2-B | 256 | 16 | 116.7663 | 115.8072 | 117.8056 | 10 |
| Bloom+Locator | F2-B | 256 | 32 | 223.0872 | 222.7102 | 224.1544 | 10 |
| Bloom+Locator | F2-B | 256 | 64 | 437.4624 | 436.0948 | 439.4945 | 10 |
| Cuckoo | F2-A | 32 | 8 | 60.7966 | 60.5838 | 61.1744 | 10 |
| Cuckoo | F2-A | 64 | 8 | 60.9416 | 60.4827 | 61.4191 | 10 |
| Cuckoo | F2-A | 128 | 8 | 60.8868 | 60.1696 | 61.3658 | 10 |
| Cuckoo | F2-A | 256 | 8 | 60.7036 | 60.4496 | 61.0266 | 10 |
| Cuckoo | F2-A | 512 | 8 | 61.1153 | 60.5827 | 61.4982 | 10 |
| Cuckoo | F2-B | 256 | 4 | 34.6692 | 34.4354 | 34.9789 | 10 |
| Cuckoo | F2-B | 256 | 8 | 61.1911 | 60.8416 | 61.5529 | 10 |
| Cuckoo | F2-B | 256 | 16 | 114.9601 | 114.0879 | 116.6751 | 10 |
| Cuckoo | F2-B | 256 | 32 | 221.5786 | 220.3113 | 222.5905 | 10 |
| Cuckoo | F2-B | 256 | 64 | 437.6903 | 435.6657 | 455.5962 | 10 |
| FX-ABF | F2-A | 32 | 8 | 61.7280 | 61.4732 | 62.3943 | 10 |
| FX-ABF | F2-A | 64 | 8 | 61.8967 | 61.5594 | 62.5142 | 10 |
| FX-ABF | F2-A | 128 | 8 | 62.0100 | 61.8419 | 62.1497 | 10 |
| FX-ABF | F2-A | 256 | 8 | 62.1107 | 61.7756 | 63.0576 | 10 |
| FX-ABF | F2-A | 512 | 8 | 62.8094 | 62.5054 | 63.4192 | 10 |
| FX-ABF | F2-B | 256 | 4 | 37.0691 | 36.7530 | 37.5045 | 10 |
| FX-ABF | F2-B | 256 | 8 | 64.1188 | 63.9701 | 64.6500 | 10 |
| FX-ABF | F2-B | 256 | 16 | 117.1091 | 116.7153 | 117.7490 | 10 |
| FX-ABF | F2-B | 256 | 32 | 223.9474 | 223.3282 | 225.7642 | 10 |
| FX-ABF | F2-B | 256 | 64 | 436.4252 | 435.5337 | 437.3611 | 10 |
| Xor | F2-A | 32 | 8 | 60.7937 | 60.5758 | 61.2257 | 10 |
| Xor | F2-A | 64 | 8 | 61.1676 | 60.6179 | 61.5859 | 10 |
| Xor | F2-A | 128 | 8 | 61.3036 | 60.6799 | 61.8396 | 10 |
| Xor | F2-A | 256 | 8 | 61.4412 | 60.9540 | 61.8172 | 10 |
| Xor | F2-A | 512 | 8 | 61.1595 | 60.7854 | 61.4223 | 10 |
| Xor | F2-B | 256 | 4 | 35.1615 | 34.8556 | 35.3386 | 10 |
| Xor | F2-B | 256 | 8 | 61.7555 | 61.4563 | 62.2103 | 10 |
| Xor | F2-B | 256 | 16 | 115.3664 | 114.6454 | 116.3006 | 10 |
| Xor | F2-B | 256 | 32 | 222.0081 | 221.4518 | 223.4260 | 10 |
| Xor | F2-B | 256 | 64 | 436.6879 | 433.2700 | 439.1579 | 10 |

## Correctness summary

| filter_name | u | median | ci95_low | ci95_high | count |
| --- | --- | --- | --- | --- | --- |
| Bloom+Locator | 2048 | 0.0000 | 0.0000 | 0.0000 | 10 |
| Cuckoo | 2048 | 0.0000 | 0.0000 | 0.0000 | 10 |
| FX-ABF | 2048 | 0.0000 | 0.0000 | 0.0000 | 10 |
| Xor | 2048 | 0.0000 | 0.0000 | 0.0000 | 10 |

| filter_name | u | median | ci95_low | ci95_high | count |
| --- | --- | --- | --- | --- | --- |
| Bloom+Locator | 2048 | 0.0000 | 0.0000 | 0.0000 | 10 |
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
