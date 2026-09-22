# FX anonymous-index component experiment report

## Environment

- Timestamp: `2026-07-29T04:09:57.833753+00:00`
- Git commit: `f2b402afb8776dd9256f268ed5d44fcc5caf1cc4` (dirty=True)
- Python: `3.8.10 (default, Mar 18 2025, 20:04:55) `
- OS: `Linux-6.18.33.1-microsoft-standard-WSL2-x86_64-with-glibc2.29`
- CPU: `Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz`
- Pairing backend: `MNT224`
- CPU affinity: `{'cpu': 0, 'status': 'fixed'}`

## Test configuration

```yaml
mode: smoke
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
  - 64
  - 256
  independent_seeds: 2
  warmup_builds: 1
  measured_builds_per_seed: 1
f2:
  ell_scaling:
  - 64
  - 128
  fixed_N_a: 32
  fixed_r_a: 8
  fixed_ell_b: 128
  fixed_N_b: 64
  r_scaling:
  - 4
  - 8
  independent_workloads: 2
  warmup_queries: 2
  measured_queries: 5
f3:
  u: 256
  member_queries: 512
  nonmember_queries: 1000
  independent_workloads: 2
bootstrap_resamples: 500
threads: 1
```

## Build time summary (F1-A, ms)

| filter_name | workload | u | ell | median | ci95_low | ci95_high | count |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Bloom+Locator | F1-A | 64 | 64 | 5.1377 | 5.0476 | 5.2278 | 2 |
| Bloom+Locator | F1-A | 256 | 256 | 16.6484 | 16.4895 | 16.8073 | 2 |
| Cuckoo+Locator | F1-A | 64 | 64 | 3.1882 | 3.0440 | 3.3323 | 2 |
| Cuckoo+Locator | F1-A | 256 | 256 | 9.9624 | 9.5957 | 10.3291 | 2 |
| FX-ABF | F1-A | 64 | 64 | 50.0717 | 37.3078 | 62.8356 | 2 |
| FX-ABF | F1-A | 256 | 256 | 22.0242 | 15.7736 | 28.2749 | 2 |
| Legacy ABF | F1-A | 64 | 64 | 38.3067 | 30.2658 | 46.3476 | 2 |
| Legacy ABF | F1-A | 256 | 256 | 181.9118 | 175.3158 | 188.5078 | 2 |
| Xor+Locator | F1-A | 64 | 64 | 4.5930 | 4.0707 | 5.1153 | 2 |
| Xor+Locator | F1-A | 256 | 256 | 12.2046 | 12.1393 | 12.2699 | 2 |

## Integrated build phase breakdown (F1-A)

At `u=256`, milliseconds; structure is the wall-time remainder after the separately measured locator, PStore, and metadata phases.

| filter_name | structure_build_ms | locator_build_ms | pstore_build_ms | metadata_build_ms | integrated_build_ms |
| --- | --- | --- | --- | --- | --- |
| Bloom+Locator | 8.2368 | 0.7222 | 7.6754 | 0.0140 | 16.6484 |
| Cuckoo+Locator | 1.4361 | 0.7229 | 7.7920 | 0.0113 | 9.9624 |
| FX-ABF | 14.5424 | 0.0000 | 7.4665 | 0.0153 | 22.0242 |
| Legacy ABF | 174.3325 | 0.0000 | 7.5640 | 0.0153 | 181.9118 |
| Xor+Locator | 3.7204 | 0.7209 | 7.7473 | 0.0159 | 12.2046 |

## Integrated index space (F1-A, bytes/token)

| filter_name | workload | u | ell | median | ci95_low | ci95_high | count |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Bloom+Locator | F1-A | 64 | 64 | 71.8906 | 71.8906 | 71.8906 | 2 |
| Bloom+Locator | F1-A | 256 | 256 | 71.8477 | 71.8477 | 71.8477 | 2 |
| Cuckoo+Locator | F1-A | 64 | 64 | 74.7188 | 74.7188 | 74.7188 | 2 |
| Cuckoo+Locator | F1-A | 256 | 256 | 74.4297 | 74.4297 | 74.4297 | 2 |
| FX-ABF | F1-A | 64 | 64 | 54.0859 | 52.8906 | 55.2812 | 2 |
| FX-ABF | F1-A | 256 | 256 | 48.4531 | 48.4531 | 48.4531 | 2 |
| Legacy ABF | F1-A | 64 | 64 | 76.7812 | 71.2188 | 82.3438 | 2 |
| Legacy ABF | F1-A | 256 | 256 | 99.3359 | 99.3359 | 99.3359 | 2 |
| Xor+Locator | F1-A | 64 | 64 | 73.0156 | 73.0156 | 73.0156 | 2 |
| Xor+Locator | F1-A | 256 | 256 | 72.9531 | 72.9531 | 72.9531 | 2 |

## Integrated index query (F2-A, ms; excludes pairing)

| filter_name | experiment | ell | r | median | ci95_low | ci95_high | count |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Bloom+Locator | F2-A | 64 | 8 | 1.5841 | 1.5188 | 1.6494 | 2 |
| Bloom+Locator | F2-A | 128 | 8 | 1.5700 | 1.5150 | 1.6250 | 2 |
| Cuckoo+Locator | F2-A | 64 | 8 | 0.6303 | 0.6200 | 0.6406 | 2 |
| Cuckoo+Locator | F2-A | 128 | 8 | 0.7227 | 0.6688 | 0.7766 | 2 |
| FX-ABF | F2-A | 64 | 8 | 1.8165 | 1.7341 | 1.8988 | 2 |
| FX-ABF | F2-A | 128 | 8 | 1.8718 | 1.8287 | 1.9149 | 2 |
| Legacy ABF | F2-A | 64 | 8 | 1.1470 | 1.1350 | 1.1589 | 2 |
| Legacy ABF | F2-A | 128 | 8 | 1.3244 | 1.2994 | 1.3494 | 2 |
| Xor+Locator | F2-A | 64 | 8 | 0.9120 | 0.8947 | 0.9293 | 2 |
| Xor+Locator | F2-A | 128 | 8 | 0.9861 | 0.9237 | 1.0486 | 2 |

## Supplemental Transform scaling (total, ms)

| filter_name | experiment | ell | r | median | ci95_low | ci95_high | count |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Bloom+Locator | F2-A | 64 | 8 | 60.5149 | 59.2015 | 61.8283 | 2 |
| Bloom+Locator | F2-A | 128 | 8 | 60.3848 | 60.3477 | 60.4220 | 2 |
| Bloom+Locator | F2-B | 128 | 4 | 36.0861 | 35.2648 | 36.9075 | 2 |
| Bloom+Locator | F2-B | 128 | 8 | 61.8341 | 60.7269 | 62.9413 | 2 |
| Cuckoo+Locator | F2-A | 64 | 8 | 60.2064 | 59.5045 | 60.9082 | 2 |
| Cuckoo+Locator | F2-A | 128 | 8 | 59.4890 | 59.2911 | 59.6869 | 2 |
| Cuckoo+Locator | F2-B | 128 | 4 | 33.2819 | 33.1087 | 33.4551 | 2 |
| Cuckoo+Locator | F2-B | 128 | 8 | 59.3479 | 58.5838 | 60.1121 | 2 |
| FX-ABF | F2-A | 64 | 8 | 60.8454 | 60.7216 | 60.9691 | 2 |
| FX-ABF | F2-A | 128 | 8 | 60.5843 | 59.8260 | 61.3426 | 2 |
| FX-ABF | F2-B | 128 | 4 | 35.9270 | 35.8575 | 35.9965 | 2 |
| FX-ABF | F2-B | 128 | 8 | 62.2443 | 61.0978 | 63.3908 | 2 |
| Legacy ABF | F2-A | 64 | 8 | 59.7457 | 58.6030 | 60.8883 | 2 |
| Legacy ABF | F2-A | 128 | 8 | 59.2883 | 59.0969 | 59.4797 | 2 |
| Legacy ABF | F2-B | 128 | 4 | 37.8557 | 37.6804 | 38.0311 | 2 |
| Legacy ABF | F2-B | 128 | 8 | 61.1485 | 61.1058 | 61.1911 | 2 |
| Xor+Locator | F2-A | 64 | 8 | 59.2923 | 58.4113 | 60.1733 | 2 |
| Xor+Locator | F2-A | 128 | 8 | 59.8651 | 58.7087 | 61.0216 | 2 |
| Xor+Locator | F2-B | 128 | 4 | 33.9656 | 33.6665 | 34.2647 | 2 |
| Xor+Locator | F2-B | 128 | 8 | 61.2424 | 60.7606 | 61.7243 | 2 |

## Correctness summary

| filter_name | u | median | ci95_low | ci95_high | count |
| --- | --- | --- | --- | --- | --- |
| Bloom+Locator | 256 | 0.0000 | 0.0000 | 0.0000 | 2 |
| Cuckoo+Locator | 256 | 0.0000 | 0.0000 | 0.0000 | 2 |
| FX-ABF | 256 | 0.0000 | 0.0000 | 0.0000 | 2 |
| Legacy ABF | 256 | 0.0000 | 0.0000 | 0.0000 | 2 |
| Xor+Locator | 256 | 0.0000 | 0.0000 | 0.0000 | 2 |

| filter_name | u | median | ci95_low | ci95_high | count |
| --- | --- | --- | --- | --- | --- |
| Bloom+Locator | 256 | 0.0000 | 0.0000 | 0.0000 | 2 |
| Cuckoo+Locator | 256 | 0.0000 | 0.0000 | 0.0000 | 2 |
| FX-ABF | 256 | 0.0000 | 0.0000 | 0.0000 | 2 |
| Legacy ABF | 256 | 0.0000 | 0.0000 | 0.0000 | 2 |
| Xor+Locator | 256 | 0.0000 | 0.0000 | 0.0000 | 2 |

## Build failures and retries

Measured build failures: **0**.
Retry and resize statistics are retained in raw F1 and its summary.

## Anomalies

Validation status: **PASS**. No validation errors were found.

## Preliminary observations

The tables report observed medians and bootstrap intervals without assuming that FX-ABF must be fastest. Membership-filter space is interpreted only through the integrated index metric, which includes locator and authenticated PStore bytes. Core Transform measurements are an ABE/pairing baseline, not evidence for filter speed; filter effects are assessed through integrated-index query time. Total Transform is retained as a supplemental, pairing-dominated metric.
