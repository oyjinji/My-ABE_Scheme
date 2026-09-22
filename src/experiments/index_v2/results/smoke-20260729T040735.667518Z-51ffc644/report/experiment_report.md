# FX anonymous-index component experiment report

## Environment

- Timestamp: `2026-07-29T04:07:35.764241+00:00`
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
| Bloom+Locator | F1-A | 64 | 64 | 4.2804 | 4.2587 | 4.3022 | 2 |
| Bloom+Locator | F1-A | 256 | 256 | 17.7758 | 16.5325 | 19.0191 | 2 |
| Cuckoo+Locator | F1-A | 64 | 64 | 3.1083 | 2.7575 | 3.4591 | 2 |
| Cuckoo+Locator | F1-A | 256 | 256 | 9.9631 | 9.4742 | 10.4520 | 2 |
| FX-ABF | F1-A | 64 | 64 | 47.9851 | 33.8344 | 62.1358 | 2 |
| FX-ABF | F1-A | 256 | 256 | 21.9702 | 15.7408 | 28.1996 | 2 |
| Legacy ABF | F1-A | 64 | 64 | 34.1779 | 26.2253 | 42.1306 | 2 |
| Legacy ABF | F1-A | 256 | 256 | 184.6145 | 176.8134 | 192.4157 | 2 |
| Xor+Locator | F1-A | 64 | 64 | 3.8142 | 2.9669 | 4.6616 | 2 |
| Xor+Locator | F1-A | 256 | 256 | 12.2913 | 12.1571 | 12.4256 | 2 |

## Integrated build phase breakdown (F1-A)

At `u=256`, milliseconds; structure is the wall-time remainder after the separately measured locator, PStore, and metadata phases.

| filter_name | structure_build_ms | locator_build_ms | pstore_build_ms | metadata_build_ms | integrated_build_ms |
| --- | --- | --- | --- | --- | --- |
| Bloom+Locator | 8.1846 | 0.6918 | 8.8879 | 0.0115 | 17.7758 |
| Cuckoo+Locator | 1.5116 | 0.8204 | 7.6204 | 0.0108 | 9.9631 |
| FX-ABF | 14.0526 | 0.0000 | 7.9015 | 0.0160 | 21.9702 |
| Legacy ABF | 176.9579 | 0.0000 | 7.6391 | 0.0175 | 184.6145 |
| Xor+Locator | 3.6272 | 0.7125 | 7.9382 | 0.0134 | 12.2913 |

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
| Bloom+Locator | F2-A | 64 | 8 | 1.4764 | 1.4381 | 1.5147 | 2 |
| Bloom+Locator | F2-A | 128 | 8 | 1.4867 | 1.3944 | 1.5789 | 2 |
| Cuckoo+Locator | F2-A | 64 | 8 | 0.6880 | 0.6650 | 0.7110 | 2 |
| Cuckoo+Locator | F2-A | 128 | 8 | 0.6307 | 0.6213 | 0.6401 | 2 |
| FX-ABF | F2-A | 64 | 8 | 1.7111 | 1.6273 | 1.7949 | 2 |
| FX-ABF | F2-A | 128 | 8 | 1.8290 | 1.7111 | 1.9468 | 2 |
| Legacy ABF | F2-A | 64 | 8 | 1.2608 | 1.2559 | 1.2657 | 2 |
| Legacy ABF | F2-A | 128 | 8 | 1.4262 | 1.3823 | 1.4700 | 2 |
| Xor+Locator | F2-A | 64 | 8 | 0.9607 | 0.8932 | 1.0281 | 2 |
| Xor+Locator | F2-A | 128 | 8 | 0.9041 | 0.8840 | 0.9241 | 2 |

## Supplemental Transform scaling (total, ms)

| filter_name | experiment | ell | r | median | ci95_low | ci95_high | count |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Bloom+Locator | F2-A | 64 | 8 | 65.1578 | 59.6384 | 70.6773 | 2 |
| Bloom+Locator | F2-A | 128 | 8 | 62.1742 | 60.7764 | 63.5720 | 2 |
| Bloom+Locator | F2-B | 128 | 4 | 35.8092 | 34.9384 | 36.6800 | 2 |
| Bloom+Locator | F2-B | 128 | 8 | 61.3562 | 61.2115 | 61.5010 | 2 |
| Cuckoo+Locator | F2-A | 64 | 8 | 60.0466 | 59.4400 | 60.6533 | 2 |
| Cuckoo+Locator | F2-A | 128 | 8 | 58.8317 | 58.5249 | 59.1385 | 2 |
| Cuckoo+Locator | F2-B | 128 | 4 | 33.9794 | 33.9356 | 34.0231 | 2 |
| Cuckoo+Locator | F2-B | 128 | 8 | 59.8618 | 59.4719 | 60.2517 | 2 |
| FX-ABF | F2-A | 64 | 8 | 60.4060 | 60.0710 | 60.7411 | 2 |
| FX-ABF | F2-A | 128 | 8 | 60.1589 | 60.1154 | 60.2024 | 2 |
| FX-ABF | F2-B | 128 | 4 | 38.4485 | 36.1704 | 40.7266 | 2 |
| FX-ABF | F2-B | 128 | 8 | 61.9484 | 61.8585 | 62.0383 | 2 |
| Legacy ABF | F2-A | 64 | 8 | 59.9688 | 59.2523 | 60.6853 | 2 |
| Legacy ABF | F2-A | 128 | 8 | 60.5279 | 59.2057 | 61.8502 | 2 |
| Legacy ABF | F2-B | 128 | 4 | 34.4753 | 34.3280 | 34.6226 | 2 |
| Legacy ABF | F2-B | 128 | 8 | 62.7826 | 62.2363 | 63.3288 | 2 |
| Xor+Locator | F2-A | 64 | 8 | 59.8853 | 58.9419 | 60.8288 | 2 |
| Xor+Locator | F2-A | 128 | 8 | 61.5170 | 59.0122 | 64.0218 | 2 |
| Xor+Locator | F2-B | 128 | 4 | 33.7663 | 33.6636 | 33.8690 | 2 |
| Xor+Locator | F2-B | 128 | 8 | 60.4296 | 60.2428 | 60.6163 | 2 |

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
