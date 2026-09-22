# FX anonymous-index component experiment report

## Environment

- Timestamp: `2026-07-29T03:01:01.981884+00:00`
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
- Bloom+Locator
- Cuckoo
- Xor
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
| Bloom+Locator | F1-A | 64 | 64 | 4.2227 | 4.1537 | 4.2918 | 2 |
| Bloom+Locator | F1-A | 256 | 256 | 18.1357 | 16.8814 | 19.3901 | 2 |
| Cuckoo | F1-A | 64 | 64 | 3.1139 | 2.4946 | 3.7333 | 2 |
| Cuckoo | F1-A | 256 | 256 | 11.6338 | 10.3070 | 12.9606 | 2 |
| FX-ABF | F1-A | 64 | 64 | 48.9634 | 37.6720 | 60.2548 | 2 |
| FX-ABF | F1-A | 256 | 256 | 23.1762 | 17.4638 | 28.8886 | 2 |
| Xor | F1-A | 64 | 64 | 4.3615 | 3.2222 | 5.5008 | 2 |
| Xor | F1-A | 256 | 256 | 12.9573 | 12.0920 | 13.8225 | 2 |

## Integrated index space (F1-A, bytes/token)

| filter_name | workload | u | ell | median | ci95_low | ci95_high | count |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Bloom+Locator | F1-A | 64 | 64 | 71.8906 | 71.8906 | 71.8906 | 2 |
| Bloom+Locator | F1-A | 256 | 256 | 71.8477 | 71.8477 | 71.8477 | 2 |
| Cuckoo | F1-A | 64 | 64 | 74.5938 | 74.5938 | 74.5938 | 2 |
| Cuckoo | F1-A | 256 | 256 | 74.3984 | 74.3984 | 74.3984 | 2 |
| FX-ABF | F1-A | 64 | 64 | 54.0859 | 52.8906 | 55.2812 | 2 |
| FX-ABF | F1-A | 256 | 256 | 48.4531 | 48.4531 | 48.4531 | 2 |
| Xor | F1-A | 64 | 64 | 72.8906 | 72.8906 | 72.8906 | 2 |
| Xor | F1-A | 256 | 256 | 72.9219 | 72.9219 | 72.9219 | 2 |

## Transform scaling (total, ms)

| filter_name | experiment | ell | r | median | ci95_low | ci95_high | count |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Bloom+Locator | F2-A | 64 | 8 | 62.4551 | 61.5301 | 63.3801 | 2 |
| Bloom+Locator | F2-A | 128 | 8 | 62.8304 | 60.4812 | 65.1797 | 2 |
| Bloom+Locator | F2-B | 128 | 4 | 37.7662 | 34.9700 | 40.5625 | 2 |
| Bloom+Locator | F2-B | 128 | 8 | 63.3438 | 63.1843 | 63.5034 | 2 |
| Cuckoo | F2-A | 64 | 8 | 61.1572 | 59.6268 | 62.6876 | 2 |
| Cuckoo | F2-A | 128 | 8 | 60.4802 | 59.6078 | 61.3526 | 2 |
| Cuckoo | F2-B | 128 | 4 | 34.3782 | 33.8491 | 34.9073 | 2 |
| Cuckoo | F2-B | 128 | 8 | 60.4463 | 60.0651 | 60.8275 | 2 |
| FX-ABF | F2-A | 64 | 8 | 62.3269 | 61.8885 | 62.7653 | 2 |
| FX-ABF | F2-A | 128 | 8 | 62.4923 | 61.8105 | 63.1740 | 2 |
| FX-ABF | F2-B | 128 | 4 | 36.7425 | 35.5536 | 37.9315 | 2 |
| FX-ABF | F2-B | 128 | 8 | 62.0223 | 61.9829 | 62.0618 | 2 |
| Xor | F2-A | 64 | 8 | 61.4310 | 61.3991 | 61.4630 | 2 |
| Xor | F2-A | 128 | 8 | 59.9568 | 58.9539 | 60.9596 | 2 |
| Xor | F2-B | 128 | 4 | 34.5314 | 34.1293 | 34.9335 | 2 |
| Xor | F2-B | 128 | 8 | 61.6851 | 59.8426 | 63.5277 | 2 |

## Correctness summary

| filter_name | u | median | ci95_low | ci95_high | count |
| --- | --- | --- | --- | --- | --- |
| Bloom+Locator | 256 | 0.0000 | 0.0000 | 0.0000 | 2 |
| Cuckoo | 256 | 0.0000 | 0.0000 | 0.0000 | 2 |
| FX-ABF | 256 | 0.0000 | 0.0000 | 0.0000 | 2 |
| Xor | 256 | 0.0000 | 0.0000 | 0.0000 | 2 |

| filter_name | u | median | ci95_low | ci95_high | count |
| --- | --- | --- | --- | --- | --- |
| Bloom+Locator | 256 | 0.0000 | 0.0000 | 0.0000 | 2 |
| Cuckoo | 256 | 0.0000 | 0.0000 | 0.0000 | 2 |
| FX-ABF | 256 | 0.0000 | 0.0000 | 0.0000 | 2 |
| Xor | 256 | 0.0000 | 0.0000 | 0.0000 | 2 |

## Build failures and retries

Measured build failures: **0**.
Retry and resize statistics are retained in raw F1 and its summary.

## Anomalies

Validation status: **PASS**. No validation errors were found.

## Preliminary observations

The tables report observed medians and bootstrap intervals without assuming that FX-ABF must be fastest. Membership-filter space is interpreted only through the integrated index metric, which includes locator and authenticated PStore bytes. Core Transform measurements are an ABE/pairing baseline, not evidence for filter speed; filter effects are assessed through index-query and total-Transform time.
