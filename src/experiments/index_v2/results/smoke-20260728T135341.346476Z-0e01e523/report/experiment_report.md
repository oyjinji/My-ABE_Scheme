# FX anonymous-index component experiment report

## Environment

- Timestamp: `2026-07-28T13:53:41.361836+00:00`
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
- ABF
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
| ABF | F1-A | 64 | 64 | 4.1254 | 4.1160 | 4.1349 | 2 |
| ABF | F1-A | 256 | 256 | 18.2039 | 17.9871 | 18.4208 | 2 |
| Cuckoo | F1-A | 64 | 64 | 2.8667 | 2.4551 | 3.2783 | 2 |
| Cuckoo | F1-A | 256 | 256 | 10.0556 | 9.8465 | 10.2647 | 2 |
| FX-ABF | F1-A | 64 | 64 | 9.2442 | 8.2000 | 10.2884 | 2 |
| FX-ABF | F1-A | 256 | 256 | 46.2454 | 40.1110 | 52.3798 | 2 |
| Xor | F1-A | 64 | 64 | 3.7631 | 2.9958 | 4.5304 | 2 |
| Xor | F1-A | 256 | 256 | 13.3620 | 12.7987 | 13.9254 | 2 |

## Integrated index space (F1-A, bytes/token)

| filter_name | workload | u | ell | median | ci95_low | ci95_high | count |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ABF | F1-A | 64 | 64 | 71.7344 | 71.7344 | 71.7344 | 2 |
| ABF | F1-A | 256 | 256 | 71.8086 | 71.8086 | 71.8086 | 2 |
| Cuckoo | F1-A | 64 | 64 | 74.5938 | 74.5938 | 74.5938 | 2 |
| Cuckoo | F1-A | 256 | 256 | 74.3984 | 74.3984 | 74.3984 | 2 |
| FX-ABF | F1-A | 64 | 64 | 50.6406 | 50.6406 | 50.6406 | 2 |
| FX-ABF | F1-A | 256 | 256 | 48.4180 | 48.4180 | 48.4180 | 2 |
| Xor | F1-A | 64 | 64 | 72.8906 | 72.8906 | 72.8906 | 2 |
| Xor | F1-A | 256 | 256 | 72.9219 | 72.9219 | 72.9219 | 2 |

## Transform scaling (total, ms)

| filter_name | experiment | ell | r | median | ci95_low | ci95_high | count |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ABF | F2-A | 64 | 8 | 64.3742 | 63.1978 | 65.5507 | 2 |
| ABF | F2-A | 128 | 8 | 62.8970 | 62.1685 | 63.6256 | 2 |
| ABF | F2-B | 128 | 4 | 35.7537 | 35.6808 | 35.8266 | 2 |
| ABF | F2-B | 128 | 8 | 66.9854 | 63.1415 | 70.8292 | 2 |
| Cuckoo | F2-A | 64 | 8 | 62.6668 | 61.6272 | 63.7065 | 2 |
| Cuckoo | F2-A | 128 | 8 | 60.5088 | 60.4376 | 60.5801 | 2 |
| Cuckoo | F2-B | 128 | 4 | 34.6742 | 34.1357 | 35.2127 | 2 |
| Cuckoo | F2-B | 128 | 8 | 63.5424 | 62.4841 | 64.6008 | 2 |
| FX-ABF | F2-A | 64 | 8 | 61.7894 | 61.4896 | 62.0891 | 2 |
| FX-ABF | F2-A | 128 | 8 | 62.7863 | 62.5245 | 63.0480 | 2 |
| FX-ABF | F2-B | 128 | 4 | 39.6314 | 36.4280 | 42.8349 | 2 |
| FX-ABF | F2-B | 128 | 8 | 65.3193 | 65.1509 | 65.4877 | 2 |
| Xor | F2-A | 64 | 8 | 62.0302 | 61.5047 | 62.5557 | 2 |
| Xor | F2-A | 128 | 8 | 61.1621 | 60.6226 | 61.7015 | 2 |
| Xor | F2-B | 128 | 4 | 35.3752 | 34.9867 | 35.7638 | 2 |
| Xor | F2-B | 128 | 8 | 66.1162 | 61.8522 | 70.3802 | 2 |

## Correctness summary

| filter_name | u | median | ci95_low | ci95_high | count |
| --- | --- | --- | --- | --- | --- |
| ABF | 256 | 0.0000 | 0.0000 | 0.0000 | 2 |
| Cuckoo | 256 | 0.0000 | 0.0000 | 0.0000 | 2 |
| FX-ABF | 256 | 0.0000 | 0.0000 | 0.0000 | 2 |
| Xor | 256 | 0.0000 | 0.0000 | 0.0000 | 2 |

| filter_name | u | median | ci95_low | ci95_high | count |
| --- | --- | --- | --- | --- | --- |
| ABF | 256 | 0.0000 | 0.0000 | 0.0000 | 2 |
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
