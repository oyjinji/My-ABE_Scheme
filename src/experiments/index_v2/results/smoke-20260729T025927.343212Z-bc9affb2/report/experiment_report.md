# FX anonymous-index component experiment report

## Environment

- Timestamp: `2026-07-29T02:59:27.364293+00:00`
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
| Bloom+Locator | F1-A | 64 | 64 | 4.3771 | 4.0152 | 4.7390 | 2 |
| Bloom+Locator | F1-A | 256 | 256 | 16.8523 | 16.8475 | 16.8570 | 2 |
| Cuckoo | F1-A | 64 | 64 | 3.0349 | 2.7445 | 3.3253 | 2 |
| Cuckoo | F1-A | 256 | 256 | 10.4758 | 9.4788 | 11.4728 | 2 |
| FX-ABF | F1-A | 64 | 64 | 46.7516 | 34.7272 | 58.7759 | 2 |
| FX-ABF | F1-A | 256 | 256 | 24.7500 | 20.8618 | 28.6382 | 2 |
| Xor | F1-A | 64 | 64 | 4.2646 | 2.9915 | 5.5376 | 2 |
| Xor | F1-A | 256 | 256 | 13.0458 | 12.3194 | 13.7722 | 2 |

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
| Bloom+Locator | F2-A | 64 | 8 | 65.5138 | 62.5230 | 68.5046 | 2 |
| Bloom+Locator | F2-A | 128 | 8 | 62.9548 | 61.8566 | 64.0530 | 2 |
| Bloom+Locator | F2-B | 128 | 4 | 37.7283 | 35.5478 | 39.9089 | 2 |
| Bloom+Locator | F2-B | 128 | 8 | 63.8865 | 61.4390 | 66.3340 | 2 |
| Cuckoo | F2-A | 64 | 8 | 62.7658 | 60.5002 | 65.0314 | 2 |
| Cuckoo | F2-A | 128 | 8 | 62.5325 | 60.9821 | 64.0828 | 2 |
| Cuckoo | F2-B | 128 | 4 | 34.4408 | 34.1586 | 34.7231 | 2 |
| Cuckoo | F2-B | 128 | 8 | 64.0602 | 61.9672 | 66.1532 | 2 |
| FX-ABF | F2-A | 64 | 8 | 63.0697 | 60.4607 | 65.6788 | 2 |
| FX-ABF | F2-A | 128 | 8 | 63.0418 | 61.3507 | 64.7328 | 2 |
| FX-ABF | F2-B | 128 | 4 | 38.0601 | 37.3375 | 38.7827 | 2 |
| FX-ABF | F2-B | 128 | 8 | 63.1994 | 62.5296 | 63.8692 | 2 |
| Xor | F2-A | 64 | 8 | 63.6889 | 60.5258 | 66.8520 | 2 |
| Xor | F2-A | 128 | 8 | 62.3222 | 59.9472 | 64.6973 | 2 |
| Xor | F2-B | 128 | 4 | 37.2317 | 37.1299 | 37.3335 | 2 |
| Xor | F2-B | 128 | 8 | 61.1845 | 60.7074 | 61.6615 | 2 |

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
