# FX anonymous-index component experiment report

## Environment

- Timestamp: `2026-07-29T03:02:32.574353+00:00`
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
| Bloom+Locator | F1-A | 64 | 64 | 5.4303 | 4.7909 | 6.0696 | 2 |
| Bloom+Locator | F1-A | 256 | 256 | 20.1386 | 19.0178 | 21.2595 | 2 |
| Cuckoo | F1-A | 64 | 64 | 2.9093 | 2.8506 | 2.9681 | 2 |
| Cuckoo | F1-A | 256 | 256 | 10.9580 | 10.2176 | 11.6983 | 2 |
| FX-ABF | F1-A | 64 | 64 | 47.0095 | 35.4065 | 58.6125 | 2 |
| FX-ABF | F1-A | 256 | 256 | 22.5740 | 17.2204 | 27.9277 | 2 |
| Xor | F1-A | 64 | 64 | 4.2115 | 3.3534 | 5.0697 | 2 |
| Xor | F1-A | 256 | 256 | 13.8801 | 12.5660 | 15.1942 | 2 |

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
| Bloom+Locator | F2-A | 64 | 8 | 62.2553 | 61.4961 | 63.0145 | 2 |
| Bloom+Locator | F2-A | 128 | 8 | 59.7239 | 59.4039 | 60.0440 | 2 |
| Bloom+Locator | F2-B | 128 | 4 | 35.6365 | 35.6215 | 35.6515 | 2 |
| Bloom+Locator | F2-B | 128 | 8 | 63.2947 | 61.7535 | 64.8358 | 2 |
| Cuckoo | F2-A | 64 | 8 | 63.9642 | 60.3446 | 67.5838 | 2 |
| Cuckoo | F2-A | 128 | 8 | 62.9577 | 60.3692 | 65.5462 | 2 |
| Cuckoo | F2-B | 128 | 4 | 33.8835 | 33.8279 | 33.9391 | 2 |
| Cuckoo | F2-B | 128 | 8 | 61.2458 | 58.8187 | 63.6729 | 2 |
| FX-ABF | F2-A | 64 | 8 | 59.8347 | 59.5581 | 60.1112 | 2 |
| FX-ABF | F2-A | 128 | 8 | 61.1319 | 61.0886 | 61.1752 | 2 |
| FX-ABF | F2-B | 128 | 4 | 36.9331 | 35.9166 | 37.9496 | 2 |
| FX-ABF | F2-B | 128 | 8 | 62.0688 | 61.5577 | 62.5799 | 2 |
| Xor | F2-A | 64 | 8 | 60.1888 | 60.1288 | 60.2488 | 2 |
| Xor | F2-A | 128 | 8 | 61.9704 | 58.6332 | 65.3076 | 2 |
| Xor | F2-B | 128 | 4 | 33.9900 | 33.7459 | 34.2341 | 2 |
| Xor | F2-B | 128 | 8 | 61.0108 | 60.7630 | 61.2586 | 2 |

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
