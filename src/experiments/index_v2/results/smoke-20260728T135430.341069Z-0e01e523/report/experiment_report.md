# FX anonymous-index component experiment report

## Environment

- Timestamp: `2026-07-28T13:54:30.358094+00:00`
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
| ABF | F1-A | 64 | 64 | 5.3774 | 4.8891 | 5.8657 | 2 |
| ABF | F1-A | 256 | 256 | 19.5751 | 19.3263 | 19.8239 | 2 |
| Cuckoo | F1-A | 64 | 64 | 2.9346 | 2.4428 | 3.4263 | 2 |
| Cuckoo | F1-A | 256 | 256 | 11.6012 | 11.0533 | 12.1491 | 2 |
| FX-ABF | F1-A | 64 | 64 | 10.8291 | 8.6818 | 12.9764 | 2 |
| FX-ABF | F1-A | 256 | 256 | 51.2578 | 46.7193 | 55.7962 | 2 |
| Xor | F1-A | 64 | 64 | 3.8903 | 3.0046 | 4.7759 | 2 |
| Xor | F1-A | 256 | 256 | 14.0831 | 14.0764 | 14.0897 | 2 |

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
| ABF | F2-A | 64 | 8 | 61.6199 | 61.2289 | 62.0109 | 2 |
| ABF | F2-A | 128 | 8 | 63.6333 | 62.6161 | 64.6506 | 2 |
| ABF | F2-B | 128 | 4 | 36.4538 | 36.0898 | 36.8178 | 2 |
| ABF | F2-B | 128 | 8 | 67.4114 | 62.1363 | 72.6866 | 2 |
| Cuckoo | F2-A | 64 | 8 | 62.8720 | 61.7229 | 64.0211 | 2 |
| Cuckoo | F2-A | 128 | 8 | 63.5090 | 62.9930 | 64.0250 | 2 |
| Cuckoo | F2-B | 128 | 4 | 34.2820 | 34.2719 | 34.2921 | 2 |
| Cuckoo | F2-B | 128 | 8 | 66.4153 | 61.3197 | 71.5109 | 2 |
| FX-ABF | F2-A | 64 | 8 | 62.1174 | 62.0913 | 62.1435 | 2 |
| FX-ABF | F2-A | 128 | 8 | 62.1239 | 61.6175 | 62.6303 | 2 |
| FX-ABF | F2-B | 128 | 4 | 36.5010 | 36.2525 | 36.7495 | 2 |
| FX-ABF | F2-B | 128 | 8 | 67.5473 | 66.8425 | 68.2521 | 2 |
| Xor | F2-A | 64 | 8 | 61.8118 | 61.3926 | 62.2310 | 2 |
| Xor | F2-A | 128 | 8 | 61.9516 | 61.7856 | 62.1176 | 2 |
| Xor | F2-B | 128 | 4 | 34.8539 | 34.5391 | 35.1686 | 2 |
| Xor | F2-B | 128 | 8 | 64.4328 | 62.8411 | 66.0246 | 2 |

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
