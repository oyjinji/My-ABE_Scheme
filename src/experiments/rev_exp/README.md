# Revocation Experiments

This is the independent experiment layer for the dual-epoch tree-revocable
FX-ABE design in the external design note `ABE-Scheme-02.md` (not in this
repository).  The 2026-08-11 correctness and
smoke implementation is retained; the current orchestration uses tiered
sampling so expensive MNT224 endpoints are measured rigorously without applying
one global repeat count to every experiment.

## Cryptographic boundary

The experiment imports `src/core/fxabe_rev/` read-only and continues to execute its
real Charm-Crypto `PairingGroup("MNT224")` operations, LSSS/MSP reconstruction,
pairing OPRF, Binary-Fuse-style FX-ABF, AES-GCM PStore, Transform, and KEM-DEM
FinalDec.  No cryptographic algebra or revocation semantics were changed by the
tiered-sampling revision.

`src/experiments/rev_exp/src/revocation.py` remains the tested experiment-local timing wrapper for the
same tree, node secrets, epoch hash, scalar source, and G2 operations.  Its
KUNodes/Path/Cover rules and fixed KU wire encoding are unchanged.  KU size uses
Charm's canonical serialization (42-byte G1 and 118-byte G2 on this installed
MNT224 backend), never Python object size.

## Correctness

Tests continue to cover C1--C12: cover boundaries and intersection semantics,
satisfied/unsatisfied decryption, revoked failure, honest and relabelled-old KU
failure, fail-closed epoch mismatch, frozen epochs, privacy/revocation state
isolation, and forward-only revocation.  Framework tests additionally verify
tiered sample counts, full large-endpoint sampling, placement-independent Exp06,
and the required placement range statistics.

Use a cache-isolated command so the strict `src/experiments/rev_exp/` write boundary is kept:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTEST_ADDOPTS='-p no:cacheprovider' \
  python3 -m pytest src/experiments/rev_exp/tests -q
```

Current result: `17 passed` (the original 13 correctness tests plus four
orchestration/statistics tests).

## Tiered benchmark design

Every formal timing remains a raw CSV row measured with
`time.perf_counter_ns()`.  Warmups run the genuine operation but are not formal
samples.  Revoked placements and cryptographic repeats are separate axes and
their SHA-256-derived seeds are recorded.  Sampling is configured independently
inside each YAML experiment; no repeat count is hard-coded in Python.

The previous global `warmup=3, repeat=10, placements=10` plan implied 1,950
RevKeyUpt invocations in Exp01, 1,170 in Exp02, and 1,040 full epoch transitions
in Exp05 (520 of them Coupled bulk-user refreshes).  The former full profile
raised Exp05 alone to 2,500 transitions.  This uniform multiplication—not the
cryptographic implementation—was the source of the multi-day estimate.

Standard configuration:

| Experiment | Domain | Parameters | Warmup | Repeats | Placements | Formal samples |
|---|---|---|---:|---:|---:|---:|
| Exp01 | default | `n=2^10..2^16`, ratios 1/5/10% | 2 | 5 | 5 | 300 |
| Exp02/03 | default/derived | `n=16384`, 8 `r_v` values | 2 | 5 | 5 | 200 / 0 new |
| Exp04 | default | `n=16384,N=20,ell=64,r=10` | 2 | 5 | 5 | 200 |
| Exp05-A | direct comparison | `n=8..1024`, two modes | 2 | 5 | 3 | 240 |
| Exp05-B | reused Dual scalability view | Exp01 5% at `n=1024..65536` | 0 | 0 | 0 | 0 new / 100 reused |
| Exp06 | placement-independent | seven `S` values | 3 | 10 | 1 | 70 |

Total standard formal benchmark samples are 1010, plus 397 warmup invocations.
Exp03 and Exp05-B do not perform any extra benchmark operation.

Exp01's optional `n=2^18` endpoint is disabled in standard and enabled in full;
it uses 1 warmup, 3 repeats, and 3 placements.  Full increases only selected
repeats, raises Exp02 to `n=32768`, Exp04 to `n=65536`, adds the Exp01 and
Exp05-B `n=2^18` endpoints at 3x3 sampling, and adds Exp06 `S=640`.  It does not
globally multiply every workload.

## Exp05-A and Exp05-B

Exp05-A is the fair real-operation comparison for `n=8,16,...,1024`:

- Dual-Epoch executes only Rev and RevKeyUpt.
- **Coupled-Epoch Ablation** executes Rev, RevKeyUpt, genuine PrivacyKeyUpt for
  every active user, policy OPRF token refresh, FX-ABF rebuild, and encrypted
  PStore rebuild.

Both modes start from the same type of registered valid user state.  Standard
uses `S=20`, `ell=64`, `u=48`, hence a fixed 25% duplicate-row ratio.  This is an
internal ablation, not a published baseline.

Exp05-B does not execute a second Dual benchmark.  It filters Exp01's measured
5% samples at `n=2^10,2^12,2^14,2^16`; full also reuses Exp01's measured
`2^18` 5% endpoint.  Seeds, repeats, revoked placements, Cover sizes, Rev time,
and RevKeyUpt time are preserved one-to-one.

**Exp05-B reuses the 5% Dual-Epoch measurements from Exp01 because both
experiments benchmark the identical revocation-epoch transition; the same raw
samples are presented under different analytical views, avoiding redundant
cryptographic executions.**

There are no simulated or extrapolated values mixed into real CSV data. Figure
1 uses only `revkeyupt_time_ms`; Figure 5(b) uses `dual_epoch_total_ms =
rev_time_ms + revkeyupt_time_ms` from those same Exp01 rows. Figure 5 contains
two panels corresponding exactly to the direct-comparison and reused
scalability views.

## Aggregation and diagnostics

Every metric reports mean, median, sample standard deviation, **min**, **max**,
p05, p95, normal-approximation 95% CI, and sample count.  Structural metrics are
deduplicated by placement before aggregation, so crypto repeats do not create
false placement independence.  Figure 3 shows CI for both Cover nodes and KU
KiB and therefore exposes placement variance.

`revocation_cost_diagnostics.csv`, derived only from Exp01/Exp02 raw data,
contains:

- Cover-size mean/std, KUNodes/crypto/total means;
- `ku_crypto_ms_per_cover_node_mean` (Cover zero is NaN and excluded);
- `ku_crypto_fraction`;
- Pearson and Spearman Cover-size/KU-crypto correlation diagnostics.

These statistics describe the measured chain `r_v -> Cover -> KU -> crypto
cost -> RevKeyUpt`; they are not presented as a proof of the asymptotic bound.
No `r_v log(n/r_v)` runtime R-squared claim is made.

`transform_stability_diagnostics.csv` reports Transform coefficient of
variation, relative max-min point-mean range, and an optional slope.  Every raw
Exp04 row records `fx_query_ns`, `pairing_ns`, actual hit rows, actual pairing
count, lookup time, total time, and Cover size; it asserts
`actual_pairings = 2 + 2r`.  The diagnostic never removes an outlier or forces a
flat conclusion.

## Non-overwriting results

The original smoke is preserved in:

```text
src/experiments/rev_exp/results_archive/smoke_20260811/
  raw/ aggregated/ figures/ metadata/
```

New runs are isolated as:

```text
src/experiments/rev_exp/results/<run_name>/
  raw/
  aggregated/
  figures/
  metadata/run.json
```

An existing run name is rejected instead of overwritten.  Without `--run-name`
the runner creates a UTC timestamp name.  The old canonical `results/raw`,
`results/aggregated`, `results/figures`, and `results/metadata` are retained only
as the original smoke-era layout.

## Commands

Inspect standard without running crypto:

```bash
python3 src/experiments/rev_exp/scripts/run_all.py \
  --config src/experiments/rev_exp/configs/standard.yaml \
  --dry-run
```

Estimate wall time from archived smoke calibration:

```bash
python3 src/experiments/rev_exp/scripts/estimate_runtime.py \
  --config src/experiments/rev_exp/configs/standard.yaml
```

This is a planning estimate only and is never written into benchmark raw data.
Current calibration estimates standard at about 6.77 hours, with potentially
material error from setup, registration, FX retry, cache, and backend effects.

Run standard after reviewing the plan:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 src/experiments/rev_exp/scripts/run_all.py \
  --config src/experiments/rev_exp/configs/standard.yaml \
  --run-name standard_20260811
```

Run full:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 src/experiments/rev_exp/scripts/run_all.py \
  --config src/experiments/rev_exp/configs/full.yaml \
  --run-name full_20260811
```

Re-aggregate, validate, or plot one existing run without benchmarking:

```bash
python3 src/experiments/rev_exp/scripts/aggregate.py \
  --results-dir src/experiments/rev_exp/results/standard_20260811_v1
python3 src/experiments/rev_exp/scripts/validate_results.py \
  --results-dir src/experiments/rev_exp/results/standard_20260811_v1
python3 src/experiments/rev_exp/scripts/plot_all.py \
  --results-dir src/experiments/rev_exp/results/standard_20260811_v1
```

All six main figures remain 300-dpi PNG plus vector PDF with unsmoothed values,
white backgrounds, units, and 95% CI bands.  The completed final reuse regression
is in `results/smoke_exp05b_reuse_final_20260811/`; it validated all six CSVs,
Exp03/Exp02 identity, Exp05-A/B domains, diagnostics, and the two-panel Figure 5.
