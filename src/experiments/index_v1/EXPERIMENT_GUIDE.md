# FXDACP experiment operation guide

Run every command from `/home/jinjio_TEE_container/ABE/Git/My-ABE_Scheme`.

## 1. Environment and dependencies

Check the base environment:

```bash
python3 --version
python3 -c "from charm.toolbox.pairinggroup import PairingGroup; print(PairingGroup('MNT224').groupType())"
python3 -c "import cryptography, matplotlib, yaml; print(cryptography.__version__, matplotlib.__version__, yaml.__version__)"
```

If pytest is absent, create an isolated environment that retains the repository's system Charm installation:

```bash
python3 -m venv --system-site-packages .venv-fx
.venv-fx/bin/python -m pip install -r src/experiments/index_v1/requirements.txt
```

On Debian images without `ensurepip`, install only the missing test packages into a repository-local target:

```bash
python3 -m pip install --target .fxdeps -r src/experiments/index_v1/requirements.txt
```

Subsequent examples use `.venv-fx/bin/python`. If using the target fallback, replace it with `PYTHONPATH=.fxdeps python3`; if the base interpreter already has every dependency, replace it with `python3`.

## 2. Tests

Run FXDACP and experiment-framework tests, producing separate JUnit logs:

```bash
.venv-fx/bin/python -m pytest -q src/core/fxdacp/tests --junitxml=src/experiments/index_v1/logs/tests/fxdacp.xml
.venv-fx/bin/python -m pytest -q src/experiments/index_v1/tests --junitxml=src/experiments/index_v1/logs/tests/fx_exp.xml
```

Run both together:

```bash
.venv-fx/bin/python -m pytest -q src/core/fxdacp/tests src/experiments/index_v1/tests
```

## 3. Profiles and complete runs

Smoke (small end-to-end validation):

```bash
.venv-fx/bin/python -m experiments.index_v1.runners.run_all --profile smoke --run-id smoke_manual
```

Standard (recommended routine paper run):

```bash
.venv-fx/bin/python -m experiments.index_v1.runners.run_all --profile standard --run-id standard_01
```

Full (long final-data run):

```bash
.venv-fx/bin/python -m experiments.index_v1.runners.run_all --profile full --run-id full_01
```

Inspect a grid without executing it:

```bash
.venv-fx/bin/python -m experiments.index_v1.runners.run_all --profile full --dry-run
```

The full runner appends and fsyncs each trial immediately. On SIGINT, it finishes the current trial where possible and exits. Resume without overwriting completed combinations:

```bash
.venv-fx/bin/python -m experiments.index_v1.runners.run_all --profile full --run-id full_01 --resume
```

Override the deterministic master seed:

```bash
.venv-fx/bin/python -m experiments.index_v1.runners.run_all --profile smoke --seed 424242 --run-id smoke_seed_424242
```

Run IDs must be unique unless `--resume` is supplied. Omitting `--run-id` creates `YYYYMMDD_HHMMSS_<profile>`.

## 4. Individual experiments

Experiments 1-3 (first success, retries, build/expansion):

```bash
.venv-fx/bin/python -m experiments.index_v1.runners.run_fxabf_build --profile smoke --run-id build_smoke
```

Experiments 4 and 10 (query breakdown and rejection):

```bash
.venv-fx/bin/python -m experiments.index_v1.runners.run_query_breakdown --profile smoke --run-id query_smoke
```

Experiments 5 and 6 (FX-ABF and PStore storage):

```bash
.venv-fx/bin/python -m experiments.index_v1.runners.run_storage_suite --profile smoke --run-id storage_smoke
```

Filter comparison only (experiment 7):

```bash
.venv-fx/bin/python -m experiments.index_v1.runners.run_filter_suite --profile smoke --run-id filters_smoke
```

Segment and joint sensitivity (experiments 8 and 11):

```bash
.venv-fx/bin/python -m experiments.index_v1.runners.run_sensitivity --profile smoke --run-id sensitivity_smoke
```

Fixed `N=32,r=8` Transform scaling only (experiment 9):

```bash
.venv-fx/bin/python -m experiments.index_v1.runners.run_transform_scaling --profile smoke --run-id transform_smoke
```

Each focused runner accepts the same `--seed`, `--dry-run`, `--run-id` and `--resume` flags.

## 5. Redraw without rerunning

```bash
.venv-fx/bin/python -m experiments.index_v1.plots.plot_all --run-dir src/experiments/index_v1/results/smoke_manual
```

This reads only raw JSONL and rewrites `plots/*.png`, `plots/*.pdf`, and the exact aggregated inputs in `plot_data/*.csv`.

## 6. Results and logs

For run `<id>`:

- `src/experiments/index_v1/results/<id>/manifest.json`: environment, git state, full config, seed and command;
- `src/experiments/index_v1/results/<id>/raw/exp*.jsonl`: one append-only object per trial/combination, including failures and tracebacks;
- `src/experiments/index_v1/results/<id>/summary/exp*.csv`: grouped sample count, mean, median, standard deviation, min, max, P95 and (with at least 10 samples) P99;
- `src/experiments/index_v1/results/<id>/plot_data/*.csv`: exact figure inputs;
- `src/experiments/index_v1/results/<id>/plots/*.{png,pdf}`: paper-ready raster/vector figures;
- `src/experiments/index_v1/logs/<profile>/<id>.log`: progress and per-combination status.

View progress and summaries:

```bash
tail -f src/experiments/index_v1/logs/smoke/smoke_manual.log
ls src/experiments/index_v1/results/smoke_manual/summary
sed -n '1,20p' src/experiments/index_v1/results/smoke_manual/summary/exp07_filter_suite.csv
```

## 7. Raw and summary fields

All raw rows include `experiment`, `combination_key`, `status`, and the reproducible `seed`. Failed rows add `exception`, `traceback`, and the failing `config`. Common workload fields are `trial`, `u`, `ell`, `N`, `r`, `delta`, `c_fx`, `gamma`, `r_max`, `segment_length`, `distribution`, `hit_ratio`, and `backend` where applicable.

- Build: `first_attempt_success`, `retries`, `initial_m`, `final_m`, `expansions`, `peeling_ns`, `assignment_ns`, `pstore_encryption_ns`, `build_ns`.
- Query: phase totals ending in `_ns`, `slot_reads`, `aead_attempts`, `aead_successes`, `hit_count`, `mean_query_ns`.
- Storage: `b_j`, `payload_bits`, `filter_bytes`, `pstore_bytes`, `metadata_bytes`, `total_index_bytes`, per-token/per-row values, nonce/tag/payload/padding bytes.
- Filter suite: build/hit/miss timing, throughput, sizes, retries/expansions, false accepts and false negatives.
- Transform: `filter_query_ns`, `pstore_processing_ns`, `pairing_ns`, `other_ns`, `core_transform_ns`, `e2e_transform_ns`, and `pairing_count`.
- Rejection: range/short-check/AEAD rejection counts and empirical false-accept rate.

Summary CSV files use one row per numeric metric and grouping combination. Fields are `metric`, grouping columns, `sample_count`, `mean`, `median`, `stddev`, `min`, `max`, `p95`, and `p99` when supported by sample size.

## 8. Success criteria and troubleshooting

A run is successful when every raw row has `status=ok`, summary CSVs exist for all requested experiments, and the plots directory contains both PNG and PDF files. For experiment 9, verify `r=8` and `pairing_count=17` for every row. For every filter, `false_negatives` must be zero.

Common problems:

- `No module named pytest`: create `.venv-fx` and install `src/experiments/index_v1/requirements.txt` as above.
- Charm import/pairing failure: use `--system-site-packages` and verify `PairingGroup('MNT224')` before running.
- Matplotlib cache permissions: the plotter automatically uses `/tmp/fx_exp_matplotlib`.
- Existing run directory: select a new `--run-id`, or pass `--resume` only when continuing that exact config/run.
- A failed combination: inspect its raw JSONL traceback and the profile log; failures are deliberately not marked complete, so resume retries them.
- Long greedy-ABF build: raise its configured load coefficient for exploratory work, but record the changed YAML as a new run.

## 9. Runtime and disk estimates

Use `--dry-run` to obtain combination count. Measure a smoke run's elapsed time and result bytes, then estimate:

```text
estimated runtime = smoke seconds / smoke combinations * target combinations
estimated raw disk = smoke raw bytes / smoke combinations * target combinations
figure disk = number of figures * (typical PNG bytes + typical PDF bytes)
```

Transform trials include real Charm pairings and usually dominate runtime; rejection experiments dominate query count. The formulas are estimates only—build retries, policy size and machine load are nonlinear. Check free space before `full` and retain its manifest with the data.
