# FX-ABE anonymous-index component experiments

The original F1/F2/F3 suite compares five **system-level composed indexes**:
Legacy ABF, Bloom+Locator, Cuckoo+Locator, Xor+Locator, and FX-ABF. These
immutable results remain useful as measurements of the current Python
prototype, but are supplemental rather than a main functionally-equivalent
filter-algorithm ranking: the exact locator in three baselines can independently
perform precise token-to-identifier retrieval.

The primary algorithm-level comparison now lives in
`fx_exp_v2/retrieval_exp/`. Its five structures use only their own serialized
array/table to implement `token -> fixed-width j || check / miss`; it contains
no locator, PStore, KDF, AEAD, or ABE pairing.

The former `ABF` display name in the composed suite was audited
and corrected: it is an ordinary Bloom membership bitmap plus exact locator.
`ABF` remains an input compatibility alias for Bloom+Locator. Legacy ABF is the
separate greedy XOR retrieval construction adapted from
`fx_exp/filters/original_abf.py`.
Every alternative implements the same external meaning:

```text
anonymous token -> authenticated hit(posting list) or miss
```

Bloom, cuckoo, and XOR are membership filters, so they use an anonymous exact
locator and the common encrypted PStore after a candidate-positive result.
Legacy ABF and FX-ABF directly XOR-recover a PStore identifier plus a short
check, so neither uses a locator. Space is reported as filter-only,
locator, PStore, metadata, and their exact integrated sum. The integrated sum,
not a bare fingerprint array, is the paper-facing comparison.

F1 varies distinct tokens and measures real Build time, retry/resize behavior,
integrated space, and bytes/token. F1-A has `ell=u`; F1-B has `ell=4u`. F2-A
fixes query tokens and matched rows while increasing policy rows. F2-B fixes
policy size while increasing matched rows and checks the observed `2+2r`
pairing count. F3 measures member false negatives, raw candidate positives,
authentication rejection, and final false accepts.

`core_transform_ms` begins after the hit set is available and covers Path/Cover,
the two revocation pairings, `2r` row pairings, and result construction.
`integrated_index_query_ms` is the exact sum of membership/retrieval, optional
locator lookup, PStore KDF, PStore AEAD, and posting decode. In F2 it is the
complete `N`-token query batch per Transform and excludes pairing.
`transform_total_ms` additionally includes metadata and real pairing work, so
it is retained as a supplemental rather than the primary index-query figure.

From the repository root, run:

```bash
python3 -m fx_exp_v2.benchmarks.run_suite \
  --config fx_exp_v2/configs/smoke.yaml

python3 -m fx_exp_v2.benchmarks.run_suite \
  --config fx_exp_v2/configs/standard.yaml

python3 -m fx_exp_v2.benchmarks.run_suite \
  --config fx_exp_v2/configs/full.yaml
```

`full` is intentionally never selected by default. A complete standard run is:

```bash
python3 -m fx_exp_v2.benchmarks.run_suite \
  --config fx_exp_v2/configs/standard.yaml \
  --validate --plot --report
```

For an existing run:

```bash
python3 -m fx_exp_v2.analysis.validate_results --run-dir fx_exp_v2/results/<run_id>
python3 -m fx_exp_v2.plots.plot_all --run-dir fx_exp_v2/results/<run_id>
python3 -m fx_exp_v2.analysis.generate_report --run-dir fx_exp_v2/results/<run_id>
```

Each run gets a non-overwriting `results/<run_id>` with environment/config,
raw CSV, summary CSV/JSON, validation and experiment reports, logs, four main
PNG/PDF figure pairs, and a supplemental Total Transform pair. The main figures
are integrated Build time, integrated bytes/token, integrated query time, and
Core Transform time. Error bars are 95% bootstrap confidence intervals for the
median across independent workloads/seeds.

`Code.fxabe_rev.FXABERev` exposes separately timed `KeyGen`, `Encrypt`,
`Transform`, and `FinalDec` with canonical-size helpers and explicit pairing
counters. A later FABEO comparison can reuse those operations, metrics,
workload seeding, environment capture, summary, validation, and plotting
infrastructure without changing this component experiment.
