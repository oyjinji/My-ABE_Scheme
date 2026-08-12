# Functionally equivalent retrieval experiment

This suite is the primary algorithm-level anonymous retrieval comparison. It
measures only:

```text
token -> fixed-width Encode_bj(j) || delta-bit check / miss
```

It excludes locator dictionaries, PStore, KDF, AEAD, ABE Transform, group
operations, and pairings. The existing `fx_exp_v2/results/full-*` runs are
preserved as supplemental **system-level composed-index** results.

Run the smoke suite:

```bash
cd /home/jinji_o/ABE-Test/Git/FABEO
python3 -m fx_exp_v2.retrieval_exp.run_suite \
  --config fx_exp_v2/retrieval_exp/configs/smoke.yaml \
  --validate --plot --report
```

Standard and full configurations are present but are not run automatically:

```bash
python3 -m fx_exp_v2.retrieval_exp.run_suite \
  --config fx_exp_v2/retrieval_exp/configs/standard.yaml \
  --validate --plot --report
```

Each immutable run is written below
`fx_exp_v2/retrieval_exp/results/<run_id>/`, with raw CSV, independent-seed
summary, validation/report Markdown, and four PNG/PDF figure pairs.

The four figures report build time, mixed retrieval time, serialized bytes per
key, and build success/retry behavior. Error bars are 95% bootstrap confidence
intervals over independent seeds. The build figure has an all-structure log-y
panel and a modern-structure linear-y panel so Legacy ABF cannot hide modern
differences.
