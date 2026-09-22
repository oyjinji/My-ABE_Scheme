# Run Ledger

## Authoritative runs

- Smoke: `results/smoke_05_3_final3_20260818` (final implementation, all gates).
- Standard: `results/standard_05_3_20260818` (final implementation, 20 measured replicates after 3 warmups).
- EXP-12 smoke: `results/exp12_smoke_20260819` (3 measured replicates after 1 warmup; legality/correctness pipeline gate).
- EXP-12 Standard supplemental: `results/exp12_standard_20260819` (20 measured replicates after 3 warmups; fixed ell=640).
- Full: `results/full_05_3_20260819` (critical scalability experiments, 50 measured replicates after 5 warmups; validation PASS).

## Retained audit attempts

Earlier smoke directories are retained, but are not formal results. They precede one or more audit corrections: standard-only Full gating, deep FABEO policy serialization, configured warmups, real blind OPRF issuance, Setup pairing counts, or the explicit Transform Crypto field.

Within the authoritative standard run, superseded CSVs are retained under `logs/` with names ending in `_invalid.csv`; they are excluded from `raw/`, aggregation, plots and analysis. The manifest covers both authoritative artifacts and retained audit evidence.

The Standard final audit only added derived CSVs, clearer plots and audit documents. It did not rewrite `results/standard_05_3_20260818/raw/`. Full reuses the validated Standard EXP-00 and mechanism-only EXP-05, and retains EXP-12 as a Standard supplemental experiment as declared before execution.

## Baseline scope

FABEO is the mandatory audited baseline. The repository also contains `Code/fabesa`, but this run does not claim verified official provenance for it and therefore does not include it. No remembered/reimplemented FABESA result is reported.
