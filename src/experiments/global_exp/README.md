# Global_Exp — Global ABE End-to-End Performance Experiment

Third formal experiment suite in the FABEO/FX-ABE repository.  It answers one
research question:

> **For a complete ABE deployment, how does the end-to-end cost of the FX-ABE
> system (OPRF → FX-ABF → PStore → ABE → CSP Transform → FinalDec, with
> dual-epoch revocation) compare with the high-performance FABEO22 CP-ABE
> baseline on computation, storage and total cost?**

Three schemes are benchmarked on **identical workloads** (same policy, same
LSSS matrix, same `rho`, same user set, same message, same seed):

| Scheme | Description |
| --- | --- |
| **FABEO22** | The repository's real FABEO22 CP-ABE, untouched. |
| **FXABE-Base** | Internal ablation baseline (not a published construction): the real FXABE setup, revocation tree, epoch scalars, pairings, KDF/AEAD and `final_dec`, with the anonymity layer (OPRF / FX-ABF / PStore) replaced by a plaintext attribute→policy-row direct mapping. |
| **FXABE-Full** | The complete real system (`src/core/fxabe_rev.FXABERev`). |

## Guarantees

* **Same workload object for all schemes** — policy, matrix, rho, user set and
  message fingerprints are identical across schemes for every point.
* **Policy size = `l`, the number of LSSS rows.** OR policies over `l`
  attributes convert to exactly `l` unit rows in both MSP engines.
* **Satisfaction ratio ≈ 0.5** for standard workloads (all policy rows are
  even, so exactly 0.5).
* **Real cryptography only.** Every exponentiation and pairing is a real Charm
  MNT224 group operation; no mock groups, no `sleep`, no fake pair counters.
* **No cross-repetition caching.** Each repetition builds a fresh scheme,
  fresh keys, fresh ciphertext and fresh transformed ciphertext.
* **Median + IQR** as the point estimator and error band; **p95 and max** are
  always reported (outliers are never deleted).  Bootstrap 95% CIs for the
  median are included.
* **Non-invasive instrumentation** — optional `metrics` parameters on the real
  scheme functions (`setup`/`keygen`/`encrypt`), verified to leave equations
  and outputs unchanged (measured phase sum ≈ total within 0.2%).
* **Real serialized sizes** for storage (`group.serialize` / canonical
  `encode`), never `sys.getsizeof`.

## Experiments

| # | Figure | Content |
| --- | --- | --- |
| exp01 | `exp01_setup.png` | Setup cost **by scheme** (Setup is universe-independent for both schemes; no fabricated scaling curve). |
| exp02 | `exp02_user_provisioning.png` | Provisioning (KeyGen) vs \|S\|. |
| exp03 | `exp03_encrypt.png` | End-to-end encryption vs `l` (`encrypt_total_ms`). |
| exp04 | `exp04_transform.png` | CSP Transform vs `l` (Base/Full only; FABEO22 has no outsourced transform). |
| exp05 | `exp05_client_decrypt.png` | Client-side decryption vs `l` (FABEO22 full Decrypt vs Base/Full FinalDec — explicit phase-difference caveat in the figure). |
| exp06 | `exp06_e2e_decrypt.png` | End-to-end decryption latency vs `l` (`end_to_end_decrypt_ms`, the headline metric). |
| exp07 | `exp07_storage.png` | Ciphertext-side storage vs `l` (serialized bytes). |
| exp08 | `exp08_encrypt_breakdown.png`, `exp08_decrypt_breakdown.png` | Phase breakdown (stacked) on a representative workload. |
| exp09 | `exp09_normalized_overhead.png` | *Supplementary:* e2e-decryption overhead vs FABEO22. |

> **exp06 measurement note (conservative).**  The FX-ABE implementation derives
> the user's anonymous tokens at key issuance.  For the end-to-end decryption
> metric we additionally time a per-query re-tokenization of the user's
> attributes (`user_oprf_ms`), representing a device that does not cache
> tokens.  The decomposition (`user_oprf_ms` + `transform_ms` + `finaldec_ms`)
> lets the reader recompute the deployed-path total excluding the OPRF stage.

## Layout

```
src/experiments/global_exp/
  configs/         smoke.yaml · standard.yaml · full.yaml
  src/             common · workloads · timing · statistics · storage ·
                   adapters · experiments · planning
  scripts/         run_all · aggregate · plot_all · validate_results
  tests/           correctness, workload identity, validation logic
  results/<run_name>/
    metadata.json  config_snapshot.yaml  environment.json  correctness.json
    raw/           per-repetition CSVs (defined schema, one row per repetition)
    summary/       median/IQR/p95 summary CSVs (long form)
    plots/         exp01..exp09 PNGs
    logs/          timing.json · validation.json · aggregation.json
```

## Running

```bash
# 1. tests
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest src/experiments/global_exp/tests -q

# 2. smoke (end-to-end plumbing)
python3 src/experiments/global_exp/scripts/run_all.py --config src/experiments/global_exp/configs/smoke.yaml \
    --run-name global_smoke_20260812_v1
python3 src/experiments/global_exp/scripts/aggregate.py  --run-dir src/experiments/global_exp/results/global_smoke_20260812_v1
python3 src/experiments/global_exp/scripts/plot_all.py    --run-dir src/experiments/global_exp/results/global_smoke_20260812_v1
python3 src/experiments/global_exp/scripts/validate_results.py --run-dir src/experiments/global_exp/results/global_smoke_20260812_v1

# 3. standard (primary benchmark, ~10 min)
python3 src/experiments/global_exp/scripts/run_all.py --config src/experiments/global_exp/configs/standard.yaml \
    --run-name global_standard_20260812_v1
# ... aggregate / plot / validate as above ...

# 4. full (deep statistical run) — only after the standard run's
#    runtime projection shows it is feasible
```

## Configuration

All three configs fix the same `master_seed`, pairing group (MNT224) and
satisfaction ratio (0.5).  `repetitions`/`warmups` and the `policy_rows` /
`user_attrs` sweeps differ by tier.  Per-unit wall-clock from a completed run
is recorded in `logs/timing.json`; `src/experiments/global_exp/src/planning.py` projects a candidate
config's runtime from it (linear-in-`l` model, with linearity diagnostics).
