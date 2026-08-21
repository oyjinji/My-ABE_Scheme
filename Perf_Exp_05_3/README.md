# FX-ABE 05.3 + FABEO Common-Backend Experiments

This independent suite implements the frozen 05.3 algebra on the exact profile used by the repository's official FABEO CP-ABE benchmark: Charm/PBC `PairingGroup("MNT224")`. It does not modify historical `Global_Exp`, `Rev_Exp`, `fx_exp`, `fx_exp_v2`, `Code/fxabe_rev`, or `Code/fabeo22cp` data/source.

## Reproduction

```bash
cd /home/jinji_o/ABE-Test/Git/FABEO
python3 Perf_Exp_05_3/scripts/run_pipeline.py \
  --config Perf_Exp_05_3/configs/smoke.yaml --run-id smoke_05_3
python3 Perf_Exp_05_3/scripts/run_pipeline.py \
  --config Perf_Exp_05_3/configs/standard.yaml --run-id standard_05_3
```

The general runner refuses `full.yaml`. The explicit gated Full runner is used only after `PRE_FULL_AUDIT.md` reports `FULL_READY=YES`.

The final-audit and explicitly gated Full sequence is:

```bash
python3 Perf_Exp_05_3/scripts/standard_final_audit.py \
  Perf_Exp_05_3/results/standard_05_3_20260818
python3 Perf_Exp_05_3/scripts/run_exp12.py \
  --config Perf_Exp_05_3/configs/exp12_standard.yaml \
  --run-id exp12_standard_20260819
python3 Perf_Exp_05_3/scripts/pre_full_audit.py \
  Perf_Exp_05_3/results/standard_05_3_20260818 \
  Perf_Exp_05_3/results/exp12_standard_20260819
python3 Perf_Exp_05_3/scripts/run_full.py \
  --config Perf_Exp_05_3/configs/full.yaml --run-id full_05_3_20260819 \
  --standard-run Perf_Exp_05_3/results/standard_05_3_20260818
```

All timers use `time.perf_counter_ns`; smoke uses warmup 1/repeats 3, standard 3/20, and the unexecuted full profile 5/50. Raw samples, failures and outliers are retained. Aggregates report median, mean, sample standard deviation, p25, p75, min and max.

## Experiment questions and falsification conditions

| Experiment | Research question | Independent variable | Controls | Metrics | Expected structural trend | Falsification condition |
|---|---|---|---|---|---|---|
| EXP-00 | What does this backend charge per primitive? | operation | machine/curve/backend | ns, serialized bytes | G2 asymmetry visible | fake/zero crypto call |
| EXP-01 | Does occurrence reuse reduce Encrypt slope? | ell | OR LSSS, backend | time, G1/G2/GT counts | 05.3 G2=`c_max`; ablation G2=`ell` | 05.3 G2 grows as ell |
| EXP-02 | Is theoretical storage reflected on wire? | ell | canonical serializer | component bytes | G2 term `c_max` vs `ell` | object-size accounting/count mismatch |
| EXP-03 | Is Transform reconstruction-first? | J | OR, k=tI=1 | phase time, pairs | pairs remain 4 | pairs grow with J |
| EXP-04 | Does tI explain pairing cost? | tI | ell=J=k=cmax=8 | transform ns, pairs | pairs=`3+tI` | any count mismatch |
| EXP-05 | What is padding overhead? | c_max | ell=40, tI=1 | Encrypt/storage/Transform | Encrypt/storage grow, pairs fixed | Transform pairs follow c_max |
| EXP-06 | What does real FX/PStore Build cost? | u | profile/load rule | build phases, retry, bytes | near-linear typical trend | exact locator or missing AEAD |
| EXP-07 | What does online Query cost? | N | all-hit, L=4 | retrieval/check/AEAD/decode | linear in N+Lhit | dict locator path |
| EXP-08 | Where is full lifecycle cost paid? | ell | same environment | named phase ns | user issuance offline | user OPRF charged per Transform |
| EXP-09 | What is anonymity/index overhead? | ell | 05.3 decomposition | absolute/percent | workload-specific | invented insecure baseline |
| EXP-10 | How does revocation scale? | n/revoked/S | same tree/backend | KU/cover/bytes/Transform | cover-dependent | reused historical timing |
| EXP-11 | What is the fair core gap to FABEO? | ell | same OR MSP/profile | Setup/KeyGen/Encrypt, Transform Crypto, Transform, FinalDec, Transform+FinalDec, FABEO Decrypt, counts/bytes | source-explainable | different curve/backend |
| EXP-12 | Is policy OPRF driven by rows or distinct tokens? | u at fixed ell=640 | c_max=8, same duplicate-aware occurrence rule | OPRF/FX/PStore/Core/Full time and canonical bytes | OPRF follows u; Core remains row-controlled | illegal multiplicity or flat OPRF cost |

The feature table prevents interpreting a fast FABEO core as a full feature-equivalent system comparison. The scheme remains **CANDIDATE — FORMAL PROOF OPEN**; MNT224 is a compatibility benchmark, not a production recommendation.

EXP-08 additionally records representative `ell=40` AND and 20-of-40 explicit-threshold workloads for the full FXABE lifecycle. Cross-scheme FABEO figures use the exact same official OR MSP; no threshold adapter rewrites FABEO's algorithm.

EXP-09 percentages always use the corresponding EXP-09 workload's own `FXABE Core` denominator. They must not be divided by an EXP-01 median. The original `03_ciphertext_storage.png` is a supplemental full-system storage comparison and is not feature-equivalent; the formal storage views are `03a_core_ciphertext_storage.png` and `03b_fxabe_full_storage_breakdown.png`.

## Final figure set

The authoritative Full run is `results/full_05_3_20260819`. Its main figures are: `01_encrypt_core.png` (median/IQR), `02_full_encrypt_breakdown.png`, `03a_core_ciphertext_storage.png`, `03b_fxabe_full_storage_breakdown.png`, `05_transform_decomposition_vs_J.png`, `06_transform_vs_tI.png`, `07_real_fx_build.png`, `08_real_fx_query.png`, `09_policy_oprf_vs_u.png`, and `10_dual_vs_coupled.png`. `S1`/`S2` are supplemental revocation/c_max ablations. There is only one main Encrypt Core comparison figure.
