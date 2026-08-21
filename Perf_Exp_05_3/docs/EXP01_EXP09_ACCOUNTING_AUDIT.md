# EXP-01 / EXP-09 Accounting Audit

Result: **PASS**. No raw sample or aggregation defect was found.

| ell | EXP01 core median (ms) | EXP09 core median (ms) | EXP09 anonymity overhead (ms) | reported % | recomputed % |
|---:|---:|---:|---:|---:|---:|
| 40 | 86.034476 | 89.548162 | 81.865004 | 91.420084 | 91.420084 |
| 160 | 227.584591 | 248.479172 | 334.303712 | 134.539933 | 134.539933 |
| 640 | 813.181324 | 894.920145 | 1327.851859 | 148.376575 | 148.376575 |

- workload_equal: **NO**
- timing_boundary_equal: **YES**

## Raw-row provenance

EXP-01 denominator rows are `raw/exp01_encrypt.csv`, `scheme=FXABE-05.3 Core`, `phase=Encrypt Core`. EXP-09 denominator rows are `raw/exp09_anonymity_overhead.csv`, `phase=FXABE Core`. Both values are the implementation's `encrypt_core_ns`; the timing boundary is therefore the same ABE-core boundary.

The experiments are not sample-identical workloads. EXP-01 is the encrypt-only OR workload with one matched attribute, a seven-byte payload, and a scheme instance reused across repetitions. EXP-09 is emitted by the full E2E OR workload with `N=J=16`, a three-byte payload, a fresh scheme instance per repetition, and different derived seeds/state. The policy-side metadata (`ell`, `u`, `c_max`, `actual_c_star`) matches, but the complete workload/lifecycle does not.

Accordingly, the reported 148.3766% at ell=640 is `1327.851859 / 894.920146`, not `1327.851859 / 813.181325`. EXP-09 always uses its own paired workload's Core denominator. The frozen raw samples remain unchanged.
