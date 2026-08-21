# Full Runtime Estimate

Generated before Full from retained Standard medians and the frozen `full.yaml`. It is a planning estimate, not a change to repeats or workload.

| experiment | estimated runs/invocations | estimated runtime | basis |
|---|---:|---:|---|
| EXP-01 Encrypt Core | 1155 | 31.8 min | linear endpoint extrapolation; 15% margin |
| EXP-02 Storage | 21 | 0.5 min | deterministic canonical recomputation |
| EXP-03 Transform vs J | 385 | 3.0 min | timed Transform plus one preparation per J |
| EXP-04 Transform vs t_I | 220 | 2.0 min | timed Transform plus preparation |
| EXP-06 FX Build | 385 | 1.5 min | real peeling/AEAD builds |
| EXP-07 FX Query | 350 | 0.8 min | batched all-hit query |
| EXP-08/09 E2E | 275 | 6.0 min | three OR sizes plus AND/threshold lifecycle |
| EXP-10 Critical Revocation | 1595 | 20.0 min | n=2048 endpoint and 50-repeat update loops |
| EXP-11 FABEO Core | 660 | 24.9 min | fresh lifecycle objects at four core sizes |

Total estimated wall time: **1.51 hours**.

EXP-00 and EXP-05 reuse their validated Standard mechanism results; EXP-12 remains a 20-repeat Standard supplemental experiment. Storage is recomputed on Full workloads without artificial 50-fold deterministic duplication. No Full repeat was reduced.
