# Phase 5D-R metric-level fairness matrix

The prior Phase 5D global stop record is historical. Baseline-specific blockers
are isolated. Both formal local tracks use BLS12-381/py_ecc on the same host,
timer, pinned CPU, 5 warmups and 30 samples per arm in three alternating blocks.
The 1200-sample ablation and 360-sample FABEO core tracks are COMPLETE and
independently verified against frozen source snapshots. No samples were removed.

| Metric / pair | Classification | Scope and limit |
|---|---|---|
| MyABE algebra-core Encrypt vs row-independent ablation | `DIRECTLY_COMPARABLE` | Same OR matrix, policy rows, AF, backend and timer; only D allocation changes. |
| MyABE algebra-core Transform vs row-independent ablation | `DIRECTLY_COMPARABLE` | Same authorized OR request and AF/LSSS; both arms use two CSP pairings. The larger row-D vector changes validation/serialization work; this workload does not isolate a pairing-count benefit. |
| MyABE core group bytes and D count vs ablation | `DIRECTLY_COMPARABLE` | Encoded `C_i`, `D_j`, `C` only; not a complete signed CT. |
| MyABE full signed CT wire bytes vs ablation | `STRUCTURAL_ONLY` | One EMULATED TEST public construction/decryption per arm and configuration; AF slot shape matches. Different TEST encoding marker contributes serialization bytes. No timing distribution. |
| MyABE ABE-core Setup/KeyGen/Encrypt/access vs FABEO tau=1 BLS | `DIRECTLY_COMPARABLE` | Same unique-attribute AND policy and backend; distinct cryptographic functions and key placement must accompany each timing. MyABE access includes synthetic T0, AF.Query, CSP transform and DU recovery; FABEO access is direct decrypt. |
| MyABE vs FABEO core group bytes | `STRUCTURAL_ONLY` | FABEO includes masked GT message; MyABE's byte-message DEM is outside the core group count. No full-CT size ratio follows. |
| MyABE vs FABEO total ABE-core key bytes | `STRUCTURAL_ONLY` | MyABE total includes enclave-side `mu`/`K0` plus DU RK; FABEO key is DU-side. Credential, Blob and envelopes excluded. |
| MyABE vs FABEO pairing call count | `STRUCTURAL_ONLY` | Counted calls, not isolated pairing latency. |
| MyABE full request vs FABEO direct decrypt | `NOT_COMPARABLE` | Privacy, revocation, capability, publication, RPC and SGX trust boundaries differ. |
| FABEO released MNT224 vs common BLS port | `STRUCTURAL_ONLY` | Native tau=1 is a correctness/cardinality oracle; no cross-curve time ratio. |
| FABEO released source vs paper tau>1 | `NOT_COMPARABLE` as oracle | Released source samples one `sprime`; multi-use is a paper reimplementation with structural-only local evidence. |
| MyABE real SGX vs HR-ABE native Type-A | `PAPER_REPORTED_ONLY` | Common Type-III mapping blocked; paper curves/runtimes cannot be compared directly. |
| MyABE real SGX vs LUAR simulation | `PAPER_REPORTED_ONLY` | LUAR correctness blocked and TEE environments differ. |

Formal paired data: `artifacts/myabe08/baselines/phase5d_r/ablation/20260927T112557Z-389ead9f765c/`
and `artifacts/myabe08/baselines/phase5d_r/core/20260927T154528Z-fd1052f3416d/`.
The separate CT-size artifact is `artifacts/myabe08/baselines/phase5d_r/public_ct/20260927T165759Z/`.

MyABE remains **CANDIDATE — FORMAL PROOF OPEN**. HR-ABE paper states sIND-style security models under its original construction; that claim does not transfer to an absent Type-III port. FABEO paper states adaptive generic-group/ROM security; its local BLS performance port is not a new proof. Prior real SGX results use
DEBUG/QVL OUT_OF_DATE with strict RA2 BLOCKED. Stable same-user/same-CT `W`
linkability remains observed. HR-ABE assumes trusted time/replay-protected
state; LUAR's expiry and attribute revocation differ from MyABE's exact
access-time user set.
