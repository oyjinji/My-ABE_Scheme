# FABEO Source Audit

## Source and provenance

- Source path: `Code/fabeo22cp/__init__.py`.
- Repository remote: `https://github.com/oyjinji/My-ABE_Scheme.git`.
- Current repository commit at audit: `09e176a7b5553f850c30d9ba9fdcada4a970b4e0`.
- File-introduction commit: `f2b402afb8776dd9256f268ed5d44fcc5caf1cc4` (2026-06-10, author Jinji).
- Audited file SHA-256: `6f72fbe717cc555dae325241f1a42e992c00bacb1aba027b3aff6ac80a3b0b97`.
- The source header identifies Doreen Riepel and Hoeteck Wee, “FABEO: Fast Attribute-Based Encryption with Optimal Security” (2022), Figure 1 left, implementation dated 2023-06.

The adapter imports `FABEO22CPABE` directly. It does not edit or replace Setup, KeyGen, Encrypt, Decrypt, MSP conversion, `prune`, or pairing calls.

## Common benchmark profile

- Pairing library/backend: Charm-Crypto 0.63 using its PBC-backed `PairingGroup` API.
- Official benchmark instantiation: `Benchmark/measurements_cp.py:145`, `PairingGroup('MNT224')`.
- Curve/group: `MNT224`; order size observed as 224 bits.
- Pairing orientation used by source: `pair(G1, G2)`.
- Canonical serialized sizes observed on this machine: G1 42 B, G2 118 B, GT 226 B, ZR 42 B.
- Hash-to-group: `group.hash(attr, G1)` for attributes; `group.hash(str(group.order()+1), G1)` for the distinguished `ZR+1` label.
- Serialization for all compared schemes: the same `group.serialize()`; framed non-group values use the 05.3 canonical encoder.
- The benchmark adapter retains the exact input policy string as an accounting-only field because Charm's left-deep policy-tree `__str__` exceeds Python's recursion limit at large `ell`; FABEO cryptographic methods ignore the field.

Therefore `COMMON_BENCHMARK_PROFILE = Charm-Crypto/PBC + PairingGroup('MNT224')`.

## Algorithm formulas read from source

Setup samples `g1 in G1`, `g2 in G2`, `alpha in ZR`, and publishes `e(g1,g2)^alpha`.

KeyGen samples `r`, sets `g2_r=g2^r`, `sk1[attr]=H(attr)^r`, and `sk2=g1^alpha H(ZR+1)^r`.

Encrypt converts the Boolean policy with `Code.msp.MSP`, samples `s1,sprime`, publishes `g2^s1`, `g2^sprime`, and for each MSP row computes `H(ZR+1)^lambda_i H(attr)^sprime`. The KEM component is `e(g1,g2)^(alpha*s1) * msg`.

Decrypt calls the official `MSP.prune(policy,key.attr_list)`. It multiplies only the returned nodes into `prod_sk` and `prod_ct`, then executes exactly three pairings:

1. `e(sk2,g2_s1)`;
2. `e(prod_sk,g2_sprime)`;
3. `e(prod_ct,g2_r)`.

For an OR policy, Charm's prune returns a satisfying subset, not all matched rows. This behavior is retained.

## Operation structure

- Setup: one GT exponentiation after one pairing used to establish parameters.
- KeyGen: one G2 exponentiation, one G1 exponentiation per user attribute, and two fixed G1 exponentiations.
- Encrypt: two fixed G2 exponentiations, two G1 exponentiations per MSP row, and one GT exponentiation.
- Decrypt: aggregation over pruned nodes followed by three pairings.

## Orientation adaptation boundary

FX-ABE 05.3 preserves the frozen semantic orientation: `Q_tau,C_i,C,C_rev,K_tau in G1`; `D_j,K1,K0,U0,U1 in G2`; all calls are `pair(G1,G2)`. No G1/G2 semantic swap was made.

The 05.3 issuance implementation executes real blind/evaluate/unblind OPRF operations for both authenticated user and finite authenticated policy sessions. A direct-token helper exists only as a correctness oracle and is not used by Encrypt, KeyGen or PrivacyKeyUpt.
