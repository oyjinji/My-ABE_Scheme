# Phase 5D baseline paper audit — STOP before implementation

Audit date: 2026-09-27 UTC. This is a source/formula audit, **not** an implementation or benchmark result. `ABE-Scheme-08.md` remains the sole MyABE-08 specification and was not changed. Formal status: **CANDIDATE — FORMAL PROOF OPEN**. Page numbers below are PDF page numbers, not necessarily journal page numbers.

Sources read:

- Li et al., *Make Revocation Cheaper: Hardware-Based Revocable Attribute-Based Encryption*, IEEE S&P 2024, DOI 10.1109/SP54263.2024.00100. Local 19-page PDF: `/home/jinjio_TEE_container/ABE/Doc/Li 等 - 2024 - Make Revocation Cheaper Hardware-Based Revocable Attribute-Based Encryption.pdf`; SHA-256 `1d3863030ed9017e004c98948d3dcad645ea4316945a62b79ab3c0b1af2158bc`.
- Riepel and Wee, *FABEO: Fast Attribute-Based Encryption with Optimal Security*, IACR ePrint 2022/1415, https://eprint.iacr.org/2022/1415.pdf; 36-page PDF SHA-256 `57aa828a6a1f25f9bb12cb222c3d5348a9de4e41fb81b4c96ecb8b3b6d2888fc`.
- Tang et al., *LUAR: Lightweight and Universal Attribute Revocation Mechanism with SGX Assistance towards Applicable ABE Systems*, published 12 Jan 2026, DOI 10.32604/cmc.2025.073423, https://www.techscience.com/files/cmc/2026/TSP_CMC-86-3/TSP_CMC_73423/TSP_CMC_73423.pdf; 19-page PDF SHA-256 `88e2f58327f6cce589cf8ad67a2949e218ab8b24dd11ea376c78551606244bfd`.

## HR-ABE 2024 — paper construction and experiment

| Required audit item | Verified reading / limitation |
|---|---|
| System entities | KGC, DO, CSP (storage, state, proxy, TEE), DU (pp. 8–9, Fig. 3). |
| Threat model | KGC/DO trusted; malicious CSP can rollback or collude with revoked/unauthorized DUs; separate corrupted-TEE model. Paper explicitly does **not** claim simultaneous collusion and corrupted-TEE resistance (pp. 8–9). |
| ABE type | CP-ABE through ABE-2OD, based on outsourced Green OABE (p. 7 Fig. 2; p. 11 Fig. 5). |
| Pairing type | Symmetric `e:G×G→GT` in Fig. 2 (p. 7). |
| Curve/backend in paper experiment | PBC Type-A symmetric curve (`rbits=512`, `qbits=1024`), C++ and Intel SGX hardware mode (p. 12 §5.1). |
| Setup | ABE-2OD publishes `g`, `e(g,g)^α`, `g^a`, H/H1/H2; MSK `g^α`. HR setup additionally sets signature keys, KTEE, trusted interval (p. 7 Fig. 2; p. 11 Fig. 5). |
| KeyGen | Samples `t1,t2,β,γ1,γ2`; outputs two CSP transformation keys TK, helper/revocation key HK/RK=`(γ1,γ2)`, DU DK=`β` (p. 7 Fig. 2; p. 11 Fig. 5). |
| Encrypt | LSSS shares `s`; access layer `(D_i=g^{r_i}, E_i=g^{aλ_i}H1(ρ(i))^{-r_i})`; `C=R·e(g,g)^{αs}`, `C1=H(R)⊕M`, `C2=g^s` (p. 7 Fig. 2). |
| Transform | Transform1 at CSP computes two `CP` values by reconstruction; Transform2 at TEE checks `CP1^γ1=CP2^γ2` and outputs `CP1^γ1` (p. 7 Fig. 2; pp. 10–11 Figs. 4–5). |
| TEE operation | Validate signed current user state/time/membership, open encrypted RK, perform Transform2. Paper reports three TEE exponentiations in the core transform (pp. 10–11). |
| Final decrypt | DU with DK `β` recovers R, M, checks both reconstructed consistency conditions (p. 7 Fig. 2). |
| Revocation type | User revocation by deleting DU record and committing signed new interval state, not attribute-level revocation (p. 11 Fig. 5). |
| Revocation state | Signed `(UL_i,i)`; optional signed Merkle hash tree (sMHT) membership proof reduces per-request TEE input (pp. 11–12 §4.6). |
| Ciphertext update? | No periodic ciphertext update/delegation for revocation (pp. 9, 11). |
| Key update? | No periodic DK update; new users receive generated keys; revoked user removed from UL (pp. 9, 11). |
| User-local key | DK `β`, held by DU (p. 7 Fig. 2). |
| CSP key/state | TK and signed state/UL; proxy performs Transform1 (pp. 8, 11). |
| TEE secret/state | KTEE, encrypted RK opening, replay-protected `t0,T`, trusted time, membership/current state check (pp. 10–11). |
| Policy hiding? | Not claimed; LSSS policy/ρ occurs in ciphertext (p. 7 Fig. 2). |
| User attribute hiding? | Not claimed; UL contains `A_ID` and TK (p. 8). |
| Outsourced decryption? | Yes, CSP Transform1 and TEE Transform2; DU final ElGamal-like step (pp. 7–11). |
| Trusted time? | Required: SGX trusted-time service and interval index (p. 10 Fig. 4). Current MyABE test environment lacks production trusted time. |
| Rollback protection? | Assumes TEE replay-protected storage/monotonic counter and state freshness (pp. 9–10). Current MyABE test environment lacks production hardware anti-rollback. |
| Formal security model? | sIND-CDA/sIND-CHA for ABE-2OD; sIND-ColA and sIND-CTA for HR-ABE under distinct compromises (pp. 5–7, 9–11). Does not automatically transfer to a Type-III port. |
| Paper experiment metrics? | Transform1, Transform2, DU decrypt, task/thread scaling, KGC/CSP revocation; Tables 2–3 and Figs. 6–7 (pp. 12–13). |
| Paper workload? | AND policies, `ell=10,20,30`; tasks 50–300; threads 1/3/6; DU population `2^10`–`2^18` (pp. 12–13). |
| Paper repetitions? | 20; averages (p. 12 §5.1). |
| Paper hardware? | Ubuntu 20.04, i7-8700 (6 cores/12 threads), 32 GB; SGX hardware mode (p. 12 §5.1). |
| Source-code availability? | No author repository or supplementary source URL identified in the paper, current repo, or exact-title GitHub repository search on 2026-09-27. This is **not** proof none exists; official implementation status `NOT_LOCATED`. |

The Type-III mapping obstruction is detailed in `HRABE_TYPEIII_MAPPING.md`. Native Table 2 times are **not** measurements on the MyABE host/backend and cannot be placed in a direct wall-clock ratio.

## FABEO 2022 — Figure 1 left CP-ABE and Section 7

| Required audit item | Verified reading / limitation |
|---|---|
| System entities | ABE authority, encryptor, user/decryptor; no CSP or TEE in Fig. 1 (p. 4). |
| Threat model | Adaptive ABE security in generic bilinear group model with hash random oracle; multi-ciphertext bound discussed (pp. 1–4, 15–17). No server revocation threat model. |
| ABE type | CP-ABE, monotone span program `(M,π)` (p. 4 Fig. 1 left). |
| Pairing type | Asymmetric Type-III `e:G1×G2→GT` (pp. 2, 4). |
| Curve/backend in paper experiment | Charm 0.43 / Python 2.7.12 / MNT224 PBC, not BLS12-381 (p. 18 §7). |
| Setup | Samples α and public H to G1; publishes pairing target `e(g1,g2)^α`, keeps MSK α (p. 4 Fig. 1). |
| KeyGen | Samples r; SK `(g1^α H(boundary)^r, {H(u)^r}, g2^r)` with `m+1` G1 and one G2 element (p. 4 Fig. 1; p. 20). |
| Encrypt | Samples secret vector and `s'_j` for `j=1..τ`; CT has `g2^s1`, `g2^{s'_j}`, row components `H(boundary)^{λ_i}H(π(i))^{s'_{ρ(i)}}`; GT KEM mask (p. 4 Fig. 1). |
| Transform | None; ordinary Dec reconstructs using weighted rows (p. 4 Fig. 1). |
| TEE operation | None in paper design. |
| Final decrypt | Authorized SK directly reconstructs GT mask; τ+2 pairings in paper operation table (pp. 4, 20). |
| Revocation type | None. |
| Revocation state | None. |
| Ciphertext update? | None for revocation. |
| Key update? | None for revocation. |
| User-local key | Complete ABE SK held by user. |
| CSP key/state | None specified. |
| TEE secret/state | None. |
| Policy hiding? | Not claimed; `(M,π)` is part of ciphertext. |
| User attribute hiding? | Not claimed; SK corresponds to S. |
| Outsourced decryption? | No. |
| Trusted time? | No. |
| Rollback protection? | Not applicable. |
| Formal security model? | Adaptive ABE generic-group security and ROM hashing, with optimal multi-ciphertext bound as stated by paper (pp. 1–4, 15–17). |
| Paper experiment metrics? | Setup/KeyGen/Encrypt/Decrypt times; group-operation counts; key/CT group-element sizes (p. 18 Fig. 3; pp. 19–20 Tables 2–3; size Table 5 later in §7). |
| Paper workload? | AND of N distinct attributes, `N=10,20,...,100`; experiment uses τ=1 (pp. 18–19 §7). |
| Paper repetitions? | 20 executions per point, reported averages (p. 18 §7). |
| Paper hardware? | Lenovo ThinkPad Yoga X1, i7-10510U 1.80 GHz, 16 GB (p. 18 §7). |
| Source-code availability? | Official https://github.com/DoreenRiepel/FABEO, audited HEAD `144959096b503e51f3b58532d51cbe1602ebea97`. Repository `src/core/fabeo22cp/__init__.py` is byte-identical SHA-256 `6f72fbe717cc555dae325241f1a42e992c00bacb1aba027b3aff6ac80a3b0b97`. Local `src/core/msp/__init__.py` differs from upstream MSP only in `unicode(...)`→`str(...)` Python-3 adaptation; local SHA-256 `94f09b22ec54b3611b7bd4e6f383356489fe0350b11ad88a0197db7d7e429bb4`. |

**Paper/source scope distinction.** Figure 1 specifies τ independent `s'_j` and occurrence rank `ρ(i)`; the official `fabeo22cp` Python source samples one `sprime`, emits one `g2_sprime`, and comments “re-use not allowed” in Decrypt. It is a τ=1 implementation/reference and cannot validate the paper's general τ>1 multi-use behavior. Native Charm/MNT224 timing must never be divided by MyABE BLS12-381 timing.

## LUAR 2026 — Algorithms 1–5, Section 6 and Section 8

| Required audit item | Verified reading / limitation |
|---|---|
| System entities | SGX, CSP, DO, DR; external trusted attribute issuer (pp. 4–5). |
| Threat model | §7.1 mentions malicious CSP/CSP-user collusion; §8.3 explicitly calls comparison profile semi-honest server. These are different stated assumptions and must not be collapsed (pp. 11, 15). |
| ABE type | CP-ABE with LSSS, described as LUAR+BSW07 overlay (pp. 9–11). |
| Pairing type | Algorithm 1 declares asymmetric `G1≠G2`, `e:G1×G2→GT` (p. 7). Published source uses PBC `type a` initialization attempt, unlike common BLS12-381 Type-III. |
| Curve/backend in paper experiment | Paper gives Ubuntu 20.04 / Intel i7-12700H and **SGX simulation mode**; no exact curve/bit parameters or language/library version found in §8 (p. 13). Do not assume py_ecc/BLS12-381. |
| Setup | Algorithm 1 selects α,β,γ; PK lists `g1,g2^β,g1^γ,e(g1,g2)^α`; MSK includes α,β,γ and `g2^α` (pp. 7, 10). |
| KeyGen | Algorithm 2 / §6.2: `K0=g2^{α+βt}`, `K1=g1^t`, `Kx=H(x)^t` in G2, `Kτ=H(expire||nonce)^t`, expiry and nonce (pp. 7–8, 10). |
| Encrypt | AES for file, ABE for key, `C0=S·e(g1,g2)^{αs}`, LSSS row components, and `e(g1,g2)^{βrs}` blinding (pp. 8, 11). Group declaration of `g2^{rs}` in Algorithm 3 is internally inconsistent (`∈G1`). |
| Transform | Algorithm 4: expiry check, timestamp pairing equation, Merkle path check, pairing-based blind-factor removal; steps leave some input/failure semantics unspecified (p. 9). |
| TEE operation | Setup and keygen in SGX; request checks and blinding removal in SGX; user does ABE/AES decrypt (pp. 4–9). |
| Final decrypt | §6.4 proposes leaf pairings and reconstruction; Algorithm 5 says local LUAR_Decrypt then AES_Decrypt (pp. 9, 11). Algebraic contradiction for general AND LSSS is detailed in `FORMULA_AUDIT.md`. |
| Revocation type | Passive expiry plus active attribute revocation via new key and Merkle membership proof (pp. 9–10). |
| Revocation state | Trusted/current root and logarithmic path proof; paper does not specify a production root rollback protocol in Algorithms 1–5 (pp. 9–10). |
| Ciphertext update? | Claims no revocation-driven CT update (pp. 2, 9–10). |
| Key update? | Attribute change re-runs keygen and issues a new key (p. 9), despite no periodic mass update claim. |
| User-local key | Full CP-ABE SK with expiry/nonce and timestamp component (p. 10). |
| CSP key/state | Stores blinded CT and passes requests/proofs; no LUAR TEE master secret (pp. 4–5, 9). |
| TEE secret/state | α,β,γ/master, Merkle root, time source, keygen/transform code (pp. 4–9, 16–17). |
| Policy hiding? | Not claimed; policy tree/LSSS is part of CT (pp. 5, 11). |
| User attribute hiding? | Not claimed; issuer gives attributes to SGX and SK has per-attribute components (pp. 5, 10). |
| Outsourced decryption? | No full ABE outsourcing; SGX removes blind factor; DR performs CP-ABE decrypt (pp. 5, 9). |
| Trusted time? | Required for expiry; §7.3 assumes SGX trusted-time service or signed remote timestamps (p. 13). Current MyABE platform has no production trusted time. |
| Rollback protection? | Root freshness/authentication is needed but no complete anti-rollback recovery protocol is specified by Algorithms 1–5. Current platform lacks production hardware anti-rollback (pp. 9–10). |
| Formal security model? | Paper states IND-CPA and collusion results under DBDH/ROM/SGX assumptions (§7, pp. 11–12). This audit does not endorse the proof; formula correctness is unresolved. |
| Paper experiment metrics? | Phase runtime, SGX time, E2E vs HR-ABE/Fan, communication and enclave-memory accounting (Tables 2–3, Figs. 4–6, §8.4; pp. 13–17). |
| Paper workload? | Fixed `(A1) AND (B2 OR B3) AND (C2 OR C3)` with 1000–10000-byte files; policy-length AND sweep (pp. 13–15). |
| Paper repetitions? | 30 independent trials averaged for fixed-policy experiments (§8.1–8.2, pp. 13–14); §8.3 repetitions not stated in extracted text. |
| Paper hardware? | Ubuntu 20.04 x64, Intel i7-12700H 12 cores/20 threads, 16 GB, SGX **simulation** mode (p. 13). |
| Source-code availability? | Paper points to https://github.com/Aw-creat/SGX_ABE. Audited HEAD `eeaeb5ea6125077b8a9687d61483ec1f45e43068`; repository contains one uploaded source ZIP with C++/PBC SGX sample-style code plus binaries. Provenance in `BASELINE_IMPLEMENTATION_PROVENANCE.md`. |

The LUAR paper equation and published-source issues are **BASELINE_SPEC_AMBIGUITY**, not permission to silently change its formulas. The paper's simulation-mode times cannot be compared as real-SGX wall-clock ratios with MyABE's QVL-checked SGX DEBUG feasibility cohort.
