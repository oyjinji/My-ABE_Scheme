# Phase 5D formula audit — BASELINE_SPEC_AMBIGUITY

No baseline implementation, correctness claim, or benchmark follows this document. The audited LUAR formula is inconsistent for an authorized two-row AND policy. Changing it would be a new scheme, not a faithful paper implementation.

## LUAR §6.3–6.4 (PDF p. 11): authorized AND counterexample

The paper gives `C_{i,1}=g1^{λ_i}` and `C_{i,2}=H(ρ(i))^{λ_i} h1^{-s}`, with `h1=g2^β`; user components are `K_x=H(x)^t`, `K1=g1^t`, `K0=g2^{α+βt}`. Taking the paper's own intended leaf cancellation at face value,

`DecryptNode(i) = e(C_{i,1},K_x) / e(K1,C_{i,2}) = e(g1,g2)^{β s t}`

for **every** matching row. The stated LSSS condition is `Σ_{i∈I} ω_i λ_i=s`. The paper then claims `Π_i DecryptNode(i)^{ω_i}=e(g1,g2)^{β s t}`. Actual exponent algebra gives `e(g1,g2)^{β s t Σ_i ω_i}`. LSSS reconstruction does not imply `Σ_i ω_i=1`.

The printed intermediate expansion in §6.4 also writes a plus sign where division of pairings requires subtraction. This audit grants the intended single-leaf cancellation above; the reconstruction failure remains even under that favorable reading.

For an authorized two-attribute AND, use rows `(1,1)` and `(0,-1)`, share vector `(s,r)`, shares `λ1=s+r`, `λ2=-r`, and coefficients `ω1=ω2=1`. Then `Σω_i λ_i=s` but `Σω_i=2`. The paper's recovered mask via `e(C1,K0)/Π DecryptNode(i)^{ω_i}` is `e(g1,g2)^{αs−βst}` rather than `e(g1,g2)^{αs}`. Thus it does not recover the AES key `S` for the paper's AND workloads, except accidental degenerate randomness.

A small prime-field exponent check (`p=101, α=7, β=11, s=13, t=17, r=5`) yields rows `(18,96)`, valid `ω=(1,1)`, expected mask exponent `91`, paper-recovered exponent `84`. This check is only algebra; it is **not** a fabricated LUAR implementation or timing measurement.

Potential fixes such as replacing `h1^{-s}` with per-row `h1^{-λ_i}`, normalizing `ω`, or changing key/ciphertext factors are **not** licensed by the paper and may affect its correctness or security proof. Therefore no `LUAR_BSW07_PAPER_PROFILE` or common backend can be asserted without an authoritative clarification and a new equation/proof audit.

## Other LUAR specification/source discrepancies

1. Algorithm 1 (p. 7) declares Type-III `e:G1×G2→GT`. Algorithm 3 (p. 8) labels `g2^{rs}` as an element of `G1`, and Algorithm 4 (p. 9) writes `e(Kτ,h2)` with `Kτ∈G2`, `h2∈G1`, opposite the declared pairing orientation. A Type-III implementation must explicitly resolve these group assignments; silent swaps are forbidden.
2. Algorithm 4 (p. 9) invokes a Merkle check without a fully specified rejection rule, signed/current root binding, or rollback recovery. §5.6 (pp. 9–10) describes a root sent through attestation, but that is not a complete persistent-current-head protocol.
3. Published upstream archive at `eeaeb5ea6125077b8a9687d61483ec1f45e43068` has `Enclave.cpp:116–117` reading an uninitialized `current_time`; `Enclave.cpp:86` hashes `sizeof(attrs[i])` pointer bytes rather than attribute-string length; `Enclave.cpp:93` truncates a fixed nonce into `uint8_t`; the keygen function does not assign `sk->expire_time`; `Enclave.cpp:163` comments out `merkle_verify`. These are source observations, not repaired here. It cannot serve as a validated correctness oracle or real-SGX comparison baseline.
4. LUAR paper §8 (p. 13) used SGX simulation mode; MyABE current cohort uses real SGX DEBUG with QVL result `OUT_OF_DATE` and strict RA2 blocked. These must not be directly compared by TEE latency ratio.

## FABEO Figure 1 versus released source

FABEO Figure 1 left (PDF p. 4) defines occurrence `ρ(i)` and `τ=maxρ`, samples `s'_1…s'_τ`, and uses `H(π(i))^{s'_{ρ(i)}}`. The byte-identical official/source `fabeo22cp` implementation samples only one `sprime`, publishes one `g2_sprime`, and aggregates matching nodes without row-specific LSSS coefficients. The released code is a τ=1 reference. Its ordinary one-use correctness can be checked, but it cannot independently validate general multi-use or weighted threshold cases. A future paper-faithful τ>1 port would need its own algebraic proof/correctness gate before any timing.

## HR-ABE Figure 2 Type-III issue

HR-ABE's symmetric construction uses the **same** `H1(attribute)` in ciphertext `E_i=g^{aλ_i}H1(attribute)^{-r_i}` and key `K_attribute=H1(attribute)^{t/(βγ)}`. A Type-III `e:G1×G2→GT` port needs the ciphertext hash in G1 and the key hash in G2 with paired exponents. `HRABE_TYPEIII_MAPPING.md` shows why ordinary independent hash-to-curve values do not cancel, while a public hash-to-scalar makes any user derive `K_attribute` for arbitrary attributes from L and defeats policy enforcement. No secure, paper-faithful arbitrary-attribute Type-III mapping has been established.

## Decision

`BASELINE_SPEC_AMBIGUITY` and `HRABE_COMMON_BACKEND_BLOCKED` are active. Per Phase 5D §§4, 19–21, 133, 176, 201: **STOP before implementation and formal benchmark**. No cross-scheme speedup, full-system comparison, or advantage statement is supported.
