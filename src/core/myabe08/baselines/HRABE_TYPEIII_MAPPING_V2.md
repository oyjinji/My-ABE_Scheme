# HR-ABE Figure 2 Type-III constraint graph (Phase 5D-R)

Status: **BLOCKED_TYPE_MAPPING**. This is an independent HR-ABE track blocker,
not a blocker for MyABE ablation or FABEO. No HR-ABE timing is eligible.

Figure 2 defines symmetric `e:G×G→GT`. Every Transform1 pairing imposes the
following Type-III orientation constraints; no source-group isomorphism is
available on BLS12-381.

| Pairing edge | Left G1 | Right G2 | Dependency |
|---|---|---|---|
| `e(C2,K_j)` | `C2=g^s` | `K_j=g^{(α+a t_j)/(βγ_j)}` | Public `g` must have G1/G2 counterparts. |
| `e(E_i,L_j)` | `E_i=g^{aλ_i}H1(x)^{-r_i}` | `L_j=g^{t_j/(βγ_j)}` | Ciphertext requires `H1_G1(x)`. |
| `e(D_i,K_{x,j})` | `D_i=g^{r_i}` | `K_{x,j}=H1(x)^{t_j/(βγ_j)}` | TK requires `H1_G2(x)`. |
| `CP1^γ1 = CP2^γ2` | GT | GT | Type assignment alone is not enough. |

Other public parameters: `g1,g1^a∈G1`, `g2∈G2`, `e(g1,g2)^α∈GT`,
`H:{0,1}*→{0,1}^k`, `H2:{0,1}*→Zr`; `C,C1` are GT/bytes,
`D_i,E_i,C2∈G1`, `K_j,L_j,K_{x,j}∈G2`, `γ_j,β,t_j,r_i,λ_i∈Zr`,
`CP_j,T2∈GT`. HK/RK contains scalar `(γ1,γ2)`; DK contains scalar `β`.

Writing `H1_G1(x)=g1^u` and `H1_G2(x)=g2^v` only as *symbolic unknowns*,
the row denominator exponent is
`(a λ_i-u r_i)t_j/(βγ_j) + r_i v t_j/(βγ_j)`.
The `r_i` term cancels iff `u=v`. Then reconstruction
`Σω_i λ_i=s` yields `CP_j=e(g1,g2)^{αs/(βγ_j)}`;
`CP1^γ1=CP2^γ2`, Transform2 returns exponent `αs/β`, and
DU exponentiation by `β` recovers the KEM mask. This verifies the *conditional*
exponent relation, not a realizable hash construction or a formal proof.

Independent hash-to-curve outputs do not guarantee `u=v`, so Transform1
retains the uncancelled term
`Σω_i r_i(v-u)t_j/(βγ_j)`. If `u=v=h(x)` is a **public**
hash-to-scalar, the CSP holding `L_j` can derive
`K_{x,j}=L_j^{h(x)}` for every attribute, bypassing the intended
attribute restriction. A secret correlated map or finite-universe setup
would change the paper's interface and needs a new construction/security audit.

Thus H1/H2/hash-to-group mapping gate H3 fails. H4–H12 cannot qualify for
runtime or wall-clock comparison. Native Type-A paper measurements remain
literature context, never a direct ratio against Type-III py_ecc data.
