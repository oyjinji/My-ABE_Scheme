# HR-ABE Figure 2 → Type-III mapping audit

Status: `HRABE_COMMON_BACKEND_BLOCKED`; no Type-III implementation was written. This document does not transfer the paper's symmetric-pairing security proof to BLS12-381.

Original paper: Li et al. 2024, Fig. 2 (PDF p. 7), symmetric `e:G×G→GT`. For a Type-III `e:G1×G2→GT`, the obvious orientation is:

| Paper element / pairing | Tentative Type-III placement | Audit result |
|---|---|---|
| `C2=g^s`, `D_i=g^{r_i}` | G1 | First pairing arguments. |
| `E_i=g^{aλ_i}H1(ρ(i))^{-r_i}` | G1 | Requires `H1_G1(attribute)`. |
| `K_j=(g^α g^{a t_j})^{1/(βγ_j)}`, `L_j=g^{t_j/(βγ_j)}` | G2 | Second pairing arguments. |
| `K_{attribute,j}=H1(attribute)^{t_j/(βγ_j)}` | G2 | Requires `H1_G2(attribute)` correlated with `H1_G1`. |
| `e(C2,K_j)` | `e(G1,G2)` | Group orientation possible. |
| `e(E_i,L_j)·e(D_i,K_{attribute,j})` | `e(G1,G2)·e(G1,G2)` | Cancellation demands `e(H1_G1(x),g2)=e(g1,H1_G2(x))`. |
| `CP1^γ1=CP2^γ2` | GT equality | Type-III placement does not resolve the hash problem. |
| `C=R·e(g,g)^{αs}` and DU Dec | GT, symmetric ciphertext structure | Would need new correctness/security audit after hash resolution. |

If `H1_G1(x)` and `H1_G2(x)` are independent hash-to-curve outputs, the cross-group hash terms in Transform1 do **not** cancel. If both are produced as `g1^{h(x)}` and `g2^{h(x)}` from a **public** hash-to-scalar, then `K_{x,j}=L_j^{h(x)}` is computable by the CSP from `L_j` for any attribute x, bypassing the intended attribute restriction. A setup-generated correlated pair with hidden exponent would restrict the publicly usable universe and alter the original arbitrary-attribute interface. None is specified by the paper.

This is a concrete mapping/security ambiguity, not an ordinary implementation choice. It prevents the proposed `HRABE2024_COMMON_BLS12381_V1` from qualifying as a paper-faithful, secure common-backend baseline. Native Type-A C++ paper times may be cited as context only; they cannot enter direct timing ratios with MyABE's Type-III Python/py_ecc profile.
