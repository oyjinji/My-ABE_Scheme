# Phase 5D stop record — FAIR_COMPARISON_BLOCKER

Status: `BLOCKED_AT_PAPER_AND_FORMULA_AUDIT`. No baseline crypto port, ablation, benchmark plan execution, real-SGX comparative run, dataset, ratio, figure, dashboard, or advantage claim was generated.

## Exact blocking evidence

1. `BASELINE_SPEC_AMBIGUITY`: LUAR §6.3–6.4's published leaf expression gives one `e(g1,g2)^{βst}` per matching row. Its LSSS reconstruction multiplies by `ω_i` yet assumes `Σω_i=1`. A valid two-row AND has `ω=(1,1)`, sum 2; authorized decryption returns the wrong GT mask. See `FORMULA_AUDIT.md` for the full equation and concrete counterexample. The published upstream ZIP also omits active membership enforcement and reads uninitialized time, so it cannot resolve the ambiguity as a correctness oracle.
2. `HRABE_COMMON_BACKEND_BLOCKED`: HR-ABE Figure 2 is symmetric Type-A. A direct Type-III mapping needs a paired G1/G2 hash for the same attribute. Independent hashes fail cancellation; public common-scalar hashing makes attribute key components derivable from CSP-held `L`. See `HRABE_TYPEIII_MAPPING.md`. No secure, paper-faithful BLS12-381 mapping is established.
3. `FABEO_SOURCE_SCOPE_LIMIT`: official τ=1 CP-ABE source is available and byte-identical to local `fabeo22cp`, but its single `sprime` and no coefficient-aware multi-use path cannot be a structural oracle for Figure 1's general τ>1 construction. This is an additional required future correctness gate, not the sole stop reason.

## Scientific consequence

Phase 5D §§4 and 201 explicitly require stopping at an unresolved baseline specification or common-backend issue. The Phase 5D objective of five comparable lines is **not achieved**. Track A/Track B timing, storage ratios, comparative visualization, `SUPPORTED_ADVANTAGES`, and paper-level performance conclusions are `N/A — NOT_EXECUTED`. Paper-native FABEO Charm/MNT224, HR-ABE C++/Type-A, and LUAR SGX-simulation numbers may be cited only as non-comparable paper context.

Existing MyABE observations remain `SGX_DEBUG_GRAMINE_V1`, QVL `OUT_OF_DATE`, strict RA2 `BLOCKED_BY_TCB_POLICY`, explicit `QVL_VERIFIED_OUTDATED_TCB_DEBUG_FEASIBILITY_V1`. They are not production attestation. Formal status remains **CANDIDATE — FORMAL PROOF OPEN**.

The existing same-user/same-ciphertext stable `W` linkability observation remains disclosed; no full per-request unlinkability claim follows from this audit. HR-ABE user revocation, LUAR expiry/attribute revocation, and MyABE exact access-time user revocation are distinct semantics, so a future feature or cost table must keep them separate.

## Resolution needed before a new benchmark attempt

- Obtain an authoritative LUAR correction/erratum or author clarification covering per-row blinding, reconstruction, group orientation, timestamp proof, and active Merkle/root freshness. Do not invent a repair.
- Obtain a security-audited, paper-faithful Type-III HR-ABE mapping, or explicitly remove HR-ABE from direct common-backend wall-clock comparison and re-scope the study. A Type-A native paper number cannot fill the gap.
- Separately validate any future FABEO τ>1 common port against Figure 1 algebra; use the official source only for its τ=1 supported scope.

No Phase 6 work was started.
