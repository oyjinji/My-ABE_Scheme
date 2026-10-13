# Phase 5D implementation provenance at the formula-audit stop

`ImplementationOrigin` is an explicit classification. A proposed implementation name is not evidence that it exists or passed correctness. No Phase 5D baseline implementation or comparative run has been created.

| Scheme/profile | ImplementationOrigin | Source identity | Validated scope / status |
|---|---|---|---|
| MyABE-08 full | Existing current implementation; outside new baseline-origin enum | `PublicMyABE08`, `ABE-Scheme-08.md` | Existing Phase 5A/5C single-scheme evidence only; no Phase 5D direct comparison. |
| MyABE-NoOccurrenceReuse | `INTERNAL_ABLATION` (planned) | No source created | `NOT_IMPLEMENTED_DUE_TO_FORMULA_AUDIT_STOP`; no ablation result. |
| FABEO22 native CP-ABE | `UPSTREAM_SOURCE` | `src/core/fabeo22cp/__init__.py`, SHA-256 `6f72fbe717cc555dae325241f1a42e992c00bacb1aba027b3aff6ac80a3b0b97`; byte-identical to official https://github.com/DoreenRiepel/FABEO HEAD `144959096b503e51f3b58532d51cbe1602ebea97` | Charm/MNT224 τ=1 native reference; not a BLS12-381 common profile. Local MSP has `unicode`→`str` adaptation, SHA-256 `94f09b22ec54b3611b7bd4e6f383356489fe0350b11ad88a0197db7d7e429bb4`. |
| FABEO22 common BLS12-381 | `COMMON_BACKEND_PORT` (planned) | No source created | `NOT_IMPLEMENTED_DUE_TO_FORMULA_AUDIT_STOP`; official source is τ=1 only. |
| HR-ABE 2024 native | `UPSTREAM_SOURCE` only if later located | No author source located in paper/current repo/exact-title GitHub search | `OFFICIAL_SOURCE_NOT_LOCATED`; native paper C++/Type-A numbers are not local runs. |
| HR-ABE 2024 paper port | `PAPER_REIMPLEMENTATION` (planned) | No source created | `HRABE_COMMON_BACKEND_BLOCKED`: Type-III hash mapping unresolved. |
| LUAR published source | `UPSTREAM_SOURCE` for provenance; `LUAR_UPSTREAM_SIMULATION_REFERENCE` for scientific use | `third_party/luar_upstream/SGX_ABE-main.zip`, SHA-256 `498a37227b36dfce47dd4dc775f8a42dbb75f20077822c28711d0eb958cd5dbb`; https://github.com/Aw-creat/SGX_ABE HEAD `eeaeb5ea6125077b8a9687d61483ec1f45e43068` | Source does not pass paper/correctness audit. Not used for timing. |
| LUAR+BSW07 paper profile | `PAPER_REIMPLEMENTATION` (planned) | No source created | `BASELINE_SPEC_AMBIGUITY`: published §6.4 AND/LSSS decryption formula fails. |
| LUAR common BLS12-381 | `COMMON_BACKEND_PORT` (planned) | No source created | Blocked by paper formula and source audit; no real-SGX smoke. |
| BSW07 supporting | No new port | Existing `src/core/bsw07cp` | Not audited or timed in Phase 5D. |

No native/common wall-clock mixing, cross-curve speedup, or security equivalence is asserted. FABEO source provenance does not validate paper multi-use `τ>1` because its released code uses one `sprime`.
