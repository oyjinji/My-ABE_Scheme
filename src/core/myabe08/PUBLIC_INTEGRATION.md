# Phase 4E-F public integration (TEST feasibility)

`core.myabe08.PublicMyABE08` is the supported facade and exposes `Setup`, `KeyGen`, `Encrypt`,
`Rev`, `RevStateUpt`, `TEEAuthorize`, `Transform`, and `FinalDec`. The caller
selects `SGX_DEBUG_GRAMINE_V1` and explicitly selects either
`STRICT_CURRENT_TCB` or
`QVL_VERIFIED_OUTDATED_TCB_DEBUG_FEASIBILITY_V1`. The current platform's
QVL result is `SGX_QL_QV_RESULT_OUT_OF_DATE`; strict `Setup` rejects before
TEST bootstrap. The explicit `EMULATED_TEE_PROFILE` backend uses
`EMULATED_TEST` and existing software protocol components, with no SGX or
QVL claim. Neither backend automatically falls back to the other.

The SGX path runs only with `test_tee_bootstrap=True`, an exact SGX identity
policy, a running real Gramine SGX service and working QVL/PCCS. `Setup`
checks a fresh quote/session with Intel QVL before invoking the existing
DEBUG TEST bootstrap. That bootstrap is experimental and does **not** make
long-term KGC/TEE key provisioning production safe. The implementation
holds the KGC signing key and `K_rev` in the TEST coordinator; the enclave
retains `K_tok`, capability signing key, sealing key, exact RevSet, and
ephemeral T0 material. The test coordinator is explicitly
`TEST_SINGLE_LOGICAL_COORDINATOR`. A process restart fails closed through
the SGX instance ID and readiness check; persistent SGX state is unavailable.

`KeyGen` returns a credential, DU recovery key and enclave-issued opaque
blob. The authentication private key is caller-held and never sent to the
SGX service. `Encrypt` rejects an empty or non-bytes message before RPC,
then sends policy labels through the existing DO channel to the SGX service
for tokenization. The host performs policy row preparation, AF build,
existing algebra encryption and signed publication. `Rev` creates one
pending KGC update; `RevStateUpt` submits that exact protected record on
the same session, verifies the enclave acknowledgement and commits the
TEST current head. `TEEAuthorize` sends credential, blob and possession
proof over the existing private ingress; enclave verification, RevSet
lookup, tokenization, T0 pairing and capability signing stay in SGX.
`Transform` verifies publication/capability and performs AF, LSSS and T_A
on the CSP host. `FinalDec` uses the DU recovery key only on the caller
side and authenticates the DEM ciphertext. The facade records smoke timing
spans for each public algorithm and checks observed TEE/CSP pairing counts.
`workload_metadata` records public dimensions and trust labels. Successful real
SGX authorization returns nonnegative host pre/post-RPC, transport send/receive,
enclave total, and six enclave stage observations. Enclave stages are sampled
inside the measured Gramine process around the actual operations. The
receive interval includes waiting for the response and therefore overlaps
server execution; these intervals must not be summed with enclave time as
disjoint durations. Timing metadata is outside Auth/cap signatures and is
DEBUG/TEST-only. No benchmark conclusion is drawn.

`serialize_ciphertext`/`parse_ciphertext`,
`serialize_authorization`/`parse_authorization`, and
`serialize_partial`/`parse_partial` provide one versioned canonical CT, Auth,
and CT' contract for both supported TEST profiles. Auth parsing requires its
CT for signed header binding. Framing, lengths, group encodings, profile and
SysID are checked; the public protocol still verifies signatures at use.
These are not formats for MSK, enclave state or RevSet. The legacy Phase-1
`MyABE08` scaffold is available only through `core.myabe08.legacy`.

The supported call graph uses the current `myabe08` AF, algebra, LSSS,
credential, publication, capability, revocation and SGX service modules.
It does not import historical ABE implementations at runtime. Abstract
`Protocol` methods in `crypto.py`, `credential.py`, and `state.py`, plus the
explicit Phase-1 scaffold, are not the concrete public facade path. The
closure tests cover canonical round trips and negative encoding cases,
field-level CT/Auth mutation, request/cap/bundle mixing, replay and wrong RK.
`E` is not a published CT member in this scheme: corruption of reconstructed
`E_hat` through `T_A` is tested at the DEM authentication boundary.

Synthetic UID and attribute canaries are scanned against public reprs,
captured output, errors and metadata, while the real SGX test scans its
service log. No actual secret is printed to perform this audit. The known
stable same-user/same-CT `W=T0/T_A` linkability remains disclosed.

The real public test is enabled only by `MYABE08_RUN_SGX_PUBLIC=1` and uses
the separately signed DCAP DEBUG build in
`MYABE08_SGX_DEBUG_BUILD_DIR` (default `/tmp/myabe08-sgx-ra-probe`). It is a
correctness and mechanism check, not a benchmark or formal proof. Every
artifact must retain TEEProfile `SGX_DEBUG_GRAMINE_V1`, ExperimentTrustMode
`QVL_VERIFIED_OUTDATED_TCB_DEBUG_FEASIBILITY_V1`, QVL result
`SGX_QL_QV_RESULT_OUT_OF_DATE`, StrictRA2
`BLOCKED_BY_TCB_POLICY`, and DEBUG=true. Same-user/same-CT `W=T0/T_A`
remains stable across fresh rerandomization and is linkable.

The real SGX path is not current-TCB attested or production-ready. Formal security
proof status remains **CANDIDATE — FORMAL PROOF OPEN**. Production stable-key
provisioning, persistent SGX state, hardware anti-rollback, trusted time,
trusted remote current-head, release enclave, and audited FABEO common
backend are open. No performance conclusion is claimed.
