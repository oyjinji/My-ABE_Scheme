# SGX_DEBUG_GRAMINE_V1 — Phase 4B implementation profile

This is a **DEBUG/TEST execution profile**, not a production SGX security
profile. MYABE algorithm formulas remain governed solely by
`ABE-Scheme-08.md`. The Phase 4A environment evidence remains in
`REAL_TEE_AUDIT.md`.

## Measured process and trust boundary

`gramine-sgx myabe08_tee` launches the fixed
`python3.8 -B -m core.myabe08.real_tee.service` entrypoint. Its signed
manifest is generated from `real_tee/gramine/myabe08_tee.manifest.template`.
The measured process imports the existing MYABE trusted authorization,
revocation, credential, sealing, and BLS12-381 code. It does not run CSP
AF.Query, LSSS reconstruction, attribute pairing T_A, or DU FinalDec. The
Gramine Python runtime and listed Python dependencies remain part of its TCB.

Inside the enclave process: generated TEST `K_tok`, `sk_cap`, application
`K_seal`, RevSet and request state, user `mu/K0` (in process or application
AEAD Blob), contextual tokenization, request rerandomization, py-ecc T0
pairing, and capability signing. The KGC generates TEST `K_rev` and sends it
through the explicitly insecure bootstrap boundary. `alpha`, `a`, KGC
signing private key and DU recovery key `RK` are not bootstrap fields and
are not held by the normal SGX service. The host owns the signed ciphertext,
AF, LSSS and T_A; the DU owns `RK` and FinalDec. Python key zeroization is
not established.

## TEST transport and bootstrap

The loopback TCP service uses one canonical V1 request per connection. A
frame contains `MY08` magic, version 1, a fixed message type, 16-byte
request ID, 32-bit payload length and canonical MYABE V1 payload. Types
have explicit size limits (maximum 2 MiB for authorization), and malformed
or replayed frames are rejected. Responses use bounded canonical payloads
or fixed error codes; exception messages and Python object representations
are not returned.

`DEBUG_TEST_BOOTSTRAP` is one-shot and requires the manifest's explicit
TEST flag and `TEST_CURRENT_HEAD`. The public algebra parameters and KGC
verification key enter through this test path. The enclave generates other
TEST secrets itself. KGC's TEST `K_rev` crosses an unauthenticated socket:
**INSECURE_TEST_BOOTSTRAP**. X25519/HKDF/AES encrypted TEST sessions carry
subsequent DO, DU and KGC records, but these ephemeral keys are **not
attested to an expected measurement**. The socket and TEST session are not
an attested secure channel and have no production provisioning claim.

Before bootstrap, authorization paths return `STATE_UNAVAILABLE`. Restart
discards the enclave tmpfs state and generated keys; there is no implicit
empty RevSet or active-user fallback. The next authorization again returns
`STATE_UNAVAILABLE` until a new explicit TEST bootstrap. An old Blob cannot
be opened after new runtime keys are generated.

## Authorization and state semantics

The SGX service calls the existing `tee.py` trusted primitives. Policy
tokenization requires a signed DO namespace certificate, a signed
session/context-bound proof, and an encrypted TEST DO session. User
authorization validates credential, possession, Blob, publication and
current TEST state; checks exact RevSet membership inside SGX; derives
request ephemeral group components and performs T0 in the measured process;
then signs the existing Auth/cap schema with enclave-resident `sk_cap`.
The service reports a non-secret T0 pairing count. The host uses the
existing `csp_transform_verified` and the DU uses `finaldec_algebra_core`.

`REV_STATE_UPDATE` decrypts and validates the protected Delta inside SGX,
updates exact RevSet, and signs an Ack. `TEST_COMMIT_HEAD` coordinates the
single-process TEST head. This integration tests ordering and fail-closed
behavior, **not** freshness security. Time is an explicit TEST integer
source; no trusted time provider is configured. A production-style path
without trusted current head/time is unavailable and must fail closed.

User Blob protection is application AES-GCM-SIV under enclave-process TEST
`K_seal`. It is not SGX hardware sealing or durable anti-rollback storage.
Revocation/head snapshots currently use enclave tmpfs and vanish on exit.
`fsync`/rename and a state digest alone do not add rollback resistance.

## Build, tests and security limits

`real_tee/gramine/build_sgx.sh` signs only a TEST manifest with a separate
0600 TEST RSA key outside the repository, defaulting to
`/tmp/myabe08-sgx-debug-build-v2/`. `build_audit.json` records the signed
manifest hash, MRENCLAVE, MRSIGNER, ISV fields, DEBUG flag and profile.
The measurement is intentionally not hardcoded into source.
`real_tee/gramine/run_sgx.sh` launches that signed artifact. Run SGX tests
only with `MYABE08_RUN_SGX_TESTS=1` and pytest `-m sgx`; ordinary pytest
skips the hardware integration module.

The current signed manifest sets `sgx.debug=true` and
`sgx.remote_attestation="none"`. A local report checks execution in a
DEBUG SGX enclave and provides measurement evidence; it is not a remotely
verified quote. Gramine's installed RA-TLS attestation library is not a
strict MYABE verifier. RA quote generation, measurement/DEBUG/TCB policy,
fresh channel-key binding and verified dummy provisioning remain blocked.
No example accept-all verifier or secret-printing provisioning server is
used. This profile cannot establish production confidentiality, trusted
freshness, multi-instance synchronization, or formal scheme security.
