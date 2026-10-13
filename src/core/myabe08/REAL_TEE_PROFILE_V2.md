# Phase 4C partial profile closure — quote and KGC-head groundwork

**No `SGX_ATTESTED_*` profile is created or enabled.** The existing
`SGX_DEBUG_GRAMINE_V1` remains DEBUG/TEST and accepts only its explicit
insecure TEST bootstrap. MYABE algorithm formulas remain those of
`ABE-Scheme-08.md`. This document records implementation boundaries and
observed Gramine 1.8 behavior, not an attestation security claim.

## Installed Gramine 1.8 path and real quote observation

Gramine's installed `sgx_attest.h` defines `sgx_get_quote`, an 8,192-byte
maximum, and DCAP/ECDSA when SPID is null. The installed `ra_tls.h` defines
RA-TLS certificate creation/verification callbacks and identity fields.
The system has `/run/aesmd/aesm.socket`; Gramine's attestation pseudo-files
are visible inside a signed SGX process. A separate signed TEST artifact uses
`sgx.remote_attestation="dcap"` and the same fixed MYABE service entrypoint.
Inside that enclave, writing `/dev/attestation/user_report_data` then reading
`/dev/attestation/quote` succeeded. One observed ECDSA quote was 4,734 bytes;
Gramine quote-view parsed version 3, sign type 2, DEBUG flags, measurement,
signer and nonempty signature bytes. Quote-view **parses only**; it does not
establish cryptographic validity or acceptable TCB status.

The installed `libra_tls_verify.a` contains
`ra_tls_verify_callback_extended_der` but has an unresolved
`verify_quote_body` backend symbol. No Intel DCAP quote-verification library
or QVL configuration was found in the current container. Consequently no
strict verifier, trusted certificate callback, RA-TLS session or verified
provisioning is active. This observation does not prove that PCCS itself is
unavailable; it identifies the missing verifier path in this environment.

## Canonical quote probe binding

The TEST quote probe uses a verifier-supplied 32-byte challenge, enclave
ephemeral X25519 public key and `SysID`. For the currently deployed DEBUG
profile, the 64-byte Gramine report data is exactly:

```
digest = SHA256(Encode((
    "MYABE-RA-BIND", SysID, "SGX_DEBUG_GRAMINE_V1",
    UInt32(1), challenge_32, enclave_x25519_public_32
)))
report_data = digest || 32 zero bytes
```

This is a **proposed channel-key binding format**, observed in an unverified
quote. The probe discards the ephemeral private key and establishes no
session. It cannot authorize provisioning. Its TEST RPC returns public quote
bytes and a public key only. A future verifier must check quote signature,
collateral/TCB result, deployment-pinned identity, DEBUG policy, report data,
fresh challenge, and possession of the quoted channel key before any secret
is sent. `SgxIdentityPolicy` implements only the deployment identity
predicate. It defaults to rejecting DEBUG, requires exactly one identity
mode, and in signer mode requires product ID plus minimum SVN. It must run
**after** a genuine quote verifier, not on untrusted parsed bytes.

## KGC current-head groundwork

`KGCCurrentHeadService` is a KGC-side single-logical-head transaction core,
not an SGX RPC service. It uses an independent Ed25519 service key, a
single-writer file lock, SQLite WAL with FULL synchronous mode, persistent
head/version/digest and reserved request nonces. Its signed permit binds
`SysID`, session ID, request nonce/digest, transaction ID, version/digest and
service time. Authorization begin/commit and revoke commit are ordered;
stale, same-version fork and local-ahead comparisons fail closed. Its time
source must be injected; there is no fallback to host `time.time()`.

The core has **not** been exposed to the SGX service. No RA-bound caller
authentication, remote transactional transport, enclave trusted-time client,
or durable enclave snapshot recovery exists yet. Unit tests of this KGC
core are not evidence that fresh remote permits protect SGX authorization.

## Sealing and recovery boundary

The installed Gramine SGX PAL contains internal EGETKEY/seal-key logic and
protected-file tools, but this phase did not establish a documented,
enclave-only Python key-derivation/provider contract or a protected
persistent MYABE mount. The Phase 4B application AEAD under runtime TEST
`K_seal` remains the only exercised Blob mechanism; it is not stable across
restart. No snapshot is restored as READY, no old snapshot is accepted, and
the Phase 4B restart still fails closed. The KGC SQLite head is a separate
authority record, not enclave state sealing or rollback protection by
itself.

Because quote verification and an attested channel are blocked, no TEST or
production secret bundle was provisioned through the Phase 4C path. Stable
`K_tok/K_rev/sk_cap`, credential registry, RevSet, request state and Blob
restore remain unimplemented for an attested profile. Release/non-DEBUG
artifact construction was not attempted before the DEBUG RA path closed.

## Phase 4D verifier package audit (2026-09-24)

The environment is Ubuntu 20.04.6 LTS (`amd64`). The installed `gramine`
package is version 1.8. `dpkg -S` identifies it as the owner of
`/usr/lib/x86_64-linux-gnu/libra_tls_verify.a`,
`libra_tls_attest.so`, the RA-TLS header and `gramine-sgx-quote-view`.
The static verifier archive contains only `ra_tls_verify_common.c.o`;
`nm -u` shows unresolved `verify_quote_body` and
`ra_tls_verify_callback` symbols in that object. This is an absent
DCAP-specific **link-time backend**, not evidence that the common archive
itself is an operational QVL. No `libsgx_dcap_quoteverify.so` or installed
Gramine DCAP verifier shared library was found, so runtime QVL calls cannot
be made in the current environment.
An explicit `ctypes.CDLL("libsgx_dcap_quoteverify.so")` check returned
`cannot open shared object file: No such file or directory`; the analogous
DCAP RA-TLS shared-library names also failed to load.

The already configured Gramine repository offers
`gramine-ratls-dcap=1.8`, depending on exactly `gramine (= 1.8)` and
`libsgx-dcap-quote-verify`; the already configured Intel repository offers
`libsgx-dcap-quote-verify=1.22.100.3-focal1`. A no-recommends apt
simulation proposed **two new packages, zero upgrades and zero removals**.
`sudo -n true` returned `sudo: a password is required`. The task forbids
workarounds, so no package was installed or locally unpacked. The exact
candidate command for a privileged maintainer is:

```
sudo apt-get install --no-install-recommends \
  gramine-ratls-dcap=1.8 \
  libsgx-dcap-quote-verify=1.22.100.3-focal1
```

This command is **not executed** here. Intel QVL return codes, collateral
status and PCCS/QPL requirements remain unobserved. Quote-view parsing is
still not quote verification. No `SGX_ATTESTED_DEBUG_GRAMINE_V1` profile,
attested channel or dummy provisioning was enabled.

## Phase 4D-R status (2026-09-24)

Gramine's matching 1.8 DCAP verifier and Intel QVL 1.22.100.3-focal1 are now
installed. `verify_quote_body` is present in the DCAP shared verifier and its
QVL dependency resolves. A newly generated, challenge-bound DEBUG quote was
passed to the actual QVL, whose API returned `0xe00e` =
`SGX_QL_PLATFORM_LIB_UNAVAILABLE` because `libdcap_quoteprov.so` is missing.
The supplemental-size API succeeded (536 bytes), but the verification call
did not produce a TCB/QV result or collateral-expiration finding.

The configured Intel repository offers
`libsgx-dcap-default-qpl=1.22.100.3-focal1`; its matching `-dev` package
contains the unversioned provider-library link sought by this QVL loader.
Neither package was installed in this phase. No PCCS configuration or
collateral behavior is yet observable. The quote's parsed MRENCLAVE, DEBUG
flag and report data are **not** verified identities. The diagnostic probe
still discards its X25519 private key. No strict verified identity policy,
attested channel, dummy provisioning or
`SGX_ATTESTED_DEBUG_GRAMINE_V1` activation occurred. RA1 remains PASS;
RA2–RA5 are blocked, and RA6 is NOT RUN. Resume only after the QPL provider
is available and the actual QVL API, TCB and collateral results pass the
frozen acceptance policy; do not promote a warning result for convenience.

## Phase 4D-Q status (2026-09-24)

The matching Intel QPL runtime package is now installed. The versioned
`libdcap_quoteprov.so.1` loads with complete dependencies. Intel's documented
`sgx_qv_set_path(SGX_QV_QPL_PATH, absolute_versioned_path)` returned success,
so the unversioned development symlink and `-dev` package are **not required**
for this raw-QVL path. A new real SGX DEBUG quote was generated; QVL's
supplemental-size call again returned 536 bytes. Verification advanced from
the old `0xe00e` to **`0xe019` (`SGX_QL_NETWORK_ERROR`)**.

QCNL is configured for
`https://localhost:8081/sgx/certification/v4/` with
`use_secure_cert=true`; a TLS-validating connection from this container was
refused before HTTP. No collateral-expiration or QV/TCB result was produced,
and no verified identity exists. This is a PCCS endpoint/connectivity blocker,
not evidence that the quote passed or failed cryptographic verification.
No configuration or TLS setting was changed. RA1 remains PASS; RA2 is blocked
by collateral retrieval; RA3–RA5 remain blocked, and RA6 was not run. The
attested-debug profile is still disabled and no long-term or dummy secret
was sent through this path.

## PCCS recovery preflight (2026-09-24)

`PCS_API_KEY_PRESENT=true`; `PCS_API_KEY_SOURCE=USER_SECRET_FILE`. The
operator secret file passed owner, `0600`, regular-file, non-symlink,
readability, and nonempty metadata checks. Its contents were not read or
recorded. Pinned NodeSource 20.10.0 and Intel PCCS 1.21.100.3-focal1 archives
were inspected in `/tmp`, not installed. The PCCS package's Node engine
range accepts 20.10.0. A combined apt simulation projected two additions,
no upgrades or removals; PCCS alone would pull 298 packages including
Ubuntu Node 10.19.

PCCS installation could not proceed: passwordless sudo is unavailable, and
the package `postinst` calls `startup.sh`, which exits 5 without systemd or
Upstart directories in this container. Noninteractive startup also skips
the required npm/configuration step. No system service, protected PCCS
configuration, certificate, or collateral endpoint was created. QVL remains
at the previously observed `0xe019`; RA2–RA6 and the attested-debug profile
remain blocked/not run. The existing DEBUG TEST backend is unchanged.

## Manual PCCS and QVL update (2026-09-24)

`PCCSDeploymentMode=MANUAL_FROM_OFFICIAL_DEB_IN_CONTAINER`. Official Intel
PCCS 1.21.100.3-focal1 is deployed under `/opt/intel/sgx-dcap-pccs` and run
directly as the `pccs` user with NodeSource Node v20.10.0. It is neither a
dpkg-configured PCCS package nor a system service. Its sqlite-backed LAZY
cache uses Intel PCS v4 through the container's outbound proxy. A dedicated
local test CA signs a localhost certificate trusted by the system CA store;
QCNL continues to require secure certificate verification.

Certificate-validating `/rootcacrl` returned HTTP 200. A newly generated
real SGX DEBUG quote reached Intel QVL through the configured QCNL/PCCS
path: QVL API `0x0000`, collateral expiration 0, supplemental size 536 bytes,
supplemental version 3.0. The exact QV result is
`0xa002` (`SGX_QL_QV_RESULT_OUT_OF_DATE`). API success proves collateral
retrieval and completion of verification but does not meet the frozen TCB
acceptance policy. RA1 remains PASS; RA2 is `BLOCKED_BY_TCB_POLICY`; RA3–RA6
are not run. This profile is development infrastructure only.

## Phase 4D-TCB strict and feasibility separation (2026-09-24)

The latest fresh real quote and current PCCS collateral again produced QVL
API `0x0`, collateral expiration 0 and QV result
`0xa002` (`SGX_QL_QV_RESULT_OUT_OF_DATE`). Explicit and automatic collateral
paths agreed. The PCK SGX TCB components match Intel TCB Info's OutOfDate
platform level; QE Identity matches UpToDate. Collateral dates and PCCS cache
are current. Classification: `PLATFORM_TCB_OUTDATED`.

Canonical `STRICT_CURRENT_TCB` requires QV_RESULT_OK, so RA2 remains
`BLOCKED_BY_TCB_POLICY`. No attested-debug canonical profile exists. The
separate, explicit, DEBUG/TEST-only experiment carries:

```
TEEProfile: SGX_DEBUG_GRAMINE_V1
ExperimentTrustMode: QVL_VERIFIED_OUTDATED_TCB_DEBUG_FEASIBILITY_V1
RemoteAttestation: QVL_COMPLETED_NONTERMINAL
QVLResult: SGX_QL_QV_RESULT_OUT_OF_DATE
StrictRA2: BLOCKED_BY_TCB_POLICY
EnclaveDebug: true
INSECURE_TEST_OVERRIDE_USED: true
```

`QvlCheckedNonTerminalQuote` is distinct from `StrictVerifiedSgxQuote`.
The feasibility mechanism exercises strict identity/DEBUG predicates,
report-data-bound ephemeral X25519, transcript-bound HKDF-SHA256,
direction-separated AES-256-GCM-SIV records and one random TEST dummy
provision. This is engineering feasibility only: it does not enable MYABE
long-term keys, persistent SGX state, production provisioning or a formal
remote-attestation claim. The canonical TEEProfile remains
`SGX_DEBUG_GRAMINE_V1`.

## Phase 4E-F public TEST facade (2026-09-25)

The host-only `PublicMyABE08` facade adds explicit public calls for the
eight algorithms using the existing real Gramine SGX DEBUG service. It
requires a fresh QVL-checked session and explicit
`QVL_VERIFIED_OUTDATED_TCB_DEBUG_FEASIBILITY_V1` opt-in. Current QVL remains
OUT_OF_DATE and strict RA2 remains `BLOCKED_BY_TCB_POLICY`; the canonical
TEEProfile remains `SGX_DEBUG_GRAMINE_V1`. The TEST current head is
`TEST_SINGLE_LOGICAL_COORDINATOR`. No production attested profile or
provisioning claim is made. The new facade separately supports explicit
`EMULATED_TEST`; the old Phase 1 `MyABE08` signature remains a scaffold.
The new CT' codec and detailed SGX enclave timing breakdown do not yet cover
every requested case. Formal proof remains **CANDIDATE — FORMAL PROOF OPEN**.

The 2026-09-25 validation recorded 255 targeted passes, 393 full-repository
passes and one separately enabled real SGX public integration pass. The SGX
facade's strict selection rejects the actual OUT_OF_DATE quote; explicit
feasibility continues only under the TEST label. These test results do not
change RA2, the canonical profile, or the formal proof status.

## Phase 4E-F-R closure profile (2026-09-25)

The supported package API is `core.myabe08.PublicMyABE08`; the Phase-1
placeholder is under `core.myabe08.legacy` for historical tests only. The
EMULATED and SGX DEBUG TEST paths use canonical CT, Auth and CT' wrappers,
with explicit profile/SysID checks and no backend fallback. Public
`Transform` also checks its DU request state before CSP processing. Real
SGX authorization exposes host transport and enclave stage durations only
as DEBUG/feasibility instrumentation, outside signed Auth semantics. These
are smoke measurements, not formal benchmark results. The same-user/same-CT
`W=T0/T_A` observation remains a known linkability leak.

The trust labels are unchanged:

```
TEEProfile: SGX_DEBUG_GRAMINE_V1
ExperimentTrustMode: QVL_VERIFIED_OUTDATED_TCB_DEBUG_FEASIBILITY_V1
QVLResult: SGX_QL_QV_RESULT_OUT_OF_DATE
StrictRA2: BLOCKED_BY_TCB_POLICY
EnclaveDebug: true
CurrentHeadMode: TEST_SINGLE_LOGICAL_COORDINATOR
```

The QVL result is a platform TCB finding, not an ABE correctness finding.
There is still no current-TCB attested profile, production stable-key
provisioning, persistent SGX state, hardware anti-rollback, trusted time,
production remote current-head, release enclave, audited FABEO common
backend or formal security proof. Status stays
**CANDIDATE — FORMAL PROOF OPEN**.

## Phase 4F experiment provenance

The versioned `MYABE08-EXP-SCHEMA-V1` harness records source/spec hashes,
environment fingerprint, public facade provenance, backend and trust cohort
for every smoke row. Real SGX and EMULATED rows occupy separate run
directories and may not be silently pooled. The real SGX feasibility cohort
continues to record QVL API success, unexpired collateral,
`SGX_QL_QV_RESULT_OUT_OF_DATE`, and strict RA2
`BLOCKED_BY_TCB_POLICY`. The harness does not upgrade the canonical
TEEProfile or turn smoke timing into a formal benchmark. Exp2 remains blocked
until a common audited FABEO backend exists.
