# Phase 4A — real SGX/Gramine environment audit

Date: 2026-09-24. This is a read-only environment and integration audit, apart
from safe runs of existing debug examples and a capability probe in their
existing manifest. `ABE-Scheme-08.md` remains the only MYABE algorithm
specification. No MYABE runtime code, production manifest, signing key, driver,
or provisioning state was changed. No secret bytes were read or printed.

## Scope and starting state

The repository began with `git status --short` reporting only
`?? src/core/myabe08/`; that entire directory was already untracked. The
phase-start SHA-256 manifest is `/tmp/myabe08_phase4a_before.json` (1,725 files,
55 under `myabe08`). The normative 08 document SHA-256 was
`d52daf431bfececa4b1b8bf0f77fe34634710c9502d372f405b75b806812df85`.

## Observed platform and commands

| Read-only probe | Observation |
|---|---|
| `ls -l /dev/sgx* /dev/isgx` | `/dev/sgx_enclave` `crw-rw-rw- root:root` major/minor 10:125; `/dev/sgx_provision` `crw-rw---- root:sgx_prv` 10:126; no `/dev/isgx`. Current user belongs to `sgx_prv`. |
| `lscpu`, `/proc/cpuinfo`, `/proc/misc` | Intel Xeon Silver 4410Y, `sgx` and `sgx_lc` CPU flags; misc entries 125 `sgx_enclave`, 126 `sgx_provision`, 124 `sgx_vepc`. This is consistent with the upstream in-tree SGX interface. `/proc/modules` has no `isgx`/`sgx` module; kernel configuration was not readable, so built-in driver status is not independently established here. |
| `uname -a` | Linux 5.15.0-139-generic, x86_64. |
| `dmesg` | Not observable: kernel buffer read denied (`Operation not permitted`). EPC size was not observable from this container. |
| `gramine-sgx --version` | Gramine 1.8; `/usr/bin/gramine-sgx`, `gramine-direct`, `gramine-manifest`, `gramine-sgx-sign`, `gramine-sgx-get-token`, `gramine-sgx-sigstruct-view` exist. The absence of a `gramine` umbrella command is not a failure. |
| Package/library metadata | `libsgx-urts` and `libsgx-enclave-common` 2.25.100.3-focal1; `libsgx_urts.so`, `libra_tls_attest.so`, `libsecret_prov_attest.so` visible. `gramine-dcap`, `gramine-ratls-dcap`, `libsgx_dcap_ql`, `libsgx_dcap_quoteverify`, and a PCCS configuration were not found in the inspected container. This does not establish the host's full DCAP state. |
| AESM | `/var/run/aesmd/aesm.socket` exists and an AF_UNIX connect/close succeeded. `systemctl` is unavailable because this container is not booted with systemd; no local `aesmd` process was observed. Host-side AESM service mode remains unknown. |
| Signing key metadata | `/home/jinjio_TEE_container/.config/gramine/enclave-key.pem` exists with mode `0600`, owned by the current user. Its contents were not opened. |

## Existing applications and provisioning sources

The active repository contains no signed Gramine manifest or MYABE SGX entry
point. Its `src/core/myabe08/attestation.py`, `channel.py`, `sealing.py`, and
`revocation.py` are software emulation. No deployed MYABE provisioning server,
RPC endpoint, trusted remote head, or production SGX service was located in the
repository or searched home project directories.

The machine has preserved **test artifacts**, distinct from the active
repository:

* `/tmp/gramine-sgx-hw-test/gramine-v1.8/CI-Examples/helloworld/` — signed
  Gramine `helloworld` debug example.
* `/tmp/gramine-python-sgx-test/example/` — signed Python debug example,
  including `scripts/test_pyecc_pairing.py` and `scripts/sgx-report.py`.
* `/tmp/gramine-sgx-hw-test/gramine-v1.8/CI-Examples/ra-tls-secret-prov/` —
  Gramine **source examples** for RA-TLS secret provisioning. The minimal,
  programmatic, and encrypted-files examples describe a host server verifying
  an enclave client quote and delivering a secret to that client. No built,
  running provisioning server/client or validated MYABE policy was found there.
* `/tmp/myabe08-gramine-run/` and `/tmp/myabe08-validation-e82dff3.neGXF0/`
  contain old temporary manifests/copies referring to paths absent from the
  active repository. They are not evidence of a currently deployed MYABE SGX
  service. They were not launched or altered.

The secret-provisioning source demonstrates a possible **future** mechanism:
client `libsecret_prov_attest.so` can create RA-TLS evidence and receive a
server-provided secret over a TLS/TCP connection. The minimal and
encrypted-files variants use `LD_PRELOAD` constructor-time delivery before
client `main`; the richer client calls the library at runtime. The
encrypted-files variant can use the delivered value as a Gramine
encrypted-files key. It is not currently bound to MYABE's `K_tok`, `K_rev`,
`sk_cap`, or user base state. The sample server measurement callback prints
MRENCLAVE/MRSIGNER/ISV fields then returns success without comparing expected
values; sample clients print received secrets. These examples are unsuitable
as-is for MYABE provisioning and were **not run**. No real secret was
reprovisioned.

## Actual runtime and manifest

The signed Python example is an entire Python 3.8.10 process inside Gramine
SGX: `libos.entrypoint=/usr/bin/python3.8`; Gramine's loader starts it with
host-supplied argv. This is architecture **A for the demo only**. MYABE-08 has
**no real SGX runtime architecture yet**; its classification is **UNKNOWN**,
because there is no MYABE enclave entry point, service, or IPC. The existing
MYABE emulation is not a hardware trust boundary.

For the actually launched Python example, the template/manifest reports:

* `sgx.debug=true`, `sgx.remote_attestation="none"`, EDMM disabled, 1 GiB
  enclave size, 32 maximum threads, 2 MiB stack.
* Python binary/runtime, system and user-site package directories, and
  `scripts/` are mounted/trusted. The expanded signed manifest contains
  15,967 individual trusted-file entries and 12 mounts. Adding/changing a
  trusted script changes the manifest/measurement after regeneration.
* `/tmp` is enclave tmpfs. No encrypted/protected persistent mount, `sgx.seal`,
  explicit allowed-file entry, or file-check override was present in this
  example. Network/IPC permissions were not exercised; no MYABE RPC framing,
  authentication, request nonce, or connection lifecycle exists in it.
* `loader.insecure__use_cmdline_argv=true` intentionally forwards untrusted
  host arguments. This is acceptable only as demo configuration, not a
  reviewed MYABE service policy.

An existing signed example was launched, not rebuilt. `gramine-sgx helloworld`
exited 0 and printed `Hello, world`. `gramine-sgx python
scripts/helloworld.py` exited 0. An attempt to run the example's
`test_python.py` outside its trusted `scripts/` directory was denied; no
manifest was changed. `gramine-direct python ...` failed before Python with
`PAL failed setting personality failed: Operation not permitted (EPERM)` in
this container. This direct-mode restriction does not invalidate the SGX runs.

## Capability smoke, with execution location

| Capability | Host Python 3.8.10 | Gramine-direct | Gramine-SGX debug example |
|---|---|---|---|
| Python import/execute | PASS | FAIL: container `personality` EPERM | PASS |
| `cryptography` 42.0.8, `py_ecc` 8.0.0, PyYAML 6.0.3, NumPy 1.24.4 imports | PASS | Not reached | PASS |
| Charm package import | PASS | Not reached | PASS; MYABE trusted path does not require Charm |
| Ed25519 sign/verify, X25519 shared secret, AES-256-GCM-SIV nonempty roundtrip, HKDF-SHA-256 | PASS | Not reached | PASS, one functional probe each |
| `py_ecc.optimized_bls12_381` G1/G2 operations and one pairing | PASS in this audit | Not reached | PASS; bilinearity and argument consistency true; fingerprint `7cfb1f8af2291547b63d70f63497cb2a93ada51ef9a8c6ae6105417e9935b3bc` matches the current host run |
| `os.urandom(32)` and `os.getrandom(32)` | PASS for `urandom` | Not reached | PASS; output length checked, bytes not printed |
| `fsync`, atomic `os.replace`, directory `fsync`, `threading.RLock` | Not needed for this gate | Not reached | PASS in enclave `/tmp` **tmpfs only**; durable protected-file semantics are untested |

The Python SGX example generated a 432-byte **local SGX report** (not a remote
quote). It reported DEBUG=true, MRENCLAVE
`efbac8429f8190d17b6a6975700673a42a950126f1f2786910ce241bc8551fd4`,
MRSIGNER
`4e7eb4653ddbd23b4ae7c31d1f6a96c29f34a616af0b9a45905462bc424d4717`,
ISVPRODID=0, ISVSVN=0 and zero test REPORTDATA. These identify the **Gramine
Python validation enclave**, not MYABE. The current signed manifest disables
remote attestation, and no safe complete quote-generation/verification command
was found. Remote quote and RA-TLS provisioning smokes were **NOT RUN**.
The `python -c` cryptography/storage probes used the example's intentionally
untrusted command-line argv: their code is not part of the signed measurement.
They establish functional execution under SGX, not an attestable MYABE code
identity or a production entry point.

The example uses one enclave per launch; its state is lost on exit. No
long-lived process, worker pool, load/save of MYABE state, authenticated RPC,
or crash recovery was observed. The `gramine-sgx` launch exposed no PAL,
filesystem, thread, mmap, or pairing error in the successful probes.

## Storage, freshness, and deployment boundary

The active MYABE `EmulatedSealing` and Phase 3C authenticated snapshot stores
are application AEAD under software-held keys. The Gramine provisioning
examples show an encrypted-files template, but no signed running protected
files application was audited. Confidentiality/integrity from encryption is
**not** rollback protection. No hardware monotonic counter, trusted remote
current-head service, distributed coordinator, or trusted hardware clock was
found. Python `time.time()` works in the test enclave but is not thereby
trusted time. The current Phase 3C `LinearizedCurrentHeadCoordinator` is a
single-process software reference, not a multi-enclave freshness authority.

The proposed MYABE trust boundary, **not yet implemented**, is:

`KGC (outside SGX)` → `measurement-bound provisioning / attested channel` →
`narrow MYABE trusted-control-plane service (inside SGX)` ↔
`CSP host (AF.Query, AuthorizedSubset, T_A outside SGX)` →
`DU (RK and FinalDec on DU side)`.

The enclave should hold `K_tok`, `K_rev`, `sk_cap`, user `mu/K0` base states,
RID handles/RevSet, credential-version and request state, plus current-head
client state. KGC should retain `alpha`, `a`, `sk_KGC` outside the CSP-side
enclave. DU keeps `RK` and plaintext result outside that enclave. Policy labels
may enter a narrowly authenticated DO→TEE policy-tokenization request;
certified user attribute set enters the trusted authorization path. The audit
found no existing code that provisions the whole KGC master secret to SGX, but
also no real MYABE provisioning path proving this separation.

| Current abstraction | Observed real mechanism | Status for Phase 4B |
|---|---|---|
| EmulatedAttestation | SGX local report works; Gramine RA-TLS libraries/source exist, but signed Python example has RA off and no verified remote quote/policy | **BLOCKED** for remote attestation; define quote verification and expected measurement/debug/TCB policy |
| EmulatedSecureChannel | Gramine RA-TLS and secret-provisioning client library available; no MYABE peer/framing/replay protocol | **ADAPTER NEEDED** |
| EmulatedSealing | Application AEAD today; Gramine encrypted-files source template only | **ADAPTER NEEDED**; persistent SGX state and keys untested |
| EmulatedClock | Python wall time callable inside enclave, but host-controlled | **BLOCKED** for trusted expiry source |
| EmulatedPersistentState | `fsync`/rename works in enclave tmpfs; no protected durable mount/freshness source demonstrated | **ADAPTER NEEDED**, with anti-rollback still blocked |
| LinearizedCurrentHeadCoordinator | In-process software lock/snapshot only; no trusted external head discovered | **REFACTOR NEEDED** for a cross-process authenticated head, and **BLOCKED** for trustworthy freshness |
| Provisioning interface | Gramine sample source/library; no deployed MYABE provisioning server or measurement allowlist | **ADAPTER NEEDED**; demo callback and secret logging must not be reused |
| Phase 3A BLS12-381 backend | py-ecc primitive functions run inside the debug SGX example | **DIRECT REUSE** at library level only; MYABE T0 still must be integrated and measured in a MYABE enclave |

Recommended architecture for the next phase is **Option A: a narrow Python
MYABE trusted-control-plane service in Gramine SGX**, with CSP AF/LSSS/T_A on
the host and DU RK/FinalDec outside. This uses the verified Python/py-ecc
runtime while limiting enclave attack surface relative to moving the whole
CSP process into SGX. It requires a new authenticated RPC boundary, a
measurement-bound provisioning policy, durable protected state with a trusted
freshness authority, and a real enclave lifecycle; none is direct from the
observed examples. A whole-process SGX design would collapse CSP/TEE
boundaries and enlarge measured dependencies. Reusing the sample C
provisioning callback directly would accept unapproved measurements and log
secrets, so it is not a viable shortcut.

## Phase 4A smoke gates and safety limits

| Gate | Result | Evidence/limit |
|---|---|---|
| S1 Gramine-SGX launch | PASS | Existing signed `helloworld`, exit 0 |
| S2 Python inside SGX | PASS | Existing signed Python example, exit 0 |
| S3 cryptography inside SGX | PASS | Import and four non-secret primitive checks |
| S4 py-ecc inside SGX | PASS | Import of optimized BLS12-381 |
| S5 one BLS12-381 pairing inside SGX | PASS | Existing deterministic test, group checks and expected fingerprint |
| S6 SGX Python randomness | PASS | `os.urandom` and `os.getrandom` lengths |
| S7 remote attestation/quote path | NOT RUN | Only local report demonstrated; signed example has `remote_attestation=none` |
| S8 dummy provisioning | NOT RUN | No safe built flow; sample logs secrets and does not enforce measurement allowlist |

No benchmark or timing comparison was run. No production signing identity,
secret, manifest, driver setting, or service was modified. SGX debug execution
and primitive compatibility do **not** establish that MYABE currently runs
inside SGX or that its revocation state is rollback-resistant.

## Phase 4B observed update (2026-09-24)

The Phase 4A paragraph above was the starting observation. A narrow MYABE
service now runs as the fixed `core.myabe08.real_tee.service` module in a
signed Gramine SGX **DEBUG** enclave. The local SGX report's MRENCLAVE and
MRSIGNER matched the signed sigstruct in the explicit hardware integration
test, and its DEBUG bit was set. The final measurement and signed-manifest
hash are recorded in the out-of-repository `build_audit.json`; rebuilding
trusted source changes the measurement.

With TEST-only bootstrap/head/time, the hardware test exercised DO policy
tokenization, DU authorization including a real enclave-side BLS12-381 T0,
cap signing, KGC revoke and activate Delta/Ack, and a second authorization.
Host-side AF/LSSS/T_A and DU-side FinalDec recovered a nonempty TEST
plaintext. Revoked authorization returned before another T0 pairing.
After stopping and relaunching the service, authorization remained
unavailable until explicit bootstrap. The service's TEST log contained no
tested UID or key encodings. These are tested workloads, not proofs of
secret non-disclosure.

Remote attestation remains **blocked**: the signed manifest explicitly uses
`remote_attestation="none"`. The installed `libra_tls_attest.so` alone does
not provide a verified MYABE expected-measurement/DEBUG/TCB policy or
session binding. Accordingly no dummy verified provisioning was attempted.
The TEST socket/bootstrap, in-process head, TEST time, enclave tmpfs state
and runtime-generated application sealing key do not close production
provisioning, trusted time, persistent state, or rollback/freeze gates.

## Phase 4C observed update (2026-09-24)

A separate signed MYABE DEBUG artifact with `sgx.remote_attestation="dcap"`
successfully generated a real 4,734-byte SGX ECDSA quote through Gramine's
`/dev/attestation/quote`. Its public report data matched a canonical
challenge/X25519-public-key digest, and Gramine quote-view parsed the signed
artifact's measurement and DEBUG attributes. **The quote has not been
cryptographically verified**; quote-view is a parser. The installed
`libra_tls_verify.a` lacks its `verify_quote_body` backend, and no DCAP QVL
was found in the container. Strict RA-TLS verification and provisioning
therefore remain blocked. No dummy or production secret was sent under the
Phase 4C route. See `REAL_TEE_PROFILE_V2.md` for the exact binding rule and
KGC current-head groundwork. The Phase 4B TEST route remains separate.

## Phase 4D blocker audit (2026-09-24)

Ubuntu 20.04.6 has Gramine 1.8 installed but not its DCAP RA-TLS verifier
package or Intel DCAP QVL. The configured package sources offer matching
`gramine-ratls-dcap=1.8` and `libsgx-dcap-quote-verify=1.22.100.3-focal1`.
The simulated installation adds only those two packages, with no upgrades or
removals. Passwordless sudo is unavailable; per the Phase 4D instruction,
no package installation or local extraction workaround was attempted.
`verify_quote_body` remains unresolved in Gramine's common verifier archive.
No raw quote was passed to QVL, no collateral or TCB result was obtained,
and no new RA session or provisioning was attempted. The existing real quote
generation result remains intact; RA2–RA5 remain blocked by the missing
verifier package chain, and RA6 remains not run.

## Phase 4D-R QVL probe (2026-09-24)

The previous package blocker is gone: `gramine=1.8`,
`gramine-ratls-dcap=1.8`, and
`libsgx-dcap-quote-verify=1.22.100.3-focal1` are installed.
`libra_tls_verify_dcap.so` and its `_gramine.so` variant resolve their
dynamic dependencies to `libsgx_dcap_quoteverify.so.1`. The DCAP shared
objects contain a local `verify_quote_body` implementation; the unresolved
reference in the *common static archive* is no longer a blocker when using
the installed DCAP shared backend. Intel QVL exports both required APIs.
No package was installed or upgraded in this phase.

An unchanged signed Gramine DEBUG/DCAP test artifact was launched once and
generated a **new** 4,734-byte quote with a fresh 32-byte challenge and
ephemeral X25519 public key in the existing report-data binding. Its private
key is still discarded by the Phase 4C diagnostic service, so this quote
cannot establish an attested channel. The quote parser again checked only
structure; it did not authenticate the quote.

The raw quote was passed to the real Intel QVL via `ctypes`, loading
`libsgx_dcap_quoteverify.so.1`. The FFI argument order and types were checked
against `sgx_dcap_quoteverify.h` from the matching Intel 1.22 development
package, inspected in `/tmp` without installation. The QVL supplemental-size
API returned `0x0000`, size **536 bytes**. The verification call used the
verifier host UTC time and returned **`0xe00e`**, which Intel's matching
`sgx_ql_lib_common.h` defines as
`SGX_QL_PLATFORM_LIB_UNAVAILABLE`. Its loader diagnostic was exactly
`libdcap_quoteprov.so: cannot open shared object file: No such file or
directory`. The collateral-expiration and quote-verification-result outputs
were not written by this failed call; their sentinel values are **not** TCB
results. QVL made no cryptographic acceptance decision.

The missing provider belongs to the configured Intel package
`libsgx-dcap-default-qpl=1.22.100.3-focal1`, which is not installed. Package
contents inspected without installation also show that the unversioned
`libdcap_quoteprov.so` link requested by this QVL loader belongs to
`libsgx-dcap-default-qpl-dev=1.22.100.3-focal1`. No QPL/QCNL library or
`/etc/sgx_default_qcnl.conf` exists in the current container. Therefore a
PCCS URL, network condition, collateral freshness, and TCB result cannot yet
be diagnosed. A no-recommends apt simulation for the two exact-version QPL
packages reported two additions, zero upgrades, zero removals; it was **not
executed**. No QPL file was copied or symlinked into the runtime.

The mandated QPL stop condition was applied: no identity was accepted from
parsed quote bytes, no new attested profile, channel, or dummy provisioning
was created. RA1 remains PASS, RA2 is blocked by the missing provider, RA3–RA5
are blocked behind RA2, and RA6 was not run. The existing SGX DEBUG TEST and
EMULATED paths remain separate.

Phase 4D-R validation: MYABE targeted tests **249 passed, 2 skipped in
215.97 s**; full repository **387 passed, 2 skipped in 232.71 s**; explicit
real SGX DEBUG E2E plus quote-generation regression **2 passed in 21.55 s**.
The single new raw-QVL diagnostic call failed before TCB evaluation; it is
not counted as successful quote verification. No secret was generated or sent
by this phase's RA path. A phase-start SHA-256 manifest is stored at
`/tmp/myabe08_phase4dr_before.json`; comparison shows zero new, two modified
(this audit and `REAL_TEE_PROFILE_V2.md`), zero deleted MYABE files. The
`ABE-Scheme-08.md` SHA-256 remains
`d52daf431bfececa4b1b8bf0f77fe34634710c9502d372f405b75b806812df85`.

## Phase 4D-Q QPL/PCCS continuation (2026-09-24)

The maintainer installed `libsgx-dcap-default-qpl=1.22.100.3-focal1` before
this phase. It matches installed Intel QVL `1.22.100.3-focal1`; Gramine and
its DCAP verifier remain at 1.8. The runtime package provides
`/usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so.1` and the QCNL wrapper.
`ldd` found no missing dependencies and `ctypes.CDLL` loaded the versioned
QPL successfully. `libsgx-dcap-default-qpl-dev` is **not** installed and was
not needed for this probe; no symlink, library copy, or package installation
was performed. The Intel 1.22 header defines `SGX_QV_QPL_PATH=1` and
`sgx_qv_set_path(sgx_qv_path_type_t, const char*)`.

One new Gramine SGX DEBUG/DCAP quote (4,734 bytes) was generated with the
existing challenge/public-key report-data format. In the verifier process,
`sgx_qv_set_path(1, "/usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so.1")`
returned `0x0000`. The supplemental-size API returned `0x0000` and 536
bytes. `sgx_qv_verify_quote` used verifier host UTC time and returned
**`0xe019` = `SGX_QL_NETWORK_ERROR`**. The earlier `0xe00e` platform-library
error was eliminated. The failed verification did not set a valid collateral
expiration status or QV/TCB enum; supplemental major/minor version is also
unavailable. No quote was cryptographically accepted.

The installed `/etc/sgx_default_qcnl.conf` sets
`pccs_url=https://localhost:8081/sgx/certification/v4/`,
`use_secure_cert=true`, and no active separate `collateral_service` URL.
A certificate-validating `curl` attempt to that configured endpoint from
the current container failed with **connection refused** (`curl` exit 7,
HTTP 000). This establishes that the configured local endpoint is not
reachable here; it does not establish the status of any host-side PCCS.
QVL's `0xe019` and this connection failure indicate a collateral retrieval
network blocker. The precise missing collateral object and its TCB status
cannot be determined without a responding endpoint. No PCCS setting, TLS
validation policy, package, or service was changed.

The prescribed stop condition applies: Phase 4D-Q is blocked by the
configured PCCS endpoint. Verified identity, DEBUG policy, private-key
retention, attested channel, and dummy provisioning were not advanced.
The previous note suggesting the QPL `-dev` symlink as a possible requirement
is superseded by this successful `sgx_qv_set_path` test: the runtime `.so.1`
was sufficient to eliminate `0xe00e`.

Phase 4D-Q regression results: MYABE targeted **249 passed, 2 skipped in
211.93 s**; full repository **387 passed, 2 skipped in 239.93 s**; explicit
real SGX DEBUG E2E plus quote-generation suite **2 passed in 21.84 s**.
The new QPL/QVL diagnostic made one SGX launch, one quote and one QVL verify
call, with one QPL load, zero accepted quotes, and one API error. It made
zero verified sessions, dummy provisions, or RA secret sends. The SGX
regression suite had additional independent launches. No Phase 4D-Q
attested-channel test could run after the mandated PCCS stop.
Three SGX regression log files created after the phase snapshot (1,848 bytes
total) were scanned for private-key delimiters and named secret-log markers;
none matched. No dummy secret was created, so there was no new provisioning
RPC transcript to inspect.

## PCCS recovery preflight with user secret file (2026-09-24)

`PCS_API_KEY_PRESENT=true` and `PCS_API_KEY_SOURCE=USER_SECRET_FILE`.
The repository-external operator secret passed `lstat` checks for an existing,
nonempty, readable regular file, owned by the current user, mode `0600`, and
not a symlink. Its contents were **not read** in this preflight; no key bytes,
fragments, or digest were emitted or copied. There was no PCCS configuration
write.

Before this phase, `node`, `nodejs`, and `npm` commands and the PCCS package
were absent. The exact NodeSource archive
`nodejs_20.10.0-1nodesource1_amd64.deb` was downloaded to `/tmp`; Debian
metadata confirms package `nodejs`, version `20.10.0-1nodesource1`, amd64.
Its unpacked executable ran as `v20.10.0` (bundled npm `10.2.3`). This is
**not** a system installation. The exact Intel archive
`sgx-dcap-pccs_1.21.100.3-focal1_amd64.deb` was likewise downloaded and
inspected without installation. Its `package.json` permits Node
`>=20.0.0 <=20.11.1`, and `install.sh` checks a minimum of `v18.17.0` using
the `node` command. Node 20.10.0 meets both rules; no `nodejs` compatibility
link is needed by that installer.

Installing PCCS alone through the current apt indexes would add **298**
packages, including incompatible Ubuntu Node 10.19. A combined no-recommends
simulation with the exact local NodeSource deb and pinned PCCS package would
add **2** packages, upgrade **0**, remove **0**, and leave Gramine/QVL/QPL
unchanged. Neither simulation was executed. `sudo -n true` returned
`sudo: a password is required`, so no privileged package operation is
available to this Codex process.

There is a second independent package-install blocker: the official PCCS
Debian `postinst` calls `startup.sh debian`. In noninteractive mode that script
skips `install.sh`, then requires either `/run/systemd/system` or `/etc/init/`.
Both are absent in this container (PID 1 is `bash`); it otherwise exits 5.
Thus the requested noninteractive apt command would predictably leave the
package configuration incomplete even with sudo. The archive has no bundled
`node_modules`; `install.sh` performs `npm install` and also requires
`cracklib-check`, which is currently absent. No post-install script was run.
The package's default, unconfigured JSON has the requested PCS URI,
LAZY/sqlite mode, 127.0.0.1 host, and port 8081, but its `ApiKey` and token
hashes are empty; this is **not** a running PCCS configuration.

No old PCCS tree or database existed to back up. The existing QCNL config
remains root-owned mode `0644` with SHA-256
`44e85493c98124b6e0e0c415044cb0124dbe65c4fa0ae77776f4556484bf64b6`.
No Node/PCCS package, CA certificate, service, config, or QCNL file was
changed. QVL was not rerun; the last actual result remains `0xe019`, with
no valid TCB result. RA1 remains PASS; RA2–RA5 remain blocked; RA6 was not
run. A system administrator must provide a supported privileged installation
and service lifecycle before collateral retrieval can resume.

## Manual PCCS recovery and real QVL result (2026-09-24)

Interactive sudo enabled installation of NodeSource
`nodejs=20.10.0-1nodesource1`; both `node` and `nodejs` report v20.10.0 and
npm reports 10.2.3. The official Intel
`sgx-dcap-pccs_1.21.100.3-focal1_amd64.deb` payload was manually deployed
under `/opt/intel/sgx-dcap-pccs`. Its package.json identifies PCCS 1.21.0.
The Debian `postinst` was not run; dpkg does not report PCCS configured.
Deployment mode is `MANUAL_FROM_OFFICIAL_DEB_IN_CONTAINER`. Dependencies from
the matching official DCAP_1.21 lockfile are present, including loadable
ffi/ref and sqlite native modules. A non-login `pccs` system account runs
the official Node entry directly, with no system service.

The external PCS key file passed regular-file, no-symlink, current-owner,
`0600`, readable and nonempty checks. A root helper read it directly and
atomically wrote its value to the PCCS JSON config without displaying it or
putting it in the repository, arguments or environment. Config is
`pccs:pccs`, mode `0600`, with HTTPS 8081, `127.0.0.1`, `LAZY`, sqlite,
Intel PCS v4 and the container's local outbound proxy. The initial upstream
attempt stalled because the PCCS proxy setting was empty; setting the
container's `127.0.0.1:6969` proxy restored upstream requests. A dedicated
test CA signs a localhost server certificate with DNS/IP SAN and serverAuth;
the chain verifies. Both private keys are mode `0600`. Only the public CA
was added to system trust. The existing QCNL URL and
`use_secure_cert=true` setting were unchanged.

Official `pccs_server.js` listens as `pccs` on `127.0.0.1:8081`. Normal
TLS-validating curl reached `/` (HTTP 404, no root route) and
`/sgx/certification/v4/rootcacrl` (HTTP 200, TLS verification result 0).
During QVL, PCCS returned HTTP 200 for platform PCK CRL, TCB info, QE
identity and root CA CRL; upstream Intel request IDs were logged. This
confirms real QCNL-to-PCCS and PCCS-to-PCS collateral retrieval. PCCS logs
were compared against the complete PCS key and contained no match.

A fresh, challenge-bound 4,734-byte quote came from the signed Gramine SGX
DEBUG enclave. QPL loaded, `sgx_qv_set_path` returned 0, and the supplemental
size API returned 0 with 536 bytes. Real `sgx_qv_verify_quote` returned
**`0x0000`**, eliminating `0xe019`. Collateral expiration status is **0**;
supplemental version is **3.0**. The distinct QV result is **`0xa002` =
`SGX_QL_QV_RESULT_OUT_OF_DATE`**. Under the frozen policy, RA2 is
`BLOCKED_BY_TCB_POLICY`, not PASS. RA3–RA6 were not advanced and
`SGX_ATTESTED_DEBUG_GRAMINE_V1` remains disabled. No attested secret
provisioning occurred.

This phase's regression runs completed: MYABE targeted **249 passed, 2
skipped in 213.38 s**; full repository **387 passed, 2 skipped in 228.11 s**;
explicit real SGX DEBUG integration and quote-generation tests **2 passed in
22.44 s**. The PCCS/QVL diagnostic itself made one additional real SGX
launch, one fresh quote and one QVL verification call, with zero accepted
quotes, verified sessions or dummy provisions. Only `nodejs` was installed as
a system package; no package was removed. System changes comprise the Node
package files, the `pccs` account, the manual `/opt` PCCS tree and the public
local CA in the system trust store. The QCNL config hash remains
`44e85493c98124b6e0e0c415044cb0124dbe65c4fa0ae77776f4556484bf64b6`.
Relative to the phase-start 78-file MYABE manifest, no MYABE files were
created or deleted; only this audit and `REAL_TEE_PROFILE_V2.md` changed.
The separate `ABE-Scheme-08.md` retains SHA-256
`d52daf431bfececa4b1b8bf0f77fe34634710c9502d372f405b75b806812df85`.

## Phase 4D-TCB diagnosis and DEBUG feasibility (2026-09-24)

PCCS remained operational (certificate-validating rootcacrl HTTP 200); no
PCCS, QCNL, DCAP package, BIOS, firmware or SGX factory state was modified.
The installed Intel QVL/QPL pair is `1.22.100.3-focal1`, SGX runtime
libraries are `2.25.100.3-focal1`, Gramine is 1.8, and Node is v20.10.0.
The needed QVL/QPL ABI works; this is a coherent focal software path, not an
observed mixed-version failure. Host-visible CPU is GenuineIntel family 6,
model 143, stepping 8, Xeon Silver 4410Y, microcode `0x2b000639`.
Host-visible DMI is Supermicro X13SEI-F (Super Server), American Megatrends
BIOS 2.2 dated 2024-03-04.

The final fresh SGX DEBUG quote was generated after rebuilding the signed
test enclave for the new session code. Its SHA-256 diagnostic identifier is
`fb4aa94f3d1e2b752c3b34e18994c5a3ce34eb2d14d91335fef3bc8b7c178b91`.
Intel's quote-v3 header/schema parser reports ECDSA-P256 attestation key,
SGX TEE, QE SVN 11, quote-header PCE SVN 16, Intel QE vendor ID, DEBUG=true,
ISV product ID 0, ISV SVN 0 and certification-data type 5 (PCK certificate
chain). Current MRENCLAVE is
`e34c596506bf7f2169c70ce451680d90152d4e202f7b6af647368460f9870777`;
MRSIGNER remains
`254d64d3002fea063747913d1abd80c4088a901d858e1bbe6ac8ec37528194b0`.
The previous MRENCLAVE changed because the enclave's trusted Python code
and manifest were rebuilt; the phase-start MRENCLAVE was
`c42639118a748958bfc074188576f38152244dea7e2c5568d99796a667311044`.
No decoded PPID or encrypted PPID value was printed or stored in the
repository. One initial `gramine-sgx-quote-view` diagnostic emitted its raw
signature field to tool output; that field embeds the PCK certificate chain
and may contain encoded platform-identifying certificate extensions. Later
parsers emitted selected header and certificate metadata only. Treat that
initial tool output as potentially sensitive; do not copy it into artifacts.

Intel `tee_get_fmspc_from_quote` returned FMSPC `90806F000000`. The embedded
PCK chain has three certificates and valid chain signatures. The PCK leaf is
valid from 2026-09-18 to 2033-09-18; its PCEID is `0000`. Its certified SGX
TCB component SVN vector begins `[7,7,2,2,3,1,0,255]` (remaining entries
zero) and its PCK PCE SVN is 11. The PCCS TCB Info v3 for the same FMSPC and
PCEID was issued 2026-09-24 14:15:36 UTC, expires 2026-10-24 14:15:36 UTC,
and has evaluation data number 20. The first Intel TCB level matching that
PCK vector is dated 2024-03-13 and marked **OutOfDate**, with advisories
`INTEL-SA-01079`, `INTEL-SA-01103`, `INTEL-SA-01111` and `INTEL-SA-01313`.
The current UpToDate level requires at least `[9,9,2,2,4,1,0,255]`.
The quote's QE report has product ID 1, SVN 11 and the expected Intel QE
signer. QE Identity was issued 2026-09-24 13:25:25 UTC, expires 2026-10-24,
has evaluation number 20, and its UpToDate level requires SVN 8. The QE
therefore matches **UpToDate**; it is not the observed OUT_OF_DATE source.
PCCS sqlite inserted the TCB and QE cache records at 14:30:36 and 14:30:38
UTC respectively. Fresh TLS-validating PCCS GET responses matched the exact
JSON returned via Intel's explicit collateral API. The cache is not stale by
these checks, and no cache entry was deleted or refreshed.

For the **same fresh quote**, QVL's automatic collateral path and
`tee_qv_get_collateral` plus explicit `sgx_qv_verify_quote` both returned
API `0x0`, collateral expiration 0, QV `0xa002` and supplemental version 3.0
(536 bytes). Root-cause classification is **PLATFORM_TCB_OUTDATED**. The
available evidence excludes a QE-identity outdated result, expired or stale
collateral, invalid PCK chain and an observed DCAP software version failure.
It does not establish whether a particular BIOS, IFWI or microcode component
alone will resolve the platform TCB deficit; that requires OEM maintenance
information and a fresh post-maintenance quote.

`STRICT_CURRENT_TCB` accepts only QVL API success, collateral expiration 0
and QV_RESULT_OK. This quote remains **strict RA2 rejected** with
`BLOCKED_BY_TCB_POLICY`. No `SGX_ATTESTED_DEBUG_GRAMINE_V1` profile was
created. A separate explicit DEBUG/TEST opt-in labels the checked quote
`QvlCheckedNonTerminalQuote` and uses
`QVL_VERIFIED_OUTDATED_TCB_DEBUG_FEASIBILITY_V1` as an *ExperimentTrustMode*,
while the TEEProfile remains `SGX_DEBUG_GRAMINE_V1`. INVALID_SIGNATURE,
REVOKED, UNSPECIFIED, unknown QV results, API failures and expired collateral
remain rejected in both paths. The feasibility path is not production,
current-TCB attestation or a formal remote-attestation security claim.

The SGX process now retains each ephemeral X25519 private key only in its
session manager memory. A fresh challenge, session ID and keypair precede
each new quote. Host Intel QVL, TCB decision, authenticated identity/DEBUG
fields and frozen report-data binding are checked before the verifier
activates the TEST channel. HKDF-SHA256 includes SysID, TEE profile,
experiment mode, protocol version, session ID, challenge, quote digest, QV
result and both X25519 public keys. AES-256-GCM-SIV records have separate
direction keys, session binding and monotonic sequence numbers. In the real
SGX feasibility test, identity/DEBUG acceptance and negative substitutions,
replay, rollback and tampering checks passed. One fresh random 32-byte TEST
dummy was delivered in one session; the enclave returned only
`PROVISION_TEST_OK`, length and request ID. `strict_secrets_sent_count=0` and
`feasibility_dummy_sent_count=1` in that run. No MYABE long-term secret was
provisioned. Because QVL is used in host-library mode and the enclave cannot
authenticate the host's QVL assertion, this remains a TEST mechanism result,
not a production channel claim.

No software package remediation was performed. The operator should consult
Supermicro's official X13SEI-F BIOS/IFWI and applicable microcode releases
for the listed Intel advisories, plan host maintenance separately, then
reboot and repeat a fresh quote, collateral retrieval and QVL check. No
factory reset or PCK reset is indicated by the evidence collected here; none
was performed or requested. Persistent/sealed SGX state must be considered
before any future OEM-prescribed reset.

Phase 4D-TCB regression results: targeted MYABE **254 passed, 3 skipped in
206.40 s**; full repository **392 passed, 3 skipped in 217.37 s**; separate
real Gramine SGX integration, quote diagnostic and QVL feasibility suite
**5 passed in 24.65 s**. The real mechanism suite exercised one accepted
random TEST dummy, zero strict secret sends, and rejects for identity/DEBUG,
old challenge/quote binding, key and metadata substitution, cross-session
record, replay, rollback, direction swap and AEAD tampering. QVL's automatic
and explicit collateral paths were also independently compared on the final
fresh quote outside the pytest suite.

Historical source and experiment output were not edited.

## Phase 4E-F public integration attempt (2026-09-25)

The host-only `PublicMyABE08` facade composes the eight MYABE-08 algorithms
over the existing real SGX DEBUG service. It explicitly QVL-checks a fresh
session before TEST bootstrap. Current QVL remains API success, collateral
expiration 0, `SGX_QL_QV_RESULT_OUT_OF_DATE`; strict RA2 remains
`BLOCKED_BY_TCB_POLICY`. The feasibility label is an ExperimentTrustMode,
not an attested TEEProfile. The new facade also supports explicit
`EMULATED_TEST` using the existing software protocol. The old Phase 1
`MyABE08` contract remains separate; there is no automatic backend fallback.

Real SGX policy tokenization, exact RevSet update, credential/blob checks,
T0 pairing and capability signing remain in the Gramine process. AF/LSSS,
T_A and signed publication run on the host; RK and FinalDec stay on the DU
side. The public integration test calls the eight facade methods for its
core flow, uses an explicit TEST current-head coordinator, and never sends
real MYABE production secrets. This is mechanism and correctness evidence
only. See `PUBLIC_INTEGRATION.md` for the interface and open limits.

Phase 4E-F validation: MYABE targeted tests **255 passed, 4 skipped**;
full repository tests **393 passed, 4 skipped**; separately enabled real
Gramine SGX/QVL public integration test **1 passed**. The real test covered
single, OR, AND, 2-of-3, 3-of-5 and repeated A/B/A/C/A policies; strict
TCB rejection; active unauthorized LSSS rejection; revoke/activate and an
unconsumed historical Auth; pairing invariants; replay, mixing, wrong RK,
selected CT/AF/Auth tampering; canonical SGX CT' parse negatives; stable W;
and restart fail-closed. The service log contained neither the TEST UID nor
the KGC's TEST K_rev. The source-tree scan found no historical-runtime import
or core placeholder in `public.py`. The ABE-Scheme-08.md SHA-256 remains
`d52daf431bfececa4b1b8bf0f77fe34634710c9502d372f405b75b806812df85`.

This is a **partial Phase 4E-F result**. The legacy Phase 1 `MyABE08`
signature still has placeholders; the new facade is a separate public API.
CT' wire format is SGX TEST-only; a complete EMULATED CT' wire profile and
full adversarial field matrix are open. Per-phase enclave timing values and
separate RPC send/receive durations are unobserved (`None`) rather than
invented. The host enforces QVL-before-bootstrap in this TEST process, but
the enclave does not independently authenticate that host QVL assertion.
Accordingly the P1–P20 gate set is not all complete and Phase 4F is not
authorized by the stated progression rule.

## Phase 4E-F-R public integration closure (2026-09-25)

`PublicMyABE08` is now the package-root supported eight-algorithm facade.
The Phase-1 placeholder is explicit at `core.myabe08.legacy.LegacyMyABE08`;
the package root no longer exports `MyABE08`. The supported public source
and runtime-import audit excludes historical ABE implementations. The
concrete public path uses current MYABE-08 algebra, AF, LSSS, credential,
capability, publication, revocation, and SGX service code. `Transform`
rechecks DU request/response binding and the selected backend profile before
CSP work; `TEEAuthorize` and `FinalDec` likewise reject a wrong profile.

The CT, Auth, and CT' wire wrappers now share a versioned canonical contract
for EMULATED and real SGX DEBUG TEST profiles. CT and Auth parsing checks
the expected profile and SysID; Auth parsing requires the CT for signed
header binding. Adversarial tests use generated public objects to mutate
CT components, AF slots and metadata, publication material, Auth bundle and
capability fields; they also test mixing, one-time replay, wrong RK and
invalid encoding. Published CT has no standalone `E` field: reconstructed
`E_hat` corruption is tested through DEM authentication. The machine-readable
test matrix records case ID, object, field, expected/actual rejection, and
error class without secret values.

The real Gramine DEBUG service now returns seven TEST-only timing observations:
enclave total, credential verification, exact RevSet lookup, tokenization,
rerandomization, T0 pairing, and cap signing. The host independently records
pre/post-RPC and socket send/response intervals. Successful authorization
requires all observations to be nonnegative and the enclave stage sum not
to exceed enclave total. These observations are outside Auth/cap signed
content and are smoke instrumentation, not benchmark data. Socket response
time includes waiting on service execution and must not be added to enclave
time as though disjoint. Synthetic UID/attribute canaries are checked against
public reprs, errors, captured output, metrics and timing metadata; the real
service log is checked for the TEST UID, KGC TEST key, and stable Blob digest.
Same-user/same-CT `W=T0/T_A` remains linkable.

Closure validation recorded **260 passed, 4 skipped** in the targeted MYABE
suite, **1 passed** in the separately enabled real SGX public marker, and
**398 passed, 4 skipped** in the full repository suite. A final focused run
of the closure tests after adding machine-readable mixing/replay/RK records
and extra privacy error paths recorded **5 passed**. No formal benchmark was
run. The approved ABE-Scheme-08 specification hash remains
`d52daf431bfececa4b1b8bf0f77fe34634710c9502d372f405b75b806812df85`.

QVL still reports API success, unexpired collateral, and
`SGX_QL_QV_RESULT_OUT_OF_DATE` from `PLATFORM_TCB_OUTDATED`.
`STRICT_CURRENT_TCB` still rejects at RA2. This DEBUG feasibility work does
not create `SGX_ATTESTED_DEBUG_GRAMINE_V1`, current-TCB trust, production
provisioning or a formal proof. Formal status remains
**CANDIDATE — FORMAL PROOF OPEN**.

## Phase 4F experiment harness boundary

`experiments/` registers the unchanged Exp1–Exp7 map and generates
structural synthetic workloads. Exp2 is `BLOCKED_COMMON_BACKEND`; no
Charm/MNT224 versus py_ecc/BLS12-381 timing comparison is run. The harness
uses only `PublicMyABE08` for its algorithm paths, performs a complete
correctness precheck before measured smoke rows, and writes versioned,
hash-checked, no-overwrite artifacts outside the source tree. Unobserved
metrics stay `NOT_OBSERVED`; failure classes are not combined with successful
request samples. The real SGX path has no EMULATED fallback and continues to
require fresh QVL-checked DEBUG feasibility selection.

The run manifest records the live specification and code-tree hashes,
environment and dependency fingerprint, SGX provenance, QVL result, PCCS
reachability, and trust cohort. Text artifacts are checked for forbidden
fields and synthetic canaries. Same-context token equality and stable
same-user/same-CT `W=T0/T_A` remain documented leakage, not an
unlinkability claim. The harness is infrastructure for later controlled
experiments; this phase does not make a formal benchmark or proof claim.

## Phase 5A benchmark trust boundary

Controlled real SGX DEBUG samples retain the QVL-checked `OUT_OF_DATE`
feasibility mode and `BLOCKED_BY_TCB_POLICY` strict RA2 result. Each run
performs fresh QVL preflight before the measured loop; the preflight duration
is recorded separately. The EMULATED cohort is kept distinct. Exp2 remains
blocked by the missing common audited backend, while Exp6 and Exp7 are used
only as correctness and privacy gates. Raw data may be analyzed later but do
not upgrade this platform to current-TCB trust. Formal status remains
**CANDIDATE — FORMAL PROOF OPEN**.
