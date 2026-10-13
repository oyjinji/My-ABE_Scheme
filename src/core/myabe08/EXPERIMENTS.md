# Phase 4F experimental harness

This package prepares reproducible **TEST smoke** runs for the Exp1–Exp7 map
in `ABE-Scheme-08.md`. It does not execute a formal benchmark or establish a
performance advantage. Formal status remains **CANDIDATE — FORMAL PROOF OPEN**.

Use the CLI from the repository root with `PYTHONPATH=src`:

```
PYTHONPATH=src python3 -m core.myabe08.experiments list
PYTHONPATH=src python3 -m core.myabe08.experiments describe Exp4
PYTHONPATH=src python3 -m core.myabe08.experiments plan all --backend EMULATED_TEE_PROFILE
PYTHONPATH=src python3 -m core.myabe08.experiments smoke all --backend EMULATED_TEE_PROFILE
PYTHONPATH=src python3 -m core.myabe08.experiments validate-run artifacts/myabe08/EMULATED_TEE_PROFILE/<run_id>
PYTHONPATH=src python3 -m core.myabe08.experiments inspect-run artifacts/myabe08/EMULATED_TEE_PROFILE/<run_id>
```

`plan` writes a machine-readable plan without invoking crypto. `--output`
creates a new plan file exclusively. `smoke Exp2` returns the controlled
`BLOCKED_COMMON_BACKEND` result without starting a run. `--seed`, `--warmups`,
`--repetitions`, `--max-samples`, `--root`, and `--run-id` are explicit controls.
The default smoke budget is zero warmups and one measured sample per family;
warmups, if requested, execute the full correct path but never enter raw rows.
The estimated sample count is checked before execution. Large runs are off by
default and this phase does not use `--allow-large-run`.

| Experiment | Contribution | Smoke question | Status |
| --- | --- | --- | --- |
| Exp1 | C1 | Complete-row occurrence ranks, cancellation, and `2+tI` pairing terms across two row sizes | SMOKE_ONLY |
| Exp2 | C1 | Eight-algorithm FABEO comparison on a common audited backend | BLOCKED_COMMON_BACKEND |
| Exp3 | C1–C3 | Canonical CT/AF/credential/Blob/Auth/CT' byte breakdown for simple and repeated policies | SMOKE_ONLY |
| Exp4 | C2 | Contextual token equality and AF candidate behavior, separated by backend | SMOKE_ONLY |
| Exp5 | C1–C3 | Requested versus actual `J`, `k`, `tI`, and request spans | SMOKE_ONLY |
| Exp6 | C3 | Exact revocation lifecycle and a separately labeled synthetic state-only probe at two small RL sizes | SMOKE_ONLY |
| Exp7 | C2–C3 | Canary transcript audit and known stable `W=T0/T_A` observation | SMOKE_ONLY |

Exp2 does not enter a timing dataset. Charm/MNT224 and py_ecc/BLS12-381
durations are not directly compared. Exp6's `REVOCATION_STATE_ONLY` probe
uses synthetic handles and reports logical canonical bytes; it is not an
enclave RevSet dump or a full TEEAuthorize pairing sample. No revocation CT
component, public revocation update key, or tree TK is part of this scheme.

The generator exposes `W-SINGLE`, `W-OR`, `W-AND`, `W-2OF3`, `W-3OF5`, and
`W-REPEAT-ABACA`. Its seed determines only structural synthetic attributes
and input layout. `W-REPEAT-ABACA` retains complete-row ranks
`1,1,2,1,3`; ranks exceeding `cmax` reject instead of changing `cmax`.
Requested `J`/`tI` and actual `J`/`tI` are separate fields. Unsupported
structural overrides reject. Fresh `s`, `r_j`, `delta_q`, request/AEAD nonces,
keys, and enclave randomness continue to use the ordinary CSPRNG. Equal
workload hashes mean equal structure, not identical CT/Auth bytes.

The version is `MYABE08-EXP-SCHEMA-V1`. Each unique run directory is created
exclusively under `artifacts/myabe08/<backend>/<run_id>` by default, or an
explicit external root. It contains `manifest.json`, `plan.json`,
`environment.json`, `code_manifest.json`, `raw.jsonl`, `raw.csv`,
`counters.jsonl`, `correctness.json`, and `artifact_index.json`. JSONL is the
canonical row source; CSV is an export. The manifest starts as `RUNNING` and
is atomically finalized last as `COMPLETE`, `FAILED`, or `INTERRUPTED`.
Existing run IDs never overwrite. No source-tree experiment output is
allowed.

The manifest captures UTC start/end, timezone offset, monotonic duration,
Git HEAD/branch/status/dirty flag, a recursive SHA-256/size manifest of the
possibly untracked `myabe08` tree, the live `ABE-Scheme-08.md` SHA-256,
environment fingerprint, plan hash, backend, and trust cohort. The source
manifest excludes caches and result files. A specification mismatch fails
closed. The environment includes OS/kernel/container signal, CPU and memory,
BIOS/microcode when visible, Python and package versions, GC/affinity,
Gramine/SGX provenance, pairing profile, and PCCS reachability. `validate-run`
checks schemas, hashes, rows, counts, units, source/spec drift, artifacts,
status, and text canaries. A later source change intentionally invalidates
the current-code reproducibility check for an earlier run.

Each raw row carries expected and actual outcome, `correctness_verified`,
sample status, error class, structural variables, registered-unit metrics,
counters, trust metadata, service state, and public facade/code-manifest
provenance. A full correctness precheck precedes all measured rows. Failed
or rejected requests are retained and never folded into successful latency
distributions. Unavailable metrics are `NOT_OBSERVED`, not zero or host
estimates. Duration uses `perf_counter_ns()`; UTC is only for timestamps.
`rpc_receive_ns` includes waiting on enclave work, so it overlaps
`enclave_total_ns` and must not be added as a disjoint duration.

Real SGX runs require an already running genuine Gramine SGX DEBUG service,
PCCS/QVL, and an exact identity policy from the signed build audit. No
EMULATED fallback exists. Their run rows must carry:

```
TEEProfile: SGX_DEBUG_GRAMINE_V1
ExperimentTrustMode: QVL_VERIFIED_OUTDATED_TCB_DEBUG_FEASIBILITY_V1
QVLResult: SGX_QL_QV_RESULT_OUT_OF_DATE
StrictRA2: BLOCKED_BY_TCB_POLICY
EnclaveDebug: true
CurrentHeadMode: TEST_SINGLE_LOGICAL_COORDINATOR
```

The current QVL API succeeds and collateral is unexpired, but platform TCB
is OUT_OF_DATE. These runs belong to a separate trust cohort from any future
QV_RESULT_OK run. Exp4 records same-context equality and the observed
cross-context relationship; no absence of equality proves unlinkability.
Exp7 records same-context equality, AF/J/I/timing/revocation observability,
and stable same-user/same-CT `W`. Raw artifacts contain no plaintext message,
UID, attribute labels, secret key, Blob, stable Blob digest, or PCS key.

Remaining production gaps include platform TCB maintenance and strict RA2,
stable-key provisioning, persistent SGX state, hardware anti-rollback,
trusted time, production remote current-head, a release enclave, formal
security proof, and the audited common FABEO backend. Phase 4F success means
the measurement pipeline is ready for a separately authorized Phase 5A;
it does not mean formal benchmark execution has occurred.

## Phase 5A controlled execution

`experiments/phase5a_plan.json` is the frozen reduced balanced plan for
Exp1, Exp3, Exp4, and Exp5. The full factorial grid exceeds the six-hour
budget. The plan states the original and selected grids, order seed, sample
budget, five warmups, twenty measured repetitions per latency configuration,
and one canonical storage artifact per Exp3 configuration. Twenty repetitions
are explicitly marked as a runtime reduction. Fixed structures use one
structural label seed; cryptographic randomness stays fresh and unseeded.
Policy and user tokenization each process a complete list, so batch sizes
are the actual list lengths rather than simulated independent batch calls.

From the repository root:

```
PYTHONPATH=src python3 -m core.myabe08.experiments phase5a-run Exp3 --backend EMULATED_TEE_PROFILE --cmax 1 --plan src/core/myabe08/experiments/phase5a_plan.json
PYTHONPATH=src python3 -m core.myabe08.experiments phase5a-run Exp4 --backend SGX_DEBUG_GRAMINE_V1 --cmax 2 --plan src/core/myabe08/experiments/phase5a_plan.json
PYTHONPATH=src python3 -m core.myabe08.experiments validate-run artifacts/myabe08/benchmarks/phase5a/Exp4/SGX_DEBUG_GRAMINE_V1/<run_id>
PYTHONPATH=src python3 -m core.myabe08.experiments validate-dataset <run_path> [<run_path> ...]
PYTHONPATH=src python3 -m core.myabe08.experiments freeze-dataset <run_path> [<run_path> ...]
```

Each real run uses a fresh QVL preflight before the WARM measured loop.
Run each selected `cmax` as its own immutable run: public `Setup` freezes
`c_max`, and the validator checks that each CT actually has that many `D_j`
components. `validate-dataset` requires coverage of all frozen configurations
within one experiment/backend cohort.
SGX service startup is outside request latency, inherits the process CPU
affinity, and stops afterward. Actual `J`, `k`, `tI`, and AF hits are retained
separately from requested values. Exp6 and Exp7 run only as revocation and
transcript gates. Exp2 remains `BLOCKED_COMMON_BACKEND`. `freeze-dataset`
produces an immutable cohort manifest and descriptive summary; raw JSONL is
authoritative. EMULATED and real SGX are separate cohorts. These data do not
establish a production attestation claim, security proof, or paper conclusion.
