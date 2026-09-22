# My-ABE_Scheme

Attribute-based encryption implementations and their experiment suites, from
the FABEO / FX-ABE line of work. Everything here runs against Charm-Crypto's
PBC backend with `PairingGroup("MNT224")` and reports real group operations and
real serialized sizes — no mock groups, no `sleep`-based timing, no
`sys.getsizeof`.

The repository is split three ways: **scheme code** (`src/core`), **standalone
measurement scripts** (`src/benchmarks`), and **five self-contained experiment
suites** (`src/experiments`). Cross-suite inputs and outputs live in
`shared/`.

## Layout

```
My-ABE_Scheme/
├── src/
│   ├── core/           the schemes themselves: 23 packages, 22 importable
│   ├── benchmarks/     one file per measurement study; run as scripts
│   └── experiments/    five experiment suites, each with its own configs,
│                       runners, results/, docs and tests
├── shared/
│   ├── configs/        dataset descriptors shared between suites
│   ├── data/           DACP dataset workspace (raw → work → encrypted →
│   │                   recovered → products); bulk contents not committed
│   ├── docs/           cross-suite experiment guides and report templates
│   └── results/        DACP output trees; bulk contents not committed
├── pytest.ini          test discovery; sets `pythonpath = src`
├── requirements.txt    authoritative dependency list
└── README.md           this file
```

### `src/core` — the schemes

| Group | Packages |
| --- | --- |
| Reference CP-ABE | `bsw07cp`, `waters11cp`, `ac17cp`, `abgw17cp`, `cgw15cp`, `fabeo22cp` |
| Reference KP-ABE | `abgw17kp`, `ac17kp`, `cgw15kp`, `fabeo22kp`, `gpsw06kp` |
| Reference DFA | `fabeo22dfa`, `waters12dfa` |
| FX-ABE prototypes | `fxabe_rev` (dual-epoch revocable, anonymous index), `fxabe_05_3_exp` (frozen 05.3 algebra) |
| DACP prototype | `dacp` (data-access-control protocol: `components`, `data`, `marketplace`, `protocol`) |
| FXDACP prototype | `fxdacp` (FX-ABF + DACP) |
| Comparison skeletons | `fabesa`, `ipecp`, `lacsprp`, `mynewcp`, `newcp2.0` |
| Shared | `msp` (LSSS/MSP policy conversion) |

The comparison skeletons under `fabesa`, `ipecp`, `lacsprp`, `mynewcp` and
`newcp2.0` are **structural placeholders** kept so the benchmark runners have
something to time. Their own docstrings say which subroutines are not faithful
implementations; read those before citing anything measured on them.

`newcp2.0` cannot be imported as a package (a `.` is not a valid identifier
character). Four scripts in `src/benchmarks/compare_*newcp20*.py` load it
through an explicit `importlib` shim under the alias `core.newcp20_dynamic`.

### `src/benchmarks` — measurement scripts

Flat directory of runnable scripts. Each one bootstraps its own `sys.path` and
is invoked directly, e.g.:

```bash
python3 src/benchmarks/run_cp_schemes.py     # all reference CP-ABE: setup/keygen/encrypt/decrypt
python3 src/benchmarks/run_kp_schemes.py     # reference KP-ABE
python3 src/benchmarks/run_dfa_schemes.py    # reference DFA
python3 src/benchmarks/run_dacp.py           # DACP protocol walkthrough
python3 src/benchmarks/measurements_cp.py    # timed primitive measurements
```

This directory is deliberately **not** a package: there is no `__init__.py`
here, the scripts share no imports, and `pytest` collects the `test_dacp_*.py`
files here as top-level modules.

### `src/experiments` — the five suites

Each suite owns its `configs/`, `runners/`, `results/`, `docs/` and `tests/`,
and records its own run ledger. They do not read or overwrite each other's
results.

| Suite | Mode | Question | Entry point |
| --- | --- | --- | --- |
| `index_v1` | FX-ABF filter microbenchmarks | How do eight `token → posting list` retrieval backends compare on build, space, and Transform-scaling? | `python3 -m experiments.index_v1.runners.run_all --profile smoke --run-id <id>` |
| `index_v2` | Composed-index + algorithm-level index comparison | Do five index constructions differ once locator/PStore/metadata bytes are accounted for honestly? | `python3 -m experiments.index_v2.benchmarks.run_suite --config <cfg> --validate --plot --report` |
| `perf_05_3` | Primitive-level, frozen 05.3 algebra vs FABEO core | What does this exact backend charge per operation, and is each structural claim falsifiable? | `python3 src/experiments/perf_05_3/scripts/run_pipeline.py --config <cfg> --run-id <id>` |
| `global_exp` | End-to-end | FABEO22 vs FXABE-Base vs FXABE-Full on identical workloads: compute, storage, total cost | `python3 src/experiments/global_exp/scripts/run_all.py --config <cfg> --run-name <name>` |
| `rev_exp` | Dual-epoch tree revocation | How do RevKeyUpt, Cover/KU size, Transform and dual-vs-coupled epochs scale with users and revoked set? | `python3 src/experiments/rev_exp/scripts/run_all.py --config <cfg> --run-name <name>` |

`index_v1` and `index_v2` are run as **modules** (their runners use relative
imports), so they need `PYTHONPATH=src` outside pytest. `perf_05_3`,
`global_exp` and `rev_exp` are run as **scripts** and resolve their own paths.

Every suite ships `configs/smoke.yaml`, `configs/standard.yaml` and
`configs/full.yaml`. Smoke is plumbing validation on tiny workloads; Standard is
the peer-reviewable tier; Full is expensive and should not be launched
casually.

Only `perf_05_3` enforces that in code — `scripts/run_suite.py` exits on
`mode == "full"` and directs you to the explicit gated `run_full.py` sequence
after `PRE_FULL_AUDIT.md` reports `FULL_READY=YES`. `index_v1`, `index_v2`,
`global_exp` and `rev_exp` have **no such runtime gate**; for those, `full.yaml`
is a documented command that will simply start. Check `docs/RUN_LEDGER.md` (or
the suite's equivalent) before choosing a profile.

## Install

```bash
python3 -m pip install -r requirements.txt
```

Verified against Python 3.8.10. `charm-crypto==0.63` is pinned: the recorded
byte-size results depend on its MNT224 serialization layout. The per-suite
`src/experiments/*/requirements.txt` files are historical declarations of what
each suite asked for when it was written; `requirements.txt` is authoritative.

## Import and path conventions

Two conventions are load-bearing, and both are already satisfied — this section
exists so they stay satisfied.

1. **`src` is the import root.** `pytest.ini` sets `pythonpath = src`, which is
   why the suites import `core.*` and `experiments.*` as top-level names. When
   you run a module-form entry point by hand, supply the same root yourself:

   ```bash
   PYTHONPATH=src python3 -m experiments.index_v2.benchmarks.run_suite --config ...
   ```

   `src` is a path root, **not** a package: it has no `__init__.py`, and neither
   does `src/benchmarks`. `src/core/__init__.py` and
   `src/experiments/__init__.py` are the actual package roots.

2. **The repository root is computed from source location.** Scripts that need
   it derive it as `Path(__file__).resolve().parents[N]`, and the DACP layer
   exposes one shared helper instead:

   `src/core/dacp/data/paths.py::repo_root()`

   Note that "repository root" and "import root" are different directories.
   Runners keep `ROOT` at the repository root anyway, because they pass it to
   `subprocess` as `cwd` and record it in run provenance; they add `src` to
   `sys.path` separately.

## Test baseline

```bash
python3 -m pytest -q
```

Expected on this machine:

```
138 tests collected
120 passed, 18 errors
```

The 18 errors are **pre-existing and unrelated to layout**: 13 request a `tmp`
fixture, 4 a `group` fixture, and 1 a `codec` fixture, none of which exist
anywhere in the repository. They are all in `src/benchmarks/test_dacp_*.py`.
They are left as-is deliberately — fixing them would require inventing fixture
semantics, and changing them would destroy the before/after equivalence signal
used to verify this layout.

Per-suite runs:

```bash
python3 -m pytest src/experiments/rev_exp/tests -q          # 19 passed
python3 -m pytest src/experiments/global_exp/tests -q
python3 -m pytest src/core/fxdacp/tests src/core/fxabe_rev/tests -q
```

## Results and provenance policy

Two kinds of file live side by side in this repository, and they are governed
by different rules.

**Living documents** — `README.md`, `docs/**` analysis and guides, run ledgers.
These describe the current tree and are kept correct. If you find a stale path
in one, fix it.

**Frozen records** — everything under a suite's `results/`,
`results_archive/`, `logs/`, and `global_exp/audit/profiles/`. These are the
raw output of a specific run on a specific machine at a specific revision, and
they are **never rewritten**. They therefore still contain the old flat-layout
paths (`Code/`, `Global_Exp/`, `Rev_Exp/`, `Perf_Exp_05_3/`, `fx_exp/`,
`fx_exp_v2/`, `Benchmark/`) and an older absolute repository root.

That is intentional, not neglect — rewriting a profiler's record of where each
function lived, or a run manifest's record of the command line that produced
it, would falsify the provenance the record exists to preserve. Read those
paths as history. Three dated documents are in the same category for the same
reason: `src/experiments/index_v1/CHANGELOG.md`,
`src/experiments/perf_05_3/docs/RUN_LEDGER.md`, and
`src/experiments/index_v2/docs/repository_audit.md`.

`shared/data/**` and `shared/results/**` hold a DACP dataset workspace. Its
bulk contents are git-ignored (only `.gitkeep` placeholders are committed);
`shared/data/README.md` describes the directory roles.

## Known footguns

Several scripts write to **fixed paths inside the repository** rather than to
the run directory you passed on the command line. Running them rewrites tracked
artifacts. This is pre-existing behaviour, not a consequence of the layout.

| Script | Rewrites |
| --- | --- |
| `perf_05_3/scripts/run_pipeline.py` | `perf_05_3/docs/STANDARD_RESULTS_ANALYSIS.md` — for **any** profile, including `smoke` |
| `global_exp/audit/audit_storage.py`, `audit_row_selection.py`, `audit_reconstruction.py`, `audit_encrypt_scaling.py`, `audit_diagnostic_m.py` | tracked CSVs under `global_exp/audit/results/` |
| `global_exp/audit/audit_profile.py` | tracked profiler dumps under `global_exp/audit/profiles/` |
| `index_v1/tests/test_runner_io.py` | appends to the tracked `index_v1/logs/smoke/resume-test.log` |

Before running any of these, know which files you are about to overwrite; after
running them, `git checkout HEAD -- <path>` restores the recorded version.

Scratch runs are best kept out of the way: `configs/smoke.yaml` runs written
with a `scratch*` run id are git-ignored (`src/**/results/scratch*/`). Suites
that generate timestamped run ids (`index_v2`) are not, so delete their scratch
run directories when you are done.

## Attribution

The reference schemes under `src/core/{bsw07cp,waters11cp,ac17cp,abgw17cp,cgw15cp,abgw17kp,ac17kp,cgw15kp,gpsw06kp,fabeo22cp,fabeo22kp,fabeo22dfa,waters12dfa}`
derive from published constructions; the design notes several prototypes were
built from are **external documents not present in this repository**, and the
docstrings name them where relevant.