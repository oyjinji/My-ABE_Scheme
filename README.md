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
│   └── results/        DACP output trees, created at runtime by the scripts
│                       that write them; bulk contents not committed
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
| Comparison skeletons | `fabesa`, `ipecp`, `lacsprp`, `mynewcp`, `newcp20` |
| Shared | `msp` (LSSS/MSP policy conversion) |

The comparison skeletons under `fabesa`, `ipecp`, `lacsprp`, `mynewcp` and
`newcp20` are **structural placeholders** kept so the benchmark runners have
something to time. Their own docstrings say which subroutines are not faithful
implementations; read those before citing anything measured on them.

`newcp20` was named `newcp2.0` until the 2026-09 layout refactor. The `.` is not
a valid identifier character, so it could not be imported as a package, and the
four `src/benchmarks/compare_*newcp20*.py` scripts each carried an `importlib`
shim to load it from its file path under the alias `core.newcp20_dynamic`. The
directory is now `newcp20`, so it imports normally as `core.newcp20` and the
shims are gone. The scheme's own name is unchanged: `NewCP20CPABE` still reports
`legacy_name = "newcp2.0"`.

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
138 passed
```

All 138 pass. Until the 2026-09 layout refactor, 18 of them errored: the five
`src/benchmarks/test_dacp_*.py` modules double as runnable scripts whose
`main()` builds its inputs inline, and the fixtures their test functions take
(`tmp`, `group`, `codec`, `product`) were defined nowhere. They now come from
`src/benchmarks/conftest.py`, which supplies exactly what the matching `main()`
supplies — `tmp` is a temporary directory, `group` is
`PairingGroup("MNT224")`, `codec` is `WireCodec(group)`, and `product` is the
product the marketplace catalog test builds. No test was added, removed, or
changed in intent; the collected count is still 138, and each module still runs
standalone.

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

`shared/data/**` and `shared/results/**` hold a DACP dataset workspace. Their
bulk contents are git-ignored. Only `shared/data/**` keeps committed `.gitkeep`
placeholders; `shared/results/**` carries none — the scripts that write there
(`src/core/dacp/data/paths.py` and the `src/benchmarks/run_dacp_*` runners)
create the directories as needed, so a fresh clone has no `shared/results/`
until something writes to it. `shared/data/README.md` describes its roles.

## Writing to tracked artifacts

Some scripts write to **fixed paths inside the repository** rather than to the
run directory you passed, so running them rewrites tracked artifacts. Two of
those were outright bugs and are fixed; the rest are now redirectable.

| Script | Writes | Running it safely |
| --- | --- | --- |
| `perf_05_3/scripts/run_pipeline.py`, via `generate_analysis.py` | `perf_05_3/docs/STANDARD_RESULTS_ANALYSIS.md` | **Fixed.** Only a `standard`-tier run writes the tracked report. `smoke` (and any other mode) now writes `STANDARD_RESULTS_ANALYSIS.md` into the run directory instead — previously a smoke run overwrote the recorded Standard analysis with smoke-tier numbers. |
| `global_exp/audit/audit_{storage,row_selection,reconstruction,encrypt_scaling,diagnostic_m,ledgers}.py` | tracked CSVs under `audit/results/` | Set `GLOBAL_EXP_AUDIT_OUT=<dir>` and outputs go there, leaving the committed files alone. `audit_ledgers.py` still *reads* `operation_costs.csv` from the committed directory, so a redirected run stays consistent. |
| `global_exp/audit/audit_profile.py` | tracked profiler dumps under `audit/profiles/` | Same: set `GLOBAL_EXP_AUDIT_OUT=<dir>`. |
| `index_v1/tests/test_runner_io.py` | appended to the tracked `index_v1/logs/smoke/resume-test.log` on every `pytest` run | **Fixed.** `ExperimentRun` now takes its log root from the module-level `common.LOGS`; the test redirects it next to `common.RESULTS`. Anything that redirects `RESULTS` must redirect `LOGS` too, or the run still logs into the repository. |

If you do overwrite a recorded artifact, `git checkout HEAD -- <path>` restores
it. Note that the audit CSVs record **wall-clock measurements** and are
therefore not byte-reproducible: two consecutive runs of the same unmodified
script already differ in their timing columns. Treat the committed copies as the
record, not as something you can regenerate exactly.

Scratch runs are best kept out of the way: `configs/smoke.yaml` runs written
with a `scratch*` run id are git-ignored (`src/**/results/scratch*/`). Suites
that generate timestamped run ids (`index_v2`) are not, so delete their scratch
run directories when you are done.

## Attribution

The reference schemes under `src/core/{bsw07cp,waters11cp,ac17cp,abgw17cp,cgw15cp,abgw17kp,ac17kp,cgw15kp,gpsw06kp,fabeo22cp,fabeo22kp,fabeo22dfa,waters12dfa}`
derive from published constructions; the design notes several prototypes were
built from are **external documents not present in this repository**, and the
docstrings name them where relevant.