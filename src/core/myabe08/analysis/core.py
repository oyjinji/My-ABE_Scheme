"""Frozen-input validation and descriptive statistics for Phase 5B."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import csv
import hashlib
import json
import math
from pathlib import Path
import random
import statistics
import uuid

from . import ANALYSIS_SCHEMA
from ..experiments.schema import METRIC_UNITS
from ..experiments.storage import validate_run


REPO = Path(__file__).resolve().parents[4]
INPUT_ROOT = REPO / 'artifacts/myabe08/benchmarks/phase5a/revalidated-v2'
OUTPUT_ROOT = REPO / 'artifacts/myabe08/analysis/phase5b'
COHORTS = (('Exp1', 'SGX_DEBUG_GRAMINE_V1'),
           ('Exp3', 'EMULATED_TEE_PROFILE'),
           ('Exp4', 'EMULATED_TEE_PROFILE'),
           ('Exp4', 'SGX_DEBUG_GRAMINE_V1'),
           ('Exp5', 'SGX_DEBUG_GRAMINE_V1'))
SPEC_HASH = 'd52daf431bfececa4b1b8bf0f77fe34634710c9502d372f405b75b806812df85'
BENCHMARK_CODE_HASH = '639f1c66c3a985fa24a81e863ab6db19038b9cbb1e36873d415de20f677ffbef'
ENVIRONMENT_HASH = '567895d307e66bfa8ab82617a12b0ec274b497f04c3c6303ece5a81683f9e39c'
PLAN_HASH = '5101755f310be6aada9581bac7ac5e6ac354075093c3316f0931fe5674c24fed'
SGX_TRUST = dict(TEEProfile='SGX_DEBUG_GRAMINE_V1',
    ExperimentTrustMode='QVL_VERIFIED_OUTDATED_TCB_DEBUG_FEASIBILITY_V1',
    QVLResult='SGX_QL_QV_RESULT_OUT_OF_DATE',
    StrictRA2='BLOCKED_BY_TCB_POLICY', EnclaveDebug=True,
    QVLApiReturn=0, CollateralExpirationStatus=0,
    CurrentHeadMode='TEST_SINGLE_LOGICAL_COORDINATOR')
REQUIRED_DURATIONS = ('request_e2e_ns', 'encrypt_ns', 'tee_authorize_ns',
    'transform_ns', 'finaldec_ns', 'policy_token_ns', 'af_query_ns')
SGX_DURATIONS = ('enclave_total_ns', 'credential_verify_ns',
    'revset_lookup_ns', 'tokenization_ns', 'rerandomization_ns',
    't0_pairing_ns', 'cap_sign_ns', 'rpc_send_ns', 'rpc_receive_ns')


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def canonical_bytes(value) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=False,
                       separators=(',', ':'), allow_nan=False) + '\n').encode()


def write_json(path: Path, value) -> None:
    with path.open('xb') as stream:
        stream.write(canonical_bytes(value))


def write_text(path: Path, value: str) -> None:
    with path.open('x', encoding='utf-8', newline='\n') as stream:
        stream.write(value)


def write_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    with path.open('x', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, '') for key in fields})


def analysis_code_hash() -> str:
    h = hashlib.sha256()
    for path in sorted(Path(__file__).parent.glob('*.py')):
        h.update(path.name.encode() + b'\0' + path.read_bytes())
    return h.hexdigest()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _input_files(cohort_dir: Path, run_ids: list[str]) -> list[Path]:
    files = [cohort_dir / 'dataset_manifest.json',
             cohort_dir / 'descriptive_summary.json']
    for run_id in run_ids:
        run = cohort_dir / run_id
        files.extend(run / name for name in ('manifest.json', 'plan.json',
            'environment.json', 'code_manifest.json', 'artifact_index.json',
            'raw.jsonl', 'raw.csv', 'correctness.json', 'counters.jsonl'))
    return files


def load_frozen(input_root: Path = INPUT_ROOT) -> dict:
    """Validate only the five frozen cohorts; never read globbed old runs."""
    input_root = Path(input_root).resolve()
    plan = json.loads((REPO / 'src/core/myabe08/experiments/phase5a_plan.json').read_text())
    _require(plan['phase5a_plan_sha256'] == PLAN_HASH, 'frozen plan changed')
    superseded = json.loads((input_root.parent / 'superseded_by_code_change.json').read_text())
    _require(superseded['status'] == 'SUPERSEDED_BY_CODE_CHANGE', 'superseded ledger missing')
    excluded_ids = sorted(item['run_id'] for item in superseded['runs'])
    _require(len(excluded_ids) == len(set(excluded_ids)), 'duplicate excluded run ID')
    found = {(p.parent.parent.name, p.parent.name) for p in input_root.glob('*/*/dataset_manifest.json')}
    _require(found == set(COHORTS), 'frozen cohort set changed')
    cohorts = {}
    input_hashes = {}
    all_ids = set()
    for experiment, backend in COHORTS:
        directory = input_root / experiment / backend
        dataset_path = directory / 'dataset_manifest.json'
        dataset = json.loads(dataset_path.read_text())
        _require(dataset.get('validation') == 'PASS' and
                 dataset.get('benchmark_eligible') is True and
                 dataset.get('phase') == 'PHASE_5A', 'invalid dataset manifest')
        _require(dataset['backend'] == backend and
                 dataset['spec_sha256'] == SPEC_HASH and
                 dataset['code_manifest_sha256'] == BENCHMARK_CODE_HASH and
                 dataset['environment_fingerprint'] == ENVIRONMENT_HASH and
                 dataset['phase5a_plan_sha256'] == PLAN_HASH,
                 'frozen dataset provenance mismatch')
        run_ids = dataset['run_ids']
        _require(len(run_ids) == len(set(run_ids)) and not (set(run_ids) & set(excluded_ids)),
                 'duplicate or superseded run in dataset')
        _require(not (set(run_ids) & all_ids), 'run mixed across cohorts')
        all_ids.update(run_ids)
        selected = {c['configuration_id'] for c in plan['configurations']
                    if c['experiment_id'] == experiment and c['backend'] == backend}
        rows = []
        configs = set()
        for run_id in run_ids:
            run_path = directory / run_id
            # The analysis package changes the live myabe08 source-tree hash.
            # validate_run still checks the frozen run's own indexed code hash;
            # the explicit BENCHMARK_CODE_HASH check below pins its expected value.
            validate_run(run_path, require_current_code=False)
            manifest = json.loads((run_path / 'manifest.json').read_text())
            _require(manifest['status'] == 'COMPLETE' and
                     manifest['code_manifest_sha256'] == BENCHMARK_CODE_HASH and
                     manifest['environment_fingerprint'] == ENVIRONMENT_HASH and
                     manifest['spec']['sha256'] == SPEC_HASH and
                     manifest['phase5a_plan_sha256'] == PLAN_HASH and
                     manifest['backend'] == backend,
                     'run provenance mismatch')
            run_plan = json.loads((run_path / 'plan.json').read_text())
            for config in run_plan['configurations']:
                cid = config['configuration_id']
                _require(cid not in configs, 'duplicate configuration across runs')
                configs.add(cid)
            for line in (run_path / 'raw.jsonl').read_text().splitlines():
                row = json.loads(line)
                _require(row['experiment_id'] == experiment and row['backend'] == backend,
                         'row backend mixing')
                _require(row['sample_status'] == 'OK' and row['correctness_verified'] is True,
                         'failed or unverified sample')
                trust = row['trust_metadata']
                if backend == 'SGX_DEBUG_GRAMINE_V1':
                    _require(all(trust.get(k) == v for k, v in SGX_TRUST.items()),
                             'SGX trust metadata mismatch')
                else:
                    _require(trust.get('ExperimentTrustMode') == 'EMULATED_TEST' and
                             trust.get('TEEProfile') == 'EMULATED_TEE_PROFILE',
                             'EMULATED trust metadata mismatch')
                for key in REQUIRED_DURATIONS + (SGX_DURATIONS if backend.startswith('SGX_') else ()):
                    value = row['metrics'].get(key)
                    _require(type(value) is int and value > 0,
                             'missing or nonpositive required duration')
                for key, value in row['metrics'].items():
                    _require(not (key.endswith('_ns') and type(value) is int and value <= 0),
                             'nonpositive observed duration')
                v = row['variables']; c = row['counters']
                _require(c['tee_pairing_count'] == 1 and
                         c['csp_pairing_count'] == 1 + v['actual_tI'] and
                         c['system_pairing_count'] == 2 + v['actual_tI'] and
                         c['finaldec_pairing_count'] == 0 and
                         v['actual_cmax'] == v['cmax'] == v['d_j_count'],
                         'pairing or cmax inconsistency')
                rows.append(row)
        _require(configs == selected, 'frozen configuration coverage mismatch')
        _require(len(rows) == dataset['sample_count'] and
                 len(configs) == dataset['configuration_count'] and
                 dataset['failed_sample_count'] == 0, 'dataset count mismatch')
        counts = defaultdict(int)
        for row in rows:
            counts[row['configuration_id']] += 1
        target = 1 if experiment == 'Exp3' else 20
        _require(all(counts[c] == target for c in selected), 'per-configuration sample gap')
        for file in _input_files(directory, run_ids):
            _require(file.is_file(), 'missing frozen input file')
            input_hashes[str(file.relative_to(REPO))] = sha256_file(file)
        cohorts[(experiment, backend)] = dict(dataset=dataset, directory=directory,
            manifest_sha256=sha256_file(dataset_path), rows=rows,
            run_ids=run_ids, configuration_ids=sorted(configs))
    return dict(cohorts=cohorts, input_hashes=input_hashes,
                excluded_superseded_run_ids=excluded_ids,
                excluded_superseded_runs_count=len(excluded_ids),
                sample_count=sum(len(c['rows']) for c in cohorts.values()))


def quantile(values, probability: float) -> float:
    """Linear-interpolation empirical quantile, matching NumPy's linear method."""
    if not values or not 0 <= probability <= 1:
        raise ValueError('empty values or invalid probability')
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    low = math.floor(position); high = math.ceil(position)
    return float(ordered[low] + (ordered[high] - ordered[low]) * (position - low))


def describe(values: list[float]) -> dict:
    if not values or any(type(v) not in (int, float) or not math.isfinite(v) for v in values):
        raise ValueError('invalid descriptive sample')
    return dict(n=len(values), min=min(values), q1=quantile(values, .25),
        median=quantile(values, .5), q3=quantile(values, .75),
        mean=statistics.mean(values), std=statistics.pstdev(values),
        p90=quantile(values, .90), p95=quantile(values, .95), max=max(values))


def cluster_bootstrap_median(clusters: list[list[float]], *, seed=17,
                             replicates=2000) -> tuple[float, float]:
    """Deterministic block-resampling primitive; not used for Phase 5B inference."""
    if len(clusters) < 2 or any(not cluster for cluster in clusters) or replicates < 100:
        raise ValueError('insufficient bootstrap clusters')
    rng = random.Random(seed)
    estimates = []
    for _ in range(replicates):
        sample = [value for _ in clusters for value in clusters[rng.randrange(len(clusters))]]
        estimates.append(statistics.median(sample))
    return quantile(estimates, .025), quantile(estimates, .975)


def statistics_rows(cohort: dict, experiment: str, backend: str) -> list[dict]:
    groups = defaultdict(list)
    for row in cohort['rows']:
        groups[row['configuration_id']].append(row)
    output = []
    for cid, samples in sorted(groups.items()):
        samples.sort(key=lambda r: (r['run_id'], r['block_id'],
                                    r['sample_index_within_block']))
        v = samples[0]['variables']
        structural = dict(ell=v['ell'], N=v['N'], cmax=v['cmax'],
            repeat_regime=v['repeat_regime'], policy_shape=v['policy_shape'],
            requested_L_hit=v['requested_L_hit'], actual_L_hit=v['actual_L_hit'],
            requested_J=v['requested_J'], actual_J=v['actual_J'],
            actual_k=v['actual_k'], actual_tI=v['actual_tI'],
            occurrence_slot_count=samples[0]['metrics']['occurrence_slot_count'])
        for key in structural:
            _require(all(r['variables'].get(key, structural[key]) == structural[key]
                         for r in samples) if key in v else True,
                     'structural variable varies within configuration')
        for metric in sorted(METRIC_UNITS):
            values = [r['metrics'].get(metric) for r in samples]
            if not all(type(x) in (int, float) for x in values):
                continue
            record = dict(analysis_schema=ANALYSIS_SCHEMA,
                dataset_manifest_sha256=cohort['manifest_sha256'],
                experiment=experiment, backend=backend,
                trust_cohort=cohort['dataset']['trust_cohort'],
                configuration_id=cid, run_id=samples[0]['run_id'],
                sample_ids=[r['sample_id'] for r in samples],
                metric=metric, unit=METRIC_UNITS[metric], **structural,
                **describe(values))
            output.append(record)
    return output


def new_analysis_dir(root: Path = OUTPUT_ROOT) -> tuple[str, Path]:
    root.mkdir(parents=True, exist_ok=True)
    analysis_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:12]
    path = root / analysis_id
    path.mkdir(exist_ok=False)
    for name in ('summary', 'tables', 'figures', 'paper', 'diagnostics', 'validation'):
        (path / name).mkdir()
    return analysis_id, path
