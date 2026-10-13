"""Append-only run artifacts, canonical byte accounting and validation."""
from __future__ import annotations

import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import time
import uuid

from ..credential import credential_bytes
from ..encoding import decode, encode
from ..public import serialize_authorization, serialize_ciphertext, serialize_partial
from . import SCHEMA_VERSION
from .provenance import (REPO, SOURCE, code_manifest, environment_fingerprint,
                         file_sha256, spec_manifest)
from .schema import METRIC_UNITS, NOT_OBSERVED, validate_plan, validate_raw_row
from .workloads import canonical_json, sha256_json

TEXT_SUFFIXES = {'.json','.jsonl','.csv','.txt','.log','.md'}
DENIED_FIELDS = {'uid','raw_uid','rh_id','revocation_handle','mu','k0','k0q',
    'delta','delta_q','k_tok','k_rev','sk_cap','rk','msk','blob',
    'stable_blob_digest','pcs_api_key','tls_private_key','sgx_private_key',
    'plaintext_attribute','plaintext_attributes','plaintext_policy_labels',
    'plaintext_rho','rho','secret_key','private_key'}
KNOWN_TEST_CANARIES = ('PRIVATE-UID-4EFR-91e58e183d564fd7',
    'PRIVATE-ATTRIBUTE-4EFR-4a8a44a1', 'PRIVATE-TEST-USER')
REQUIRED_FILES = ('manifest.json','plan.json','environment.json','code_manifest.json',
    'raw.jsonl','raw.csv','counters.jsonl','correctness.json','artifact_index.json')


def _write_json(path, value):
    data = canonical_json(value) + b'\n'
    temporary = path.with_name(path.name + '.tmp-' + uuid.uuid4().hex)
    with temporary.open('xb') as output:
        output.write(data)
        output.flush(); os.fsync(output.fileno())
    os.replace(temporary, path)


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


def new_run_id():
    return datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:12]


class RunArtifacts:
    def __init__(self, plan, environment, code, specification, git,
                 *, root=None, run_id=None, trust_cohort=None, trust_metadata=None,
                 setup_with_preflight_ns=None, phase='INITIAL',
                 benchmark_eligible=False):
        validate_plan(plan)
        self.run_id = run_id or new_run_id()
        if not re.fullmatch(r'[A-Za-z0-9_-]{8,96}', self.run_id):
            raise ValueError('invalid run ID')
        artifact_root = Path(root) if root is not None else REPO/'artifacts/myabe08'
        if SOURCE == artifact_root or SOURCE in artifact_root.resolve().parents:
            raise ValueError('experiment output must be outside source tree')
        self.path = artifact_root / plan['backend'] / self.run_id
        self.path.mkdir(parents=True, exist_ok=False)
        self._start_ns = time.perf_counter_ns()
        self.plan = plan
        self.manifest = dict(schema_version=SCHEMA_VERSION, run_id=self.run_id,
            backend=plan['backend'], experiment_ids=plan['experiment_ids'],
            trust_cohort=trust_cohort, trust_metadata=trust_metadata,
            status='RUNNING', phase=phase,
            started_utc=_utc_now(), ended_utc=None,
            timezone_offset=datetime.now().astimezone().strftime('%z'),
            duration_ns=None, git=git, spec=specification,
            code_manifest_sha256=code['tree_sha256'],
            environment_fingerprint=environment_fingerprint(environment),
            plan_sha256=plan['plan_sha256'],
            metric_units_sha256=sha256_json(METRIC_UNITS),
            benchmark_eligible=benchmark_eligible)
        self.manifest['setup_with_preflight_ns'] = setup_with_preflight_ns
        _write_json(self.path/'manifest.json', self.manifest)
        _write_json(self.path/'plan.json', plan)
        _write_json(self.path/'environment.json', environment)
        _write_json(self.path/'code_manifest.json', code)
        for name in ('raw.jsonl','counters.jsonl'):
            (self.path/name).touch(exist_ok=False)
        self.correctness = []
        self.raw_count = 0

    def record_precheck(self, record):
        self.correctness.append(record)

    def append_row(self, row):
        validate_raw_row(row, self.manifest, self.plan)
        payload = canonical_json(row) + b'\n'
        with (self.path/'raw.jsonl').open('ab') as output:
            output.write(payload); output.flush(); os.fsync(output.fileno())
        counter_record = dict(schema_version=SCHEMA_VERSION, run_id=self.run_id,
                              sample_id=row['sample_id'], counters=row['counters'])
        with (self.path/'counters.jsonl').open('ab') as output:
            output.write(canonical_json(counter_record)+b'\n')
            output.flush(); os.fsync(output.fileno())
        self.raw_count += 1

    def finalize(self, status='COMPLETE'):
        if status not in ('COMPLETE','FAILED','INTERRUPTED') or self.manifest['status'] != 'RUNNING':
            raise ValueError('run already finalized or invalid final state')
        _write_json(self.path/'correctness.json', dict(schema_version=SCHEMA_VERSION,
            run_id=self.run_id, records=self.correctness))
        rows = [json.loads(line) for line in (self.path/'raw.jsonl').read_text().splitlines()]
        with (self.path/'raw.csv').open('x', newline='') as output:
            writer = csv.DictWriter(output, fieldnames=(
                'schema_version','run_id','experiment_id','sample_id','backend',
                'configuration_id','block_id','sample_index_within_block',
                'measurement_scope','workload_id','workload_seed','sample_status',
                'expected_outcome','actual_outcome','correctness_verified',
                'variables_json','metrics_json','counters_json','trust_metadata_json'))
            writer.writeheader()
            for row in rows:
                csv_row = {key:row.get(key) for key in writer.fieldnames
                           if not key.endswith('_json')}
                csv_row.update({name:json.dumps(row[name[:-5]], sort_keys=True)
                    for name in ('variables_json','metrics_json','counters_json',
                                 'trust_metadata_json')})
                writer.writerow(csv_row)
        index = []
        for path in sorted(self.path.iterdir()):
            if path.name in ('manifest.json','artifact_index.json') or not path.is_file():
                continue
            index.append(dict(path=path.name, sha256=file_sha256(path),
                              size_bytes=path.stat().st_size, purpose=path.stem))
        _write_json(self.path/'artifact_index.json', dict(schema_version=SCHEMA_VERSION,
            run_id=self.run_id, files=index,
            note='manifest is finalized last; index cannot hash itself'))
        self.manifest = dict(self.manifest, status=status,
            phase='FINAL' if self.manifest['phase']=='INITIAL' else self.manifest['phase'],
            ended_utc=_utc_now(), duration_ns=time.perf_counter_ns()-self._start_ns,
            measured_row_count=self.raw_count)
        # Last atomic write: interrupted runs cannot claim COMPLETE.
        _write_json(self.path/'manifest.json', self.manifest)
        return self.path


def canonical_storage_breakdown(ct, public_auth, partial, user, backend):
    ct_wire = serialize_ciphertext(ct, backend)
    auth_wire = serialize_authorization(public_auth, ct, backend)
    partial_wire = serialize_partial(partial, backend)
    outer = decode(ct_wire)
    inner = decode(outer[3])
    core = sum(len(encode(inner[index])) for index in (6,7,8))
    header = sum(len(encode(inner[index])) for index in (2,3,5))
    af_metadata = len(inner[4])
    af_slots = sum(len(slot) for slot in inner[9])
    af_total = len(encode(inner[4])) + len(encode(inner[9]))
    dem = len(encode(inner[10])) + len(encode(inner[11]))
    publication = len(ct_wire) - core - header - af_total - dem
    if min(core,header,af_metadata,af_slots,af_total,dem,publication) < 0:
        raise ValueError('canonical storage categories do not reconcile')
    return dict(ct_total_bytes=len(ct_wire), ct_core_bytes=core,
        header_bytes=header, af_total_bytes=af_total,
        af_slot_bytes=af_slots, af_metadata_bytes=af_metadata,
        dem_bytes=dem, publication_bytes=publication,
        credential_bytes=len(credential_bytes(user.credential)) +
            len(user.credential.signature), sealed_blob_bytes=len(user.blob.opaque),
        auth_bytes=len(auth_wire), ctprime_bytes=len(partial_wire),
        request_state_bytes=NOT_OBSERVED)


def _scan_fields(value):
    if type(value) is dict:
        for key, child in value.items():
            if str(key).lower() in DENIED_FIELDS:
                raise ValueError('forbidden secret field name')
            _scan_fields(child)
    elif type(value) is list:
        for child in value:
            _scan_fields(child)


def validate_run(path, *, canaries=(), require_current_code=True):
    path = Path(path)
    if not all((path/name).is_file() for name in REQUIRED_FILES):
        raise ValueError('incomplete run artifact layout')
    manifest = json.loads((path/'manifest.json').read_text())
    plan = json.loads((path/'plan.json').read_text())
    environment = json.loads((path/'environment.json').read_text())
    code = json.loads((path/'code_manifest.json').read_text())
    index = json.loads((path/'artifact_index.json').read_text())
    if (manifest.get('schema_version') != SCHEMA_VERSION or
        manifest.get('status') != 'COMPLETE' or
        manifest.get('phase') not in ('FINAL','PHASE_5A') or
        manifest.get('run_id') != path.name or manifest.get('backend') != path.parent.name or
        manifest.get('plan_sha256') != plan.get('plan_sha256') or
        manifest.get('metric_units_sha256') != sha256_json(METRIC_UNITS) or
        manifest.get('environment_fingerprint') != environment_fingerprint(environment) or
        manifest.get('code_manifest_sha256') != code.get('tree_sha256') or
        code.get('tree_sha256') != sha256_json(code.get('files')) or
        manifest.get('spec',{}).get('sha256') != spec_manifest()['sha256']):
        raise ValueError('run manifest/provenance mismatch')
    validate_plan(plan)
    if manifest['phase']=='PHASE_5A' and (
        manifest.get('benchmark_eligible') is not True or
        plan.get('benchmark_eligible') is not True or
        plan.get('phase') != 'PHASE_5A'):
        raise ValueError('Phase 5A benchmark provenance mismatch')
    if require_current_code and code_manifest()['tree_sha256'] != code['tree_sha256']:
        raise ValueError('source tree changed since run')
    indexed = {item['path'] for item in index.get('files',[])}
    expected = set(REQUIRED_FILES) - {'manifest.json','artifact_index.json'}
    if indexed != expected or index.get('run_id') != manifest['run_id']:
        raise ValueError('artifact index incomplete')
    for item in index['files']:
        target = path/item['path']
        if (target.name != item['path'] or not target.is_file() or
            target.stat().st_size != item['size_bytes'] or
            file_sha256(target) != item['sha256']):
            raise ValueError('artifact hash/size mismatch')
    rows = [json.loads(line) for line in (path/'raw.jsonl').read_text().splitlines()]
    if len(rows) != manifest.get('measured_row_count'):
        raise ValueError('raw row count mismatch')
    ids = set()
    configuration_counts = {}
    configuration_positions = set()
    allowed_configurations={x['configuration_id'] for x in plan.get('configurations',[])}
    for row in rows:
        validate_raw_row(row, manifest, plan)
        if row['sample_id'] in ids:
            raise ValueError('duplicate sample ID')
        ids.add(row['sample_id'])
        if manifest['phase']=='PHASE_5A':
            configuration_id=row.get('configuration_id')
            if configuration_id not in allowed_configurations:
                raise ValueError('unknown Phase 5A configuration ID')
            if (type(row.get('block_id')) is not int or
                type(row.get('sample_index_within_block')) is not int):
                raise ValueError('missing Phase 5A block index')
            if row['sample_status']=='OK' and (
                row['variables'].get('actual_cmax')!=manifest.get('setup_cmax') or
                row['variables'].get('d_j_count')!=manifest.get('setup_cmax')):
                raise ValueError('Phase 5A Setup/D_j cmax mismatch')
            configuration_counts[configuration_id]=configuration_counts.get(configuration_id,0)+1
            position=(configuration_id,row['block_id'],row['sample_index_within_block'])
            if position in configuration_positions:
                raise ValueError('duplicate Phase 5A sample position')
            configuration_positions.add(position)
    if manifest['phase']=='PHASE_5A' and (
        len(rows)!=plan['estimated_measured_samples'] or
        any(configuration_counts.get(x['configuration_id'])!=plan['repetitions']
            for x in plan['configurations'])):
        raise ValueError('Phase 5A measured sample coverage incomplete')
    with (path/'raw.csv').open(newline='') as source:
        csv_rows = list(csv.DictReader(source))
    if len(csv_rows) != len(rows) or any(
        csv_rows[i]['sample_id'] != rows[i]['sample_id'] for i in range(len(rows))):
        raise ValueError('CSV export disagrees with canonical JSONL rows')
    for index, row in enumerate(rows):
        for name in ('variables','metrics','counters','trust_metadata'):
            if json.loads(csv_rows[index][name+'_json']) != row[name]:
                raise ValueError('CSV export conflicts with canonical JSONL')
    correctness = json.loads((path/'correctness.json').read_text())
    if correctness.get('run_id') != manifest['run_id'] or any(
        record.get('passed') is not True for record in correctness.get('records',[])):
        raise ValueError('correctness precheck failure')
    prechecked = {(record.get('experiment_id'),record.get('workload_id'))
                  for record in correctness.get('records',[])}
    if any((row['experiment_id'],row['workload_id']) not in prechecked for row in rows):
        raise ValueError('raw row without matching correctness precheck')
    forbidden = tuple(KNOWN_TEST_CANARIES) + tuple(canaries)
    for target in path.iterdir():
        if target.suffix not in TEXT_SUFFIXES:
            continue
        content = target.read_text(errors='replace')
        if any(canary and canary in content for canary in forbidden):
            raise ValueError('forbidden TEST canary in text artifact')
        if target.suffix in ('.json','.jsonl'):
            values = ([json.loads(line) for line in content.splitlines()]
                      if target.suffix == '.jsonl' else [json.loads(content)])
            for value in values:
                _scan_fields(value)
    if any(target.is_file() and target.name not in REQUIRED_FILES and
           target.name != 'README.txt' for target in path.iterdir()):
        raise ValueError('unindexed extra run artifact')
    return dict(status='PASS', run_id=manifest['run_id'],
                backend=manifest['backend'], rows=len(rows),
                experiments=manifest['experiment_ids'],
                trust_cohort=manifest['trust_cohort'])
