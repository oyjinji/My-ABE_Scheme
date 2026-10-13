"""Phase 5C TEST-only controlled Exp6/Exp7 collection.

This module uses the public MYABE-08 facade and real Gramine SGX service.
Artifact rows contain aggregate counters/timings only, never identities,
handles, token bytes, group elements, ciphertexts, or secret digests.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
import uuid

from ..errors import MyABE08Error
from ..profile import SGX_DEBUG_GRAMINE_V1
from ..public import serialize_ciphertext
from ..real_tee.client import SgxDebugClient
from ..real_tee.rpc import RpcError
from ..revocation import REVOKE, ACTIVATE
from ..types import Validity
from .provenance import (REPO, code_manifest, environment_fingerprint,
    environment_manifest, file_sha256, git_provenance, spec_manifest)
from .runner import _context, _new_scheme, _register, _trust_metadata
from .workloads import canonical_json, generate_workload, sha256_json


SCHEMA = 'MYABE08-EXP-SCHEMA-V2'
PHASE = 'PHASE_5C'
ROOT = REPO / 'artifacts/myabe08/benchmarks/phase5c'
BUILD = Path(os.environ.get('MYABE08_SGX_DEBUG_BUILD_DIR',
                            '/tmp/myabe08-phase5c-build'))
SGX = SGX_DEBUG_GRAMINE_V1
RL_TARGETS = (0, 10, 100, 1000, 5000)
N_REG_TARGETS = (100, 1000, 5000)
LOAD_FRACTIONS = (.25, .50, .75, 1.0)
TRUST_EXPECTED = dict(TEEProfile=SGX,
    ExperimentTrustMode='QVL_VERIFIED_OUTDATED_TCB_DEBUG_FEASIBILITY_V1',
    QVLApiReturn=0, CollateralExpirationStatus=0,
    QVLResult='SGX_QL_QV_RESULT_OUT_OF_DATE',
    StrictRA2='BLOCKED_BY_TCB_POLICY', EnclaveDebug=True,
    CurrentHeadMode='TEST_SINGLE_LOGICAL_COORDINATOR')


def _utc():
    return datetime.now(timezone.utc).isoformat()


def _write_new(path: Path, value):
    with path.open('xb') as out:
        out.write(canonical_json(value) + b'\n')


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def make_plan(*, keygen_calibration_ns: int, update_calibration_ns: int,
              active_calibration_ns: int, warmups=5, repetitions=30,
              window_seconds=30) -> dict:
    """Freeze a bounded design; a reduced grid requires a measured budget reason."""
    for value in (keygen_calibration_ns,update_calibration_ns,
                  active_calibration_ns):
        _require(type(value) is int and value > 0, 'positive calibration required')
    _require(warmups == 5 and repetitions == 30 and window_seconds >= 30,
             'Phase 5C sampling policy mismatch')
    # Conservative growth allowance for canonical authenticated state rewrite.
    full_estimate_ns = (5002 * keygen_calibration_ns * 2 +
        5000 * update_calibration_ns * 20 +
        len(RL_TARGETS) * 2 * (warmups+repetitions) * active_calibration_ns * 2 +
        2 * len(LOAD_FRACTIONS) * window_seconds * 1_000_000_000 +
        400 * active_calibration_ns)
    if full_estimate_ns > 6 * 3600 * 1_000_000_000:
        grid=(0,10,100,1000)
        n_reg=(100,1000)
        kind='REDUCED_BALANCED_PLAN'
        reason='calibrated conservative full-grid estimate exceeds six hours'
    else:
        grid=RL_TARGETS;n_reg=N_REG_TARGETS
        kind='FULL_TARGET_GRID';reason='NOT_REDUCED'
    plan=dict(schema=SCHEMA,phase=PHASE,plan_kind=kind,
        reduction_reason=reason,rl_grid=list(grid),n_reg_grid=list(n_reg),
        requested_rl_grid=list(RL_TARGETS),requested_n_reg_grid=list(N_REG_TARGETS),
        warmups=warmups,repetitions=repetitions,blocks=3,
        load_fractions=list(LOAD_FRACTIONS),load_window_seconds=window_seconds,
        request_classes=['ACTIVE_AUTHORIZED','REVOKED_REJECT'],
        calibration_ns=dict(keygen=keygen_calibration_ns,
            update=update_calibration_ns,active_authorize=active_calibration_ns),
        conservative_estimated_total_ns=full_estimate_ns,
        n_reg_definition='enclave credential/version registry count',
        rl_definition='actual enclave ExactRevocationSet count',
        strict_ra2='BLOCKED_BY_TCB_POLICY',
        spec_sha256=spec_manifest()['sha256'])
    plan['plan_sha256']=sha256_json(plan)
    return plan


def validate_plan(plan):
    _require(plan['schema']==SCHEMA and plan['phase']==PHASE and
             plan['spec_sha256']==spec_manifest()['sha256'],
             'Phase 5C plan identity mismatch')
    digest=sha256_json({k:v for k,v in plan.items() if k!='plan_sha256'})
    _require(plan.get('plan_sha256')==digest,'Phase 5C plan hash mismatch')
    _require(plan['warmups']==5 and plan['repetitions']==30 and
             plan['blocks']==3 and plan['load_window_seconds']>=30,
             'Phase 5C sampling policy mismatch')
    _require(plan['rl_grid'][0]==0 and len(plan['rl_grid'])>=3 and
             list(plan['rl_grid'])==sorted(set(plan['rl_grid'])),
             'RevSet grid malformed')
    return True


class RunWriter:
    """Append during acquisition; final manifest and hashes seal the run."""
    def __init__(self, experiment: str, plan: dict, environment: dict,
                 code: dict, trust: dict, *, root=ROOT):
        validate_plan(plan)
        _require(experiment in ('Exp6','Exp7'), 'unknown Phase 5C experiment')
        _require(all(trust.get(key)==value for key,value in TRUST_EXPECTED.items()),
                 'TRUST_COHORT_CHANGED')
        self.run_id=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:12]
        self.path=Path(root)/experiment/SGX/self.run_id
        self.path.mkdir(parents=True,exist_ok=False)
        self.experiment=experiment
        self.code_hash=code['tree_sha256']
        self.rows=0
        self.failures=0
        self.timeouts=0
        self.expected_rejects=0
        self.started=_utc()
        self._raw=(self.path/'raw.jsonl').open('xb')
        _write_new(self.path/'plan.json',plan)
        _write_new(self.path/'environment.json',environment)
        _write_new(self.path/'code_manifest.json',code)
        _write_new(self.path/'trust.json',trust)
        _write_new(self.path/'git.json',git_provenance())

    def append(self, kind: str, *, rl_size: int, n_reg: int,
               block_id: int, sample_index: int, status: str,
               expected: str, actual: str, metrics: dict):
        _require(status in ('OK','EXPECTED_REJECT','FAILED','TIMEOUT'),
                 'sample status invalid')
        _require(type(rl_size) is int and rl_size>=0 and
                 type(n_reg) is int and n_reg>=0,
                 'state dimension invalid')
        _require(all(type(value) in (int,float,str,bool) or value is None
                     for value in metrics.values()),'metric value malformed')
        if status in ('OK','EXPECTED_REJECT'):
            _require(expected==actual,'incorrect measured outcome')
        row=dict(schema=SCHEMA,phase=PHASE,run_id=self.run_id,
            experiment=self.experiment,sample_id=uuid.uuid4().hex,
            backend=SGX,kind=kind,rl_size=rl_size,n_reg=n_reg,
            block_id=block_id,sample_index=sample_index,status=status,
            expected_outcome=expected,actual_outcome=actual,metrics=metrics)
        self._raw.write(canonical_json(row)+b'\n')
        self._raw.flush();os.fsync(self._raw.fileno())
        self.rows+=1
        self.failures+=status=='FAILED';self.timeouts+=status=='TIMEOUT'
        self.expected_rejects+=status=='EXPECTED_REJECT'

    def evidence(self, name: str, value: dict):
        _require(name in ('state_memory','registration_memory','adversarial',
            'lifecycle','calibration','load_plan','transcript_inventory',
            'freshness','equality','known_leakage','canary_audit'),
            'unknown evidence file')
        _write_new(self.path/(name+'.json'),value)

    def finish(self, *, status='COMPLETE'):
        self._raw.close()
        _require(status in ('COMPLETE','FAILED'), 'run status invalid')
        files={item.name:dict(sha256=file_sha256(item),bytes=item.stat().st_size)
               for item in sorted(self.path.iterdir()) if item.is_file()}
        _write_new(self.path/'artifact_index.json',files)
        manifest=dict(schema=SCHEMA,phase=PHASE,experiment=self.experiment,
            run_id=self.run_id,backend=SGX,status=status,started_utc=self.started,
            ended_utc=_utc(),plan_sha256=json.loads((self.path/'plan.json').read_text())['plan_sha256'],
            code_tree_sha256=self.code_hash,
            environment_fingerprint=environment_fingerprint(
                json.loads((self.path/'environment.json').read_text())),
            spec_sha256=spec_manifest()['sha256'],rows=self.rows,
            expected_rejects=self.expected_rejects,
            unexpected_failures=self.failures,timeouts=self.timeouts,
            artifact_index_sha256=file_sha256(self.path/'artifact_index.json'))
        _write_new(self.path/'manifest.json',manifest)
        return self.path


def validate_run(path: Path, *, require_current_code=True):
    path=Path(path)
    manifest=json.loads((path/'manifest.json').read_text())
    plan=json.loads((path/'plan.json').read_text())
    validate_plan(plan)
    _require(manifest['schema']==SCHEMA and manifest['phase']==PHASE and
             manifest['status']=='COMPLETE' and manifest['run_id']==path.name and
             manifest['plan_sha256']==plan['plan_sha256'] and
             manifest['spec_sha256']==spec_manifest()['sha256'],
             'Phase 5C manifest invalid')
    code=json.loads((path/'code_manifest.json').read_text())
    _require(code['tree_sha256']==manifest['code_tree_sha256'] and
             code['tree_sha256']==sha256_json(code['files']),
             'Phase 5C code provenance invalid')
    if require_current_code:
        _require(code_manifest()['tree_sha256']==code['tree_sha256'],
                 'source changed since Phase 5C run')
    environment=json.loads((path/'environment.json').read_text())
    _require(environment_fingerprint(environment)==manifest['environment_fingerprint'],
             'environment fingerprint mismatch')
    trust=json.loads((path/'trust.json').read_text())
    _require(all(trust.get(key)==value for key,value in TRUST_EXPECTED.items()),
             'TRUST_COHORT_CHANGED')
    index=json.loads((path/'artifact_index.json').read_text())
    _require(file_sha256(path/'artifact_index.json')==manifest['artifact_index_sha256'],
             'artifact index changed')
    for name,entry in index.items():
        item=path/name
        _require(item.is_file() and file_sha256(item)==entry['sha256'] and
                 item.stat().st_size==entry['bytes'], 'Phase 5C artifact changed')
    actual={item.name for item in path.iterdir() if item.is_file()}
    _require(actual==set(index)|{'artifact_index.json','manifest.json'},
             'unindexed Phase 5C artifact')
    rows=[json.loads(line) for line in (path/'raw.jsonl').read_text().splitlines()]
    _require(len(rows)==manifest['rows'] and
             len({row['sample_id'] for row in rows})==len(rows),
             'sample count or ID mismatch')
    counts=dict(OK=0,EXPECTED_REJECT=0,FAILED=0,TIMEOUT=0)
    for row in rows:
        _require(row['schema']==SCHEMA and row['phase']==PHASE and
                 row['run_id']==manifest['run_id'] and
                 row['experiment']==manifest['experiment'] and
                 row['backend']==SGX, 'sample identity mismatch')
        counts[row['status']]+=1
        if row['status'] in ('OK','EXPECTED_REJECT'):
            _require(row['expected_outcome']==row['actual_outcome'],
                     'sample outcome mismatch')
    _require(counts['FAILED']==manifest['unexpected_failures'] and
             counts['TIMEOUT']==manifest['timeouts'] and
             counts['EXPECTED_REJECT']==manifest['expected_rejects'] and
             counts['FAILED']==counts['TIMEOUT']==0,
             'Phase 5C failures or timeouts')
    if manifest['experiment']=='Exp6':
        for size in plan['rl_grid']:
            for kind in ('ACTIVE_LOOKUP','UPDATE_DELETE'):
                selected=[r for r in rows if r['kind']==kind and r['rl_size']==size]
                _require(len(selected)==plan['repetitions'],
                         'Exp6 measured configuration missing')
            inserted=[r for r in rows if r['kind']=='UPDATE_INSERT' and
                      r['metrics'].get('baseline_rl_size')==size and
                      r['rl_size']==size+1]
            _require(len(inserted)==plan['repetitions'],
                     'Exp6 insert configuration missing')
            if size:
                selected=[r for r in rows if r['kind']=='REVOKED_LOOKUP' and
                          r['rl_size']==size]
                _require(len(selected)==plan['repetitions'] and
                         all(r['status']=='EXPECTED_REJECT' and
                             r['metrics'].get('user_tokens_emitted')==0 and
                             r['metrics'].get('t0_pairings')==0 and
                             r['metrics'].get('caps_emitted')==0 for r in selected),
                         'Exp6 revoked boundary missing')
        memory=json.loads((path/'state_memory.json').read_text())['snapshots']
        registration=json.loads((path/'registration_memory.json').read_text())['snapshots']
        load=json.loads((path/'load_plan.json').read_text())['levels']
        _require([x['rl_size'] for x in memory]==plan['rl_grid'] and
                 all(x['rl_size']==x['revset_count'] for x in memory) and
                 [x['n_reg'] for x in registration]==plan['n_reg_grid'] and
                 len(load)==2*len(plan['load_fractions']) and
                 all(x['completed_count']>0 and x['failed_count']==0 for x in load),
                 'Exp6 state/load coverage mismatch')
        lifecycle=json.loads((path/'lifecycle.json').read_text())
        adversarial=json.loads((path/'adversarial.json').read_text())
        _require(all(value is True for value in lifecycle.values()) and
                 all(value is True for value in adversarial.values()),
                 'Exp6 semantic evidence failed')
    else:
        same=[r for r in rows if r['kind']=='SAME_CONTEXT']
        cross=[r for r in rows if r['kind']=='CROSS_CONTEXT']
        fresh=json.loads((path/'freshness.json').read_text())
        equality=json.loads((path/'equality.json').read_text())
        leakage=json.loads((path/'known_leakage.json').read_text())
        inventory=json.loads((path/'transcript_inventory.json').read_text())
        _require(len(same)==len(cross)==100 and
                 fresh['sample_count']>=50 and
                 all(item['sample_count']>=50 for item in fresh['observations']) and
                 equality['same_context_checks']>=100 and
                 equality['cross_context_checks']>=100 and
                 leakage['same_user_same_ct_w_requests']>=50 and
                 leakage['all_equal'] is True and
                 len(inventory['rows'])>=6,
                 'Exp7 observation coverage incomplete')
    audit=json.loads((path/'canary_audit.json').read_text())
    _require(audit['status']=='PASS' and audit['forbidden_value_hits']==0,
             'TRANSCRIPT_PRIVACY_DEFECT')
    return dict(status='PASS',run_id=manifest['run_id'],
        experiment=manifest['experiment'],rows=len(rows),
        expected_rejects=counts['EXPECTED_REJECT'])


def validate_dataset(paths):
    paths=[Path(path) for path in paths]
    _require(paths,'empty Phase 5C dataset')
    checked=[validate_run(path) for path in paths]
    manifests=[json.loads((path/'manifest.json').read_text()) for path in paths]
    reference=manifests[0]
    _require(len({m['run_id'] for m in manifests})==len(manifests),
             'duplicate Phase 5C run')
    for item in manifests[1:]:
        _require(all(item[key]==reference[key] for key in
            ('experiment','backend','plan_sha256','code_tree_sha256',
             'spec_sha256','environment_fingerprint')),
             'mixed Phase 5C dataset provenance')
    return dict(status='PASS',experiment=reference['experiment'],
        run_ids=[x['run_id'] for x in manifests],rows=sum(x['rows'] for x in manifests),
        expected_rejects=sum(x['expected_rejects'] for x in manifests))
