"""Phase 4F schema, privacy, reproducibility and smoke invariants."""
import json
from pathlib import Path

import pytest

from core.myabe08.crypto import compute_ctx_priv
from core.myabe08.experiments import SCHEMA_VERSION
from core.myabe08.experiments.cli import main
from core.myabe08.experiments.provenance import (
    code_manifest, environment_fingerprint, environment_manifest,
    spec_manifest)
from core.myabe08.experiments.registry import REGISTRY
from core.myabe08.experiments.runner import run_smoke
from core.myabe08.experiments.schema import (NOT_OBSERVED, build_plan,
    finalize_plan_hash, validate_plan)
from core.myabe08.experiments.storage import RunArtifacts, validate_run
from core.myabe08.experiments.workloads import FAMILIES, generate_workload
from core.myabe08.profile import EMULATED_TEE_PROFILE, SGX_DEBUG_GRAMINE_V1
from core.myabe08.public import EMULATED_TEST_MODE, PublicMyABE08, serialize_ciphertext
from core.myabe08.types import PolicyContext, Validity


class Clock:
    def now(self): return 1000


def test_registry_and_exp2_controlled_block(capsys):
    assert tuple(REGISTRY) == tuple('Exp'+str(i) for i in range(1,8))
    assert all(entry.research_question and entry.correctness_gates and
               entry.security_boundary for entry in REGISTRY.values())
    assert REGISTRY['Exp2'].status == 'BLOCKED'
    assert REGISTRY['Exp2'].blocked_reason == 'BLOCKED_COMMON_BACKEND'
    assert main(('smoke','Exp2','--backend',EMULATED_TEE_PROFILE)) == 0
    assert json.loads(capsys.readouterr().out)['status'] == 'BLOCKED_COMMON_BACKEND'
    assert main(('list',)) == 0
    assert len(json.loads(capsys.readouterr().out)) == 7
    assert main(('describe','Exp4')) == 0
    assert json.loads(capsys.readouterr().out)['contribution'] == 'C2'


def test_plan_schema_grid_guard_and_no_crypto(monkeypatch):
    def forbidden_crypto(*args, **kwargs):
        raise AssertionError('plan must not invoke cryptographic facade')
    monkeypatch.setattr(PublicMyABE08,'Setup',forbidden_crypto)
    plan = finalize_plan_hash(build_plan(('Exp1','Exp2'),EMULATED_TEE_PROFILE))
    assert validate_plan(plan)
    assert plan['entries'][1]['status'] == 'BLOCKED_COMMON_BACKEND'
    assert plan['estimated_measured_samples'] == 2
    with pytest.raises(ValueError,match='max_samples'):
        build_plan(('Exp1',),EMULATED_TEE_PROFILE,seeds=tuple(range(20)),
                   max_samples=10)
    wrong = dict(plan,plan_sha256='0'*64)
    with pytest.raises(ValueError,match='hash'):
        validate_plan(wrong)


def test_workload_generator_determinism_and_occurrence_bound():
    assert len(FAMILIES) == 6
    for family in FAMILIES:
        first = generate_workload(family,19)
        second = generate_workload(family,19)
        assert first.artifact() == second.artifact()
        assert first.workload_spec_sha256 != generate_workload(family,20).workload_spec_sha256
    repeat = generate_workload('W-REPEAT-ABACA',19)
    assert repeat.row_codes == (1,2,1,3,1)
    assert repeat.occurrence_ranks == (1,1,2,1,3)
    with pytest.raises(ValueError,match='cmax'):
        generate_workload('W-REPEAT-ABACA',19,cmax=2)
    with pytest.raises(ValueError,match='incompatible'):
        generate_workload('W-SINGLE',19,requested={'ell':5})
    assert generate_workload('W-AND',19,expected_outcome='UNAUTHORIZED').N == 1


def test_workload_seed_does_not_fix_ciphertext_randomness(tmp_path):
    spec = generate_workload('W-SINGLE',19)
    scheme = PublicMyABE08(sys_id=b'MYABE08-EXP-RNG-TEST', namespace='synthetic',
        backend=EMULATED_TEE_PROFILE,experiment_trust_mode=EMULATED_TEST_MODE,
        state_path=tmp_path/'state',clock=Clock())
    scheme.Setup(c_max=3,validity=Validity(100,2000))
    context_id=b'R'*32
    context=PolicyContext(scheme.sys_id,context_id,1,
        compute_ctx_priv(scheme.sys_id,context_id,1))
    first = scheme.Encrypt(message=b'RNG-isolation',policy=spec.policy(),
        context=context,data_id=b'same-data')
    second = scheme.Encrypt(message=b'RNG-isolation',policy=spec.policy(),
        context=context,data_id=b'same-data')
    assert serialize_ciphertext(first,scheme.crypto) != serialize_ciphertext(second,scheme.crypto)
    assert spec.artifact() == generate_workload('W-SINGLE',19).artifact()


def test_provenance_and_run_immutability(tmp_path, monkeypatch):
    environment={'host':'synthetic-test', 'python':{'version':'test'}}
    assert environment_fingerprint(environment) == environment_fingerprint(dict(environment))
    assert spec_manifest()['sha256'] == (
        'd52daf431bfececa4b1b8bf0f77fe34634710c9502d372f405b75b806812df85')
    code = code_manifest()
    assert code['files'] and code['tree_sha256']
    assert not any('__pycache__' in item['path'] or item['path'].endswith('.pyc')
                   for item in code['files'])
    plan=finalize_plan_hash(build_plan(('Exp4',),EMULATED_TEE_PROFILE))
    kwargs=dict(root=tmp_path,run_id='fixed-run-12345678',trust_cohort='test',
                trust_metadata={'TEEProfile':EMULATED_TEE_PROFILE})
    run=RunArtifacts(plan,environment,code,spec_manifest(),{'dirty':True},**kwargs)
    with pytest.raises(FileExistsError):
        RunArtifacts(plan,environment,code,spec_manifest(),{'dirty':True},**kwargs)
    assert run.manifest['status']=='RUNNING'
    run.finalize('INTERRUPTED')
    with pytest.raises(ValueError,match='status|provenance|incomplete'):
        validate_run(run.path)


@pytest.fixture(scope='module')
def emulated_smoke(tmp_path_factory):
    path=tmp_path_factory.mktemp('phase4f-smoke')
    result=run_smoke(('Exp3',),EMULATED_TEE_PROFILE,root=path,
                     warmups=0,repetitions=1)
    assert result['status']=='COMPLETE'
    return Path(result['run_path'])


def test_smoke_storage_and_canonical_raw_rows(emulated_smoke):
    assert validate_run(emulated_smoke)['status']=='PASS'
    rows=[json.loads(line) for line in (emulated_smoke/'raw.jsonl').read_text().splitlines()]
    assert len(rows)==2
    assert {row['variables']['policy_shape'] for row in rows} == {'single','repeated'}
    for row in rows:
        metric=row['metrics']
        assert row['schema_version']==SCHEMA_VERSION
        assert row['correctness_verified'] is True
        assert metric['ct_total_bytes']==sum(metric[name] for name in (
            'ct_core_bytes','header_bytes','af_total_bytes','dem_bytes',
            'publication_bytes'))
        assert metric['af_slot_bytes']>0 and metric['af_metadata_bytes']>0
        assert row['variables']['revocation_ciphertext_component_count']==0
        assert row['variables']['public_revocation_update_key_count']==0
        assert row['variables']['tree_TK_count']==0
        assert metric['host_to_tee_bytes']==NOT_OBSERVED


def test_validator_detects_hash_drift_canary_and_source_change(emulated_smoke,
                                                                tmp_path,monkeypatch):
    import shutil
    import core.myabe08.experiments.storage as storage
    copy=tmp_path/emulated_smoke.parent.name/emulated_smoke.name
    copy.parent.mkdir()
    shutil.copytree(emulated_smoke,copy)
    assert validate_run(copy)['status']=='PASS'
    (copy/'raw.jsonl').write_text((copy/'raw.jsonl').read_text()+'\n')
    with pytest.raises(ValueError,match='hash|size'):
        validate_run(copy)
    shutil.rmtree(copy)
    shutil.copytree(emulated_smoke,copy)
    (copy/'canary.log').write_text('PRIVATE-UID-4EFR-91e58e183d564fd7')
    with pytest.raises(ValueError,match='canary'):
        validate_run(copy)
    (copy/'canary.log').unlink()
    monkeypatch.setattr(storage,'code_manifest',lambda:{'tree_sha256':'0'*64})
    with pytest.raises(ValueError,match='source tree changed'):
        validate_run(copy)
    monkeypatch.undo()
    monkeypatch.setattr(storage,'spec_manifest',lambda:{'sha256':'0'*64})
    with pytest.raises(ValueError,match='provenance'):
        validate_run(copy)


def test_precheck_and_measured_failure_are_retained(tmp_path,monkeypatch):
    import core.myabe08.experiments.runner as runner
    original = runner._case
    def precheck_error(*args,**kwargs):
        raise RuntimeError('synthetic failure is not an artifact value')
    monkeypatch.setattr(runner,'_case',precheck_error)
    result=run_smoke(('Exp4',),EMULATED_TEE_PROFILE,root=tmp_path/'precheck')
    assert result['status']=='CORRECTNESS_PRECHECK_FAILED'
    path=Path(result['run_path'])
    assert json.loads((path/'manifest.json').read_text())['status']=='FAILED'
    assert not (path/'raw.jsonl').read_text()
    records=json.loads((path/'correctness.json').read_text())['records']
    assert records[0]['passed'] is False and records[0]['error_class']=='RuntimeError'
    count=[0]
    def second_attempt_error(*args,**kwargs):
        count[0]+=1
        if count[0]==2:
            raise RuntimeError('synthetic failure is not an artifact value')
        return original(*args,**kwargs)
    monkeypatch.setattr(runner,'_case',second_attempt_error)
    result=run_smoke(('Exp4',),EMULATED_TEE_PROFILE,root=tmp_path/'sample')
    assert result['status']=='CORRECTNESS_REGRESSION'
    path=Path(result['run_path'])
    assert json.loads((path/'manifest.json').read_text())['status']=='FAILED'
    rows=[json.loads(line) for line in (path/'raw.jsonl').read_text().splitlines()]
    assert len(rows)==1 and rows[0]['sample_status']=='FAILED'
    assert rows[0]['error_class']=='RuntimeError'
    assert rows[0]['correctness_verified'] is False
    assert rows[0]['metrics']['sample_attempt_ns']>=0
    assert 'synthetic failure is not an artifact value' not in (path/'raw.jsonl').read_text()
