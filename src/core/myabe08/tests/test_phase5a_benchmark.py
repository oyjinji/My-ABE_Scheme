"""Controlled-run contracts independent of paper analysis."""
import json
from pathlib import Path

import pytest

from core.myabe08.experiments.phase5a import (
    build_phase5a_plan, execute_cohort, freeze_dataset, validate_dataset,
    validate_phase5a_plan)
from core.myabe08.experiments.workloads import (
    generate_benchmark_workload, sha256_json)
from core.myabe08.profile import EMULATED_TEE_PROFILE


def test_balanced_plan_covers_named_axes_and_rejects_tampering():
    plan=build_phase5a_plan(repetitions=20)
    assert validate_phase5a_plan(plan)
    assert len({c['configuration_id'] for c in plan['configurations']})==len(plan['configurations'])
    assert {c['experiment_id'] for c in plan['configurations']}=={'Exp1','Exp3','Exp4','Exp5'}
    assert {c['backend'] for c in plan['configurations'] if c['experiment_id']=='Exp4'}=={
        EMULATED_TEE_PROFILE,'SGX_DEBUG_GRAMINE_V1'}
    assert {c['ell'] for c in plan['configurations'] if c['experiment_id']=='Exp1'} >= {5,10,20,40}
    assert {c['shape'] for c in plan['configurations'] if c['experiment_id']=='Exp5'} >= {
        'AND','threshold','repeated'}
    damaged=dict(plan,phase5a_plan_sha256='0'*64)
    with pytest.raises(ValueError): validate_phase5a_plan(damaged)
    with pytest.raises(ValueError): build_phase5a_plan(repetitions=19)


def test_repeat_rows_are_complete_and_structure_seed_does_not_fix_crypto():
    spec=generate_benchmark_workload(shape='repeated',ell=5,cmax=3,N=5,
        hit_codes=2,threshold=2,seed=17)
    assert spec.row_codes==(1,1,1,2,2)
    assert spec.occurrence_ranks==(1,2,3,1,2)
    assert spec.cmax==3
    assert generate_benchmark_workload(shape='repeated',ell=5,cmax=3,N=5,
        hit_codes=2,threshold=2,seed=18).workload_spec_sha256!=spec.workload_spec_sha256
    with pytest.raises(ValueError):
        generate_benchmark_workload(shape='AND',ell=5,cmax=1,N=5,
            hit_codes=2,threshold=2,seed=17)


def test_one_canonical_storage_cohort_is_immutable_and_validated(tmp_path):
    plan=build_phase5a_plan(repetitions=20,warmups=0)
    plan['configurations']=[next(c for c in plan['configurations'] if
        c['experiment_id']=='Exp3' and c['ell']==5 and c['cmax']==1)]
    plan['expected_samples']={'Exp1':0,'Exp3':1,'Exp4':0,'Exp5':0}
    plan['phase5a_plan_sha256']=sha256_json({k:v for k,v in plan.items()
        if k!='phase5a_plan_sha256'})
    result=execute_cohort(plan,'Exp3',EMULATED_TEE_PROFILE,root=tmp_path)
    assert result['status']=='COMPLETE'
    path=Path(result['run_path'])
    rows=[json.loads(x) for x in (path/'raw.jsonl').read_text().splitlines()]
    assert len(rows)==1 and rows[0]['configuration_id']
    assert rows[0]['metrics']['ct_total_bytes']==sum(rows[0]['metrics'][name] for name in
        ('ct_core_bytes','header_bytes','af_total_bytes','dem_bytes','publication_bytes'))
    assert validate_dataset([path])['status']=='PASS'
    frozen=freeze_dataset([path])
    assert Path(frozen['dataset_manifest']).exists()
    with pytest.raises(FileExistsError): freeze_dataset([path])
