"""Small correctness and protocol-contract tests; no formal benchmark rerun."""
from core.myabe08.baselines.phase5ds import (PROFILES, _order, design, plan,
    _context, _sys_id, smoke_probe, unauthorized_probe, verify_5dr)
from core.myabe08.baselines.phase5ds_report import claims, overheads, sources
from core.myabe08.experiments.provenance import spec_manifest


def test_plan_structure_and_interleave():
    frozen=plan()
    assert frozen['protocol']=='PAIRED_CORE_FULL_WORKLOAD_V1'
    assert frozen['blocks']==(7,7,6)
    assert frozen['expected_measured_rows']==420
    assert len(frozen['configurations'])==7
    for i,(_,spec) in enumerate(design()):
        assert spec.workload_spec_sha256==frozen['configurations'][i][
            'workload']['workload_spec_sha256']
        assert spec.ell==len(spec.row_codes)==len(spec.occurrence_ranks)
        assert spec.expected_outcome=='SUCCESS'
        assert frozen['configurations'][i]['sys_id_hex']==_sys_id(spec).hex()
        assert (frozen['configurations'][i]['policy_context_id_hex']==
                _context(_sys_id(spec),spec).policy_context_id.hex())
        for block,count in enumerate(frozen['blocks']):
            for sample in range(count):
                assert set(_order(i,block,sample,frozen))==set(PROFILES)
    assert design()[4][1].occurrence_ranks==(1,1,2,1,3)


def test_spec_and_frozen_core_code_unchanged():
    assert spec_manifest()['sha256']==(
        'd52daf431bfececa4b1b8bf0f77fe34634710c9502d372f405b75b806812df85')
    old=verify_5dr()
    assert old['ablation']['status']==old['core']['status']=='PASS'


def test_small_paired_correctness_and_unauthorized():
    assert smoke_probe()=={'core':'PASS','emulated':'PASS'}
    assert unauthorized_probe()=={'CORE':'UNAUTHORIZED',
        'FULL_EMULATED':'UNAUTHORIZED'}


def test_old_canonical_comparison_keeps_fabeo_access_disadvantage():
    evidence=claims(sources())
    by_id={row['claim_id']:row for row in evidence}
    assert by_id['FABEO-100-access_ns']['ratio']>1
    assert by_id['FABEO-100-access_ns']['comparability']=='DIRECTLY_COMPARABLE'
    assert by_id['FABEO-100-du_core_key_bytes']['comparability']=='KEY_PLACEMENT_TRADEOFF'


def test_access_stage_sum_never_gets_feature_overhead_ratio():
    def row(profile,metric,median):
        return dict(configuration_id='test',workload_id='WL-test',
            workload_name='W-test',ell=3,cmax=1,
            profile=profile,metric=metric,median=median,p95=median+1)
    summary=[row('CORE','encrypt_ns',10),row('CORE','access_ns',30),
        row('FULL_EMULATED','encrypt_ns',20),
        row('FULL_EMULATED','request_e2e_ns',50),
        row('FULL_REAL_SGX','encrypt_ns',40),
        row('FULL_REAL_SGX','request_e2e_ns',100)]
    values=overheads(summary)
    invalid=next(r for r in values if r['metric']=='access')
    assert invalid['comparison_class']=='NOT_DIRECTLY_COMPARABLE_STAGE_SUM_VS_WALLCLOCK'
    assert invalid['median_ratio'] is None and invalid['absolute_delta_ns'] is None
    assert next(r for r in values if r['ratio_name']=='feature_overhead_ratio')[
        'median_ratio']==2
