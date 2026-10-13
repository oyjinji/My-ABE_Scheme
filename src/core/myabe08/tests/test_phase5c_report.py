"""Isolated synthetic fixtures exercise report plumbing, never benchmark claims."""
from pathlib import Path
import tempfile

from core.myabe08.experiments.phase5c import RunWriter, TRUST_EXPECTED, validate_run
from core.myabe08.experiments.phase5c_report import compare, generate, verify
from core.myabe08.experiments.provenance import REPO, code_manifest, environment_manifest
from core.myabe08.experiments.phase5c_collect import _exp7_inventory
from core.myabe08.tests.test_phase5c_contracts import _plan


def _finish_exp6(root, plan, environment, code):
    writer=RunWriter('Exp6',plan,environment,code,dict(TRUST_EXPECTED),root=root)
    for size in plan['rl_grid']:
        for index in range(30):
            block=index//10;sample=index%10
            writer.append('ACTIVE_LOOKUP',rl_size=size,n_reg=5002,
                block_id=block,sample_index=sample,status='OK',
                expected='AUTHORIZED',actual='AUTHORIZED',
                metrics=dict(revset_lookup_ns=100+size+index))
            if size:
                writer.append('REVOKED_LOOKUP',rl_size=size,n_reg=5002,
                    block_id=block,sample_index=sample,status='EXPECTED_REJECT',
                    expected='REVOKED',actual='REVOKED',
                    metrics=dict(revset_lookup_ns=90+size+index,
                        user_tokens_emitted=0,t0_pairings=0,caps_emitted=0))
            for kind,actual_size in (('UPDATE_INSERT',size+1),
                                     ('UPDATE_DELETE',size)):
                writer.append(kind,rl_size=actual_size,n_reg=5002,
                    block_id=block,sample_index=sample,status='OK',
                    expected='COMMITTED',actual='COMMITTED',
                    metrics=dict(baseline_rl_size=size,
                        revstateupt_total_ns=1000+size+index))
    writer.evidence('state_memory',dict(snapshots=[dict(rl_size=size,
        revset_count=size,n_reg=5002,revset_logical_bytes=32+32*size,
        state_population_ns=size) for size in plan['rl_grid']]))
    writer.evidence('registration_memory',dict(snapshots=[dict(n_reg=size,
        rl_size=0,registration_state_logical_bytes=50*size)
        for size in plan['n_reg_grid']]))
    levels=[]
    for request_class in ('ACTIVE_AUTHORIZED','REVOKED_REJECT'):
        for fraction in plan['load_fractions']:
            writer.append('LOAD_'+request_class,rl_size=1000,n_reg=5002,
                block_id=round(fraction*100),sample_index=0,
                status='OK' if request_class=='ACTIVE_AUTHORIZED' else 'EXPECTED_REJECT',
                expected='AUTHORIZED' if request_class=='ACTIVE_AUTHORIZED' else 'REVOKED',
                actual='AUTHORIZED' if request_class=='ACTIVE_AUTHORIZED' else 'REVOKED',
                metrics=dict(request_latency_ns=1000000,
                    queue_delay_ns=100,revset_lookup_ns=100))
            levels.append(dict(request_class=request_class,
                target_fraction=fraction,target_request_rate_hz=fraction,
                actual_request_rate_hz=fraction,completed_count=1,failed_count=0))
    writer.evidence('load_plan',dict(levels=levels))
    writer.evidence('lifecycle',dict(historical_unconsumed_auth_valid=True))
    writer.evidence('adversarial',dict(stale_update_rejected=True))
    writer.evidence('canary_audit',dict(status='PASS',forbidden_value_hits=0,
        files_scanned=1))
    return writer.finish()


def _finish_exp7(root, plan, environment, code):
    writer=RunWriter('Exp7',plan,environment,code,dict(TRUST_EXPECTED),root=root)
    for kind in ('SAME_CONTEXT','CROSS_CONTEXT'):
        for index in range(100):
            writer.append(kind,rl_size=0,n_reg=1,block_id=index//10,
                sample_index=index%10,status='OK',expected='OBSERVED',
                actual='OBSERVED',metrics=dict(equal=kind=='SAME_CONTEXT'))
    writer.evidence('freshness',dict(sample_count=50,
        observations=[dict(component=name,sample_count=50,unique_count=50,
            collision_count=0) for name in ('request_nonce','K1q','K_tau_q','T0q','cap')]))
    writer.evidence('equality',dict(same_context_checks=100,
        same_context_equal_count=100,cross_context_checks=100,
        direct_cross_context_equal_count=0,same_context_af_success_count=50))
    writer.evidence('known_leakage',dict(same_user_same_ct_w_requests=50,
        all_equal=True,equality_count=50,
        same_user_different_ct_w_comparisons=1,
        same_user_different_ct_w_equal_count=0,
        different_user_same_ct_w_comparisons=1,
        different_user_same_ct_w_equal_count=0))
    writer.evidence('transcript_inventory',_exp7_inventory())
    writer.evidence('canary_audit',dict(status='PASS',forbidden_value_hits=0,
        files_scanned=1))
    return writer.finish()


def test_phase5c_report_reproduces_from_isolated_fixture():
    with tempfile.TemporaryDirectory(prefix='phase5c-report-test-',
                                     dir=REPO/'artifacts') as location:
        root=Path(location);plan=_plan()
        environment=environment_manifest();code=code_manifest()
        exp6=_finish_exp6(root,plan,environment,code)
        exp7=_finish_exp7(root,plan,environment,code)
        assert validate_run(exp6)['status']=='PASS'
        assert validate_run(exp7)['status']=='PASS'
        first=generate(exp6,exp7,root=root/'analysis')
        second=generate(exp6,exp7,root=root/'analysis')
        assert verify(first)['status']=='PASS'
        assert compare(first,second)['status']=='PASS'
