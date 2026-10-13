"""Real SGX DEBUG Phase 5C acquisition; no benchmark data is synthesized."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time

from ..crypto import compute_ctx_priv
from ..errors import MyABE08Error
from ..profile import SGX_DEBUG_GRAMINE_V1
from ..public import serialize_ciphertext
from ..real_tee.client import SgxDebugClient
from ..real_tee.rpc import RpcError
from ..revocation import (ACTIVATE, REVOKE, delta_plaintext,
    derive_revocation_handle, record_wire)
from ..signing import new_private_key, public_key_bytes, sign_canonical
from ..types import Attribute, PolicyContext, PolicyInput, RevocationUpdate, Validity
from ..encoding import encode
from .phase5c import (BUILD, ROOT, SGX, RunWriter, _require,
    validate_dataset, validate_run, validate_plan)
from .provenance import (REPO, code_manifest, environment_fingerprint,
                         environment_manifest, spec_manifest)
from .runner import _context, _new_scheme, _register, _trust_metadata
from .workloads import generate_workload


def calibrate(*,build_dir=BUILD):
    """Read-only budget probe on fresh TEST state; does not become formal data."""
    with _service(build_dir) as (client,log,temp):
        scheme,environment,trust=_ready_scheme(client,build_dir,temp/'kgc-state')
        spec=generate_workload('W-SINGLE',17)
        users=[];keygen=[];updates=[]
        for _ in range(3):
            started=time.perf_counter_ns()
            users.append(_register(scheme,spec))
            keygen.append(time.perf_counter_ns()-started)
        ct=scheme.Encrypt(message=b'phase5c-calibration',policy=spec.policy(),
            context=_context(scheme,spec),data_id=secrets.token_bytes(16))
        active=[]
        for _,user,holder in users:
            elapsed,_=_authorized(scheme,user,holder,ct)
            active.append(elapsed)
        for uid,_,_ in users:
            started=time.perf_counter_ns()
            _update(scheme,client,uid,REVOKE)
            updates.append(time.perf_counter_ns()-started)
        import statistics
        result=dict(schema='MYABE08-PHASE5C-CALIBRATION-V1',
            keygen_median_ns=int(statistics.median(keygen)),
            update_median_ns=int(statistics.median(updates)),
            active_authorize_median_ns=int(statistics.median(active)),
            samples_per_metric=3,
            environment_fingerprint=environment_fingerprint(environment),
            trust_cohort=trust,excluded_from_formal_dataset=True)
        client.stop_test_service();time.sleep(.2)
        if 'MYABE08_TEST_ERROR' in log.read_text(errors='replace'):
            raise ValueError('SGX calibration service error')
        return result


@contextmanager
def _service(build_dir: Path):
    client=SgxDebugClient()
    try:
        client.health()
    except (ConnectionError,OSError,TimeoutError):
        pass
    else:
        raise RuntimeError('Phase 5C requires an isolated SGX service')
    with tempfile.TemporaryDirectory(prefix='myabe08-phase5c-service-') as temp:
        log=Path(temp)/'service.log'
        with log.open('wb') as output:
            process=subprocess.Popen(('bash',str(REPO/
                'src/core/myabe08/real_tee/gramine/run_sgx.sh')),
                cwd=REPO,env=dict(os.environ,MYABE08_SGX_DEBUG_BUILD_DIR=str(build_dir)),
                stdout=output,stderr=subprocess.STDOUT)
            try:
                for _ in range(200):
                    if process.poll() is not None:
                        raise RuntimeError('Gramine SGX service exited before readiness')
                    try:
                        client.health();break
                    except (ConnectionError,OSError,TimeoutError):
                        time.sleep(.1)
                else:
                    raise RuntimeError('Gramine SGX service readiness timeout')
                yield client,log,Path(temp)
            finally:
                if process.poll() is None:
                    try:
                        client.stop_test_service();process.wait(timeout=10)
                    except Exception:
                        process.terminate();process.wait(timeout=10)


def _ready_scheme(client,build_dir,state_path):
    scheme=_new_scheme(SGX,state_path,build_dir=build_dir,client=client)
    setup=scheme.Setup(c_max=1,validity=Validity(100,2000))
    environment=environment_manifest(build_dir=build_dir)
    trust=_trust_metadata(scheme,environment)
    _require(trust['QVLApiReturn']==0 and trust['CollateralExpirationStatus']==0 and
             trust['QVLResult']=='SGX_QL_QV_RESULT_OUT_OF_DATE' and
             trust['StrictRA2']=='BLOCKED_BY_TCB_POLICY',
             'TRUST_COHORT_CHANGED')
    _require(setup.metadata['EnclaveDebug'] is True,
             'real SGX DEBUG identity unavailable')
    _require(environment['sgx']['mrenclave']==setup.metadata['MRENCLAVE'] and
             environment['sgx']['mrsigner']==setup.metadata['MRSIGNER'],
             'SGX build provenance differs from running enclave')
    return scheme,environment,trust


def _authorized(scheme,user,holder,ct):
    started=time.perf_counter_ns()
    scheme.TEEAuthorize(user=user,ciphertext=ct,
        auth_private_key=holder,expiry=1500)
    elapsed=time.perf_counter_ns()-started
    stage=scheme.authorize_breakdown_ns[-1]
    _require(type(stage['revset_lookup_ns']) is int and
             stage['revset_lookup_ns']>0,'active enclave lookup timing absent')
    return elapsed,stage['revset_lookup_ns']


def _revoked(scheme,client,user,holder,ct):
    started=time.perf_counter_ns()
    try:
        scheme.TEEAuthorize(user=user,ciphertext=ct,
            auth_private_key=holder,expiry=1500)
    except RpcError as exc:
        _require(exc.code=='REVOKED','revoked request had unexpected reject')
    else:
        raise ValueError('revoked request accepted')
    elapsed=time.perf_counter_ns()-started
    observation=client.observe_test_state()
    _require(observation['rejected_revset_lookup_ns']>0 and
             observation['rejected_user_tokens_emitted']==0 and
             observation['rejected_t0_pairings']==0 and
             observation['rejected_caps_emitted']==0,
             'revoked request crossed token/T0/cap boundary')
    return elapsed,observation


def _update(scheme,client,uid,operation):
    before=client.observe_test_state()
    started=time.perf_counter_ns()
    update=scheme.Rev(uid=uid,operation=operation)
    pending_ns=time.perf_counter_ns()-started
    started=time.perf_counter_ns()
    ack=scheme.RevStateUpt(update)
    total_ns=time.perf_counter_ns()-started
    after=client.observe_test_state()
    _require(after['rev_version']==before['rev_version']+1 and
             after['revset_count']==before['revset_count']+
                 (1 if operation==REVOKE else -1),
             'enclave exact RevSet update mismatch')
    return dict(pending_preparation_ns=pending_ns,
        revstateupt_total_ns=total_ns,
        enclave_state_apply_ns=after['enclave_state_apply_ns'],
        coordinator_commit_ns=after['coordinator_commit_ns'],
        production_sgx_persistence_ns='NOT_IMPLEMENTED'),update,ack


def _sample_lookup(writer,scheme,client,*,user,holder,ct,rl_size,
                   n_reg,kind,warmups,repetitions):
    active=kind=='ACTIVE_LOOKUP'
    for index in range(warmups+repetitions):
        if active:
            elapsed,lookup=_authorized(scheme,user,holder,ct)
            metric=dict(request_latency_ns=elapsed,revset_lookup_ns=lookup)
            status='OK';outcome='AUTHORIZED'
        else:
            elapsed,observation=_revoked(scheme,client,user,holder,ct)
            metric=dict(request_latency_ns=elapsed,
                revset_lookup_ns=observation['rejected_revset_lookup_ns'],
                user_tokens_emitted=0,t0_pairings=0,caps_emitted=0)
            status='EXPECTED_REJECT';outcome='REVOKED'
        if index>=warmups:
            measured=index-warmups
            writer.append(kind,rl_size=rl_size,n_reg=n_reg,
                block_id=measured//10,sample_index=measured%10,
                status=status,expected=outcome,actual=outcome,metrics=metric)


def _sample_updates(writer,scheme,client,spare_uid,rl_size,n_reg,
                    warmups,repetitions):
    for index in range(warmups+repetitions):
        insert,_,_=_update(scheme,client,spare_uid,REVOKE)
        delete,_,_=_update(scheme,client,spare_uid,ACTIVATE)
        if index>=warmups:
            measured=index-warmups
            for kind,metrics,actual_size in (
                ('UPDATE_INSERT',insert,rl_size+1),
                ('UPDATE_DELETE',delete,rl_size)):
                writer.append(kind,rl_size=actual_size,n_reg=n_reg,
                    block_id=measured//10,sample_index=measured%10,
                    status='OK',expected='COMMITTED',actual='COMMITTED',
                    metrics=dict(metrics,baseline_rl_size=rl_size))


def _run_load(writer,scheme,client,active_user,active_holder,
              revoked_user,revoked_holder,ct,rl_size,n_reg,plan,
              active_baseline_ns,revoked_baseline_ns):
    levels=[]
    for request_class,baseline_ns in (
        ('ACTIVE_AUTHORIZED',active_baseline_ns),
        ('REVOKED_REJECT',revoked_baseline_ns)):
        capacity=1_000_000_000/baseline_ns
        for fraction in plan['load_fractions']:
            target=capacity*fraction
            interval_ns=round(1_000_000_000/target)
            start=time.perf_counter_ns()
            end=start+plan['load_window_seconds']*1_000_000_000
            due=start
            collected=[]
            while due<end and time.perf_counter_ns()<end:
                now=time.perf_counter_ns()
                if now<due: time.sleep((due-now)/1_000_000_000)
                began=time.perf_counter_ns()
                if began>=end:break
                queue_delay=max(0,began-due)
                if request_class=='ACTIVE_AUTHORIZED':
                    elapsed,lookup=_authorized(scheme,active_user,active_holder,ct)
                    status='OK';outcome='AUTHORIZED'
                else:
                    elapsed,observed=_revoked(scheme,client,revoked_user,
                                              revoked_holder,ct)
                    lookup=observed['rejected_revset_lookup_ns']
                    status='EXPECTED_REJECT';outcome='REVOKED'
                collected.append((elapsed,lookup,queue_delay,status,outcome))
                due+=interval_ns
            duration=time.perf_counter_ns()-start
            actual=len(collected)*1_000_000_000/duration
            level=dict(request_class=request_class,rl_size=rl_size,n_reg=n_reg,
                target_fraction=fraction,target_request_rate_hz=target,
                actual_request_rate_hz=actual,completed_count=len(collected),
                failed_count=0,window_duration_ns=duration)
            levels.append(level)
            for index,(elapsed,lookup,queue_delay,status,outcome) in enumerate(collected):
                writer.append('LOAD_'+request_class,rl_size=rl_size,n_reg=n_reg,
                    block_id=round(fraction*100),sample_index=index,
                    status=status,expected=outcome,actual=outcome,
                    metrics=dict(request_latency_ns=elapsed,
                        revset_lookup_ns=lookup,queue_delay_ns=queue_delay,
                        target_request_rate_hz=target,
                        actual_request_rate_hz=actual))
    return levels


def _lifecycle(scheme,client,uid,user,holder,ct):
    before=scheme.TEEAuthorize(user=user,ciphertext=ct,
        auth_private_key=holder,expiry=1500)
    ct_wire=serialize_ciphertext(ct,scheme.crypto)
    rk=user.recovery_key
    token_before=tuple(item.token for item in before.authorization.bundle.items)
    insert,protected,ack=_update(scheme,client,uid,REVOKE)
    historical=scheme.Transform(ciphertext=ct,public_auth=before)
    historical_ok=scheme.FinalDec(partial=historical,recovery_key=rk)==b'phase5c'
    _revoked(scheme,client,user,holder,ct)
    delete,_,_=_update(scheme,client,uid,ACTIVATE)
    after=scheme.TEEAuthorize(user=user,ciphertext=ct,
        auth_private_key=holder,expiry=1500)
    token_after=tuple(item.token for item in after.authorization.bundle.items)
    result=dict(active_before=True,new_auth_after_revoke_blocked=True,
        historical_unconsumed_auth_valid=historical_ok,
        active_after_activate=True,
        ct_unchanged=serialize_ciphertext(ct,scheme.crypto)==ct_wire,
        rk_unchanged=user.recovery_key==rk,
        token_representation_not_reissued=token_before==token_after,
        test_time_semantics_only=True)
    _require(all(value is True for value in result.values()),
             'revocation lifecycle mismatch')
    return result,protected,ack


def _signed_test_update(scheme,client,*,version,predecessor,uid,operation=REVOKE):
    handle=derive_revocation_handle(scheme._k_rev,scheme.sys_id,uid)
    plain=delta_plaintext(scheme.sys_id,version,operation,handle,predecessor)
    signature=sign_canonical(scheme._kgc_key,'MYABE-REV-DELTA',plain)
    session=client.open_test_session(scheme.sys_id,'KGC')
    protected=RevocationUpdate(record_wire(session.send(
        encode(('MYABE-REV-SIGNED',plain,signature)))))
    return session,protected


def _state_unavailable(scheme,user,holder,ct):
    try:
        scheme.TEEAuthorize(user=user,ciphertext=ct,
            auth_private_key=holder,expiry=1500)
    except RpcError as exc:
        return exc.code=='STATE_UNAVAILABLE'
    return False


def _adversarial(scheme,client,spare_uid,active_uid,active_user,
                 active_holder,ct,replay_update,replay_ack):
    results={}
    session=client.open_test_session(scheme.sys_id,'KGC')
    replayed=client.rev_state_update(session,replay_update)
    results['exact_replay_idempotent']=(replayed==replay_ack)
    current=scheme._manager.version
    predecessor=scheme._manager.digest
    cases=(('stale_update',current,predecessor),
           ('future_update',current+2,predecessor),
           ('out_of_order_update',current+2,predecessor),
           ('wrong_predecessor',current+1,secrets.token_bytes(32)))
    for name,version,digest in cases:
        session,protected=_signed_test_update(scheme,client,version=version,
            predecessor=digest,uid=spare_uid)
        try:client.rev_state_update(session,protected)
        except RpcError as exc:
            results[name+'_rejected']=exc.code in ('STATE_UNAVAILABLE','AUTH_FAILED')
        else:results[name+'_rejected']=False
    observed=client.observe_test_state()
    results['invalid_updates_leave_version_unchanged']=observed['rev_version']==current
    # A stale signed delta is the rollback attempt at the TEST protocol boundary.
    results['rollback_update_rejected']=results['stale_update_rejected']
    first_session,first=_signed_test_update(scheme,client,version=current+1,
        predecessor=predecessor,uid=spare_uid)
    second_session,second=_signed_test_update(scheme,client,version=current+1,
        predecessor=predecessor,uid=active_uid)
    first_ack=client.rev_state_update(first_session,first)
    try:client.rev_state_update(second_session,second)
    except RpcError as exc:
        second_rejected=exc.code in ('STATE_UNAVAILABLE','AUTH_FAILED')
    else:second_rejected=False
    client.commit_test_head(current,predecessor,first_ack)
    results['concurrent_conflicting_update_rejected']=(second_rejected and
        client.observe_test_state()['rev_version']==current+1)
    client.test_state_fault('FREEZE_ON')
    results['freeze_fails_closed']=_state_unavailable(scheme,active_user,
                                                       active_holder,ct)
    client.test_state_fault('FREEZE_OFF')
    client.test_state_fault('HEAD_AHEAD_ON')
    results['lost_update_fails_closed']=_state_unavailable(scheme,active_user,
                                                            active_holder,ct)
    client.test_state_fault('HEAD_AHEAD_OFF')
    client.test_state_fault('LOCAL_ROLLBACK')
    results['local_rollback_fails_closed']=_state_unavailable(scheme,active_user,
                                                               active_holder,ct)
    _require(all(results.values()),'adversarial state update failure')
    return results


def _audit_canaries(writer,service_log,canaries,*,public_transcript='',
                    blob_digests=()):
    """Scan controlled surfaces without persisting identifiers or Blob digests."""
    markers=('SYNTHETIC-UID-','TEST-UID-','TEST-ATTRIBUTE-')
    forbidden=set(canaries)|set(blob_digests)
    forbidden.discard('')
    def has_leak(content):
        if any(marker in content for marker in markers):
            return True
        # Compare candidate hex words once, rather than scanning each large
        # artifact thousands of times for every registered user's Blob digest.
        import re
        words=set(re.findall(r'(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])',content))
        return bool(words & forbidden) or any(
            value in content for value in forbidden if len(value)!=64)
    inspected=0
    for item in sorted(writer.path.iterdir()):
        if item.is_file() and item.suffix in ('.json','.jsonl','.csv','.md','.log'):
            content=item.read_text(errors='replace')
            inspected+=1
            if has_leak(content):
                raise ValueError('TRANSCRIPT_PRIVACY_DEFECT')
    content=service_log.read_text(errors='replace')
    inspected+=1
    if has_leak(content):
        raise ValueError('TRANSCRIPT_PRIVACY_DEFECT')
    if has_leak(public_transcript):
        raise ValueError('TRANSCRIPT_PRIVACY_DEFECT')
    writer.evidence('canary_audit',dict(status='PASS',files_scanned=inspected,
        checked_surfaces=['run text artifacts','Gramine SGX service log',
            'public object repr','all registered Blob digests',
            'synthetic identifier prefixes'],
        forbidden_value_hits=0))
    with (writer.path/'service.log').open('xb') as output:
        output.write(service_log.read_bytes())


def collect_exp6(plan, frozen_code, *, root=ROOT, build_dir=BUILD):
    """Sequential real exact-set design; measured samples use 3×10 blocks."""
    validate_plan(plan)
    _require(code_manifest()['tree_sha256']==frozen_code['tree_sha256'],
             'Phase 5C code changed after freeze')
    with _service(build_dir) as (client,log,temp):
        scheme,environment,trust=_ready_scheme(client,build_dir,temp/'kgc-state')
        writer=RunWriter('Exp6',plan,environment,frozen_code,trust,root=root)
        try:
            spec=generate_workload('W-SINGLE',17)
            active_uid,active_user,active_holder=_register(scheme,spec)
            spare_uid,spare_user,spare_holder=_register(scheme,spec)
            filler=[];revoked_user=None;revoked_holder=None
            blob_digests={hashlib.sha256(user.blob.opaque).hexdigest()
                for user in (active_user,spare_user)}
            registration=[]
            max_rl=max(plan['rl_grid'])
            started=time.perf_counter_ns()
            for index in range(max_rl):
                uid,user,holder=_register(scheme,spec)
                filler.append(uid)
                blob_digests.add(hashlib.sha256(user.blob.opaque).hexdigest())
                if index==0:revoked_user,revoked_holder=user,holder
                count=index+3
                if count in plan['n_reg_grid']:
                    observed=client.observe_test_state()
                    _require(observed['registration_state_count']==count and
                             observed['revset_count']==0,
                             'enclave registration state count mismatch')
                    registration.append(dict(n_reg=count,rl_size=0,
                        registration_state_count=count,
                        registration_state_logical_bytes=
                            observed['registration_state_logical_bytes'],
                        state_population_ns=time.perf_counter_ns()-started))
            writer.evidence('registration_memory',dict(schema='MYABE08-PHASE5C-EXP6',
                method='canonical encoded enclave credential/version registry entries',
                snapshots=registration))
            ct=scheme.Encrypt(message=b'phase5c',policy=spec.policy(),
                context=_context(scheme,spec),data_id=secrets.token_bytes(16))
            state_memory=[];load_levels=[];current_rl=0
            for target in plan['rl_grid']:
                population_started=time.perf_counter_ns()
                for index in range(current_rl,target):
                    _update(scheme,client,filler[index],REVOKE)
                state_population_ns=time.perf_counter_ns()-population_started
                current_rl=target
                observed=client.observe_test_state()
                _require(observed['revset_count']==target,
                         'claimed RevSet size differs from enclave')
                n_reg=observed['registration_state_count']
                state_memory.append(dict(rl_size=target,revset_count=target,
                    revset_logical_bytes=observed['revset_logical_bytes'],
                    n_reg=n_reg,state_population_ns=state_population_ns,
                    measurement_method='canonical enclave ExactRevocationSet encoding',
                    process_rss_bytes='NOT_OBSERVED'))
                _sample_lookup(writer,scheme,client,user=active_user,
                    holder=active_holder,ct=ct,rl_size=target,n_reg=n_reg,
                    kind='ACTIVE_LOOKUP',warmups=plan['warmups'],
                    repetitions=plan['repetitions'])
                if target>0:
                    _sample_lookup(writer,scheme,client,user=revoked_user,
                        holder=revoked_holder,ct=ct,rl_size=target,n_reg=n_reg,
                        kind='REVOKED_LOOKUP',warmups=plan['warmups'],
                        repetitions=plan['repetitions'])
                _sample_updates(writer,scheme,client,spare_uid,target,n_reg,
                    plan['warmups'],plan['repetitions'])
                if target==1000:
                    measured=[json.loads(line) for line in
                        (writer.path/'raw.jsonl').read_text().splitlines()]
                    active=[row for row in measured if
                        row['kind']=='ACTIVE_LOOKUP' and row['rl_size']==target]
                    revoked=[row for row in measured if
                        row['kind']=='REVOKED_LOOKUP' and row['rl_size']==target]
                    _require(len(active)==len(revoked)==plan['repetitions'],
                             'request-load calibration samples incomplete')
                    import statistics
                    active_baseline=statistics.median(
                        row['metrics']['request_latency_ns'] for row in active)
                    revoked_baseline=statistics.median(
                        row['metrics']['request_latency_ns'] for row in revoked)
                    load_levels=_run_load(writer,scheme,client,
                        active_user,active_holder,revoked_user,revoked_holder,
                        ct,target,n_reg,plan,active_baseline,revoked_baseline)
            writer.evidence('state_memory',dict(schema='MYABE08-PHASE5C-EXP6',
                snapshots=state_memory,production_sgx_persistence_ns='NOT_IMPLEMENTED'))
            writer.evidence('load_plan',dict(schema='MYABE08-PHASE5C-EXP6',
                calibration_rl_size=1000,levels=load_levels,
                request_classes_kept_separate=True))
            lifecycle,replay_update,replay_ack=_lifecycle(scheme,client,
                spare_uid,spare_user,spare_holder,ct)
            writer.evidence('lifecycle',lifecycle)
            writer.evidence('adversarial',_adversarial(scheme,client,spare_uid,
                active_uid,active_user,active_holder,ct,replay_update,replay_ack))
            client.stop_test_service();time.sleep(.2)
            _audit_canaries(writer,log,(active_uid,spare_uid),
                            blob_digests=blob_digests)
            path=writer.finish()
            validate_run(path)
            return path
        except BaseException:
            if not writer._raw.closed:writer.finish(status='FAILED')
            raise


def _exp7_inventory():
    """Protocol-defined CSP surface, without material values or stable IDs."""
    fields=(
        ('CT','SysID/context/DataID/AF/header/DEM/publication','CT-stable','ALLOWED'),
        ('Auth','Bq tokens/K1q/K_tau_q/T0q/cap/nonce/rev_version','request-local plus context-stable token equality','ALLOWED_WITH_KNOWN_LEAKAGE'),
        ("CT'",'CT/Auth/T_A/J/I/tI','request-local','ALLOWED'),
        ('RPC host metadata','message type/frame length/request ID/timing','request-local','ALLOWED'),
        ('service logs','TEST readiness and controlled error class','UNKNOWN','DENYLIST_AUDITED'),
        ('metrics and experiment artifacts','counts/durations/state sizes','aggregate','ALLOWED'),
    )
    return dict(schema='MYABE08-PHASE5C-EXP7',
        rows=[dict(surface=a,visible_fields=b,stability=c,allowance=d)
              for a,b,c,d in fields],
        forbidden_fields=['UID','rh_id','K0','mu','K_rev','K_tok','sk_cap',
            'delta_q','plaintext Blob','stable plaintext Blob digest'],
        known_leakage=['DataID','context','same-context token equality',
            'access timing/count','AF hits','J/I','ciphertext identity',
            'revocation behavior','stable same-user/same-CT W'])


def collect_exp7(plan,frozen_code,*,root=ROOT,build_dir=BUILD):
    validate_plan(plan)
    _require(code_manifest()['tree_sha256']==frozen_code['tree_sha256'],
             'Phase 5C code changed after freeze')
    with _service(build_dir) as (client,log,temp):
        scheme,environment,trust=_ready_scheme(client,build_dir,temp/'kgc-state')
        writer=RunWriter('Exp7',plan,environment,frozen_code,trust,root=root)
        try:
            canary='TEST-ATTRIBUTE-'+secrets.token_hex(16)
            label=Attribute('synthetic','label',canary)
            uid='TEST-UID-'+secrets.token_hex(16)
            holder=new_private_key()
            user=scheme.KeyGen(uid=uid,attributes=(label,),
                auth_public_key=public_key_bytes(holder),
                validity=Validity(100,2000))
            context_id=secrets.token_bytes(32)
            context=PolicyContext(scheme.sys_id,context_id,1,
                compute_ctx_priv(scheme.sys_id,context_id,1))
            policy=PolicyInput(((1,),),(label,))
            ct=scheme.Encrypt(message=b'phase5c-exp7',policy=policy,
                context=context,data_id=secrets.token_bytes(16))
            components={name:set() for name in
                ('request_nonce','K1q','K_tau_q','T0q','cap')}
            token_same=0;w_values=set();first_token=None
            for index in range(100):
                auth=scheme.TEEAuthorize(user=user,ciphertext=ct,
                    auth_private_key=holder,expiry=1500)
                bundle=auth.authorization.bundle
                token=bundle.items[0].token
                if first_token is None:first_token=token
                token_same+=token==first_token
                if index<50:
                    components['request_nonce'].add(auth.authorization.capability.request_nonce)
                    components['K1q'].add(scheme.crypto.serialize_g2(bundle.k1_q))
                    components['K_tau_q'].add(scheme.crypto.serialize_g1(bundle.items[0].k_tau_q))
                    components['T0q'].add(scheme.crypto.serialize_gt(bundle.t0_q))
                    components['cap'].add(auth.authorization.capability.signature)
                    partial=scheme.Transform(ciphertext=ct,public_auth=auth)
                    w=scheme.crypto.gt_div(bundle.t0_q,partial.t_a)
                    w_values.add(scheme.crypto.serialize_gt(w))
                    _require(scheme.FinalDec(partial=partial,
                        recovery_key=user.recovery_key)==b'phase5c-exp7',
                        'Exp7 AF/FinalDec correctness failed')
                writer.append('SAME_CONTEXT',rl_size=0,n_reg=1,
                    block_id=index//10,sample_index=index%10,status='OK',
                    expected='TOKEN_EQUAL',actual='TOKEN_EQUAL' if token==first_token else 'UNEQUAL',
                    metrics=dict(same_context_equal=token==first_token,
                        af_same_context_hit=True if index<50 else 'NOT_OBSERVED'))
            _require(token_same==100 and len(w_values)==1,
                     'Exp7 equality or stable W observation failed')
            stable_w=next(iter(w_values))
            different_ct=scheme.Encrypt(message=b'phase5c-exp7',policy=policy,
                context=context,data_id=secrets.token_bytes(16))
            different_auth=scheme.TEEAuthorize(user=user,ciphertext=different_ct,
                auth_private_key=holder,expiry=1500)
            different_partial=scheme.Transform(ciphertext=different_ct,
                public_auth=different_auth)
            different_ct_w=scheme.crypto.serialize_gt(scheme.crypto.gt_div(
                different_auth.authorization.bundle.t0_q,different_partial.t_a))
            second_uid='TEST-UID-'+secrets.token_hex(16)
            second_holder=new_private_key()
            second_user=scheme.KeyGen(uid=second_uid,attributes=(label,),
                auth_public_key=public_key_bytes(second_holder),
                validity=Validity(100,2000))
            second_auth=scheme.TEEAuthorize(user=second_user,ciphertext=ct,
                auth_private_key=second_holder,expiry=1500)
            second_partial=scheme.Transform(ciphertext=ct,public_auth=second_auth)
            different_user_w=scheme.crypto.serialize_gt(scheme.crypto.gt_div(
                second_auth.authorization.bundle.t0_q,second_partial.t_a))
            direct_equal=0
            for index in range(100):
                other_context_id=secrets.token_bytes(32)
                other_context=PolicyContext(scheme.sys_id,other_context_id,1,
                    compute_ctx_priv(scheme.sys_id,other_context_id,1))
                other_ct=scheme.Encrypt(message=b'phase5c-exp7',policy=policy,
                    context=other_context,data_id=secrets.token_bytes(16))
                other_auth=scheme.TEEAuthorize(user=user,ciphertext=other_ct,
                    auth_private_key=holder,expiry=1500)
                equal=other_auth.authorization.bundle.items[0].token==first_token
                direct_equal+=equal
                writer.append('CROSS_CONTEXT',rl_size=0,n_reg=1,
                    block_id=index//10,sample_index=index%10,status='OK',
                    expected='OBSERVED',actual='OBSERVED',
                    metrics=dict(direct_token_equality=equal))
            fresh=dict(sample_count=50,observations=[dict(component=name,
                sample_count=50,unique_count=len(values),
                collision_count=50-len(values),
                interpretation='finite-sample observation, not randomness proof')
                for name,values in components.items()])
            _require(all(item['collision_count']==0 for item in fresh['observations']),
                     'unexpected request-component collision')
            writer.evidence('freshness',fresh)
            writer.evidence('equality',dict(same_context_checks=100,
                same_context_equal_count=token_same,cross_context_checks=100,
                direct_cross_context_equal_count=direct_equal,
                same_context_af_success_count=50,
                interpretation='direct equality observations only'))
            writer.evidence('known_leakage',dict(same_user_same_ct_w_requests=50,
                all_equal=len(w_values)==1,equality_count=50,
                same_user_different_ct_w_equal_count=int(different_ct_w==stable_w),
                same_user_different_ct_w_comparisons=1,
                different_user_same_ct_w_equal_count=int(different_user_w==stable_w),
                different_user_same_ct_w_comparisons=1,
                disclosure='stable W for same user and CT is known linkability'))
            writer.evidence('transcript_inventory',_exp7_inventory())
            client.stop_test_service();time.sleep(.2)
            blob_digest=hashlib.sha256(user.blob.opaque).hexdigest()
            public_transcript='\n'.join(map(repr,(user,ct,auth,partial,
                different_auth,different_partial,second_auth,second_partial,
                scheme.authorize_breakdown_ns,scheme.transform_breakdown_ns)))
            second_blob_digest=hashlib.sha256(second_user.blob.opaque).hexdigest()
            _audit_canaries(writer,log,(uid,second_uid,canary),
                            public_transcript=public_transcript,
                            blob_digests=(blob_digest,second_blob_digest))
            path=writer.finish();validate_run(path)
            return path
        except BaseException:
            if not writer._raw.closed:writer.finish(status='FAILED')
            raise
