"""Small correctness-gated public-facade smoke runner, never a benchmark."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import secrets
import tempfile
import time
import uuid

from ..crypto import compute_ctx_priv
from ..encoding import encode
from ..errors import MyABE08Error, Unauthorized
from ..profile import EMULATED_TEE_PROFILE, SGX_DEBUG_GRAMINE_V1
from ..public import (EMULATED_TEST_MODE, PublicMyABE08,
                      serialize_ciphertext)
from ..real_tee.attested_session import FEASIBILITY_MODE
from ..real_tee.client import SgxDebugClient
from ..real_tee.rpc import RpcError
from ..real_tee.identity_policy import SgxIdentityPolicy
from ..revocation import ACTIVATE, REVOKE
from ..signing import new_private_key, public_key_bytes
from ..types import PolicyContext, Validity
from . import SCHEMA_VERSION
from .provenance import (REPO, code_manifest, environment_manifest, git_provenance,
                         spec_manifest)
from .registry import REGISTRY, BLOCKED
from .schema import (DEFAULT_SCOPES, METRIC_UNITS, NOT_OBSERVED,
                     build_plan, finalize_plan_hash)
from .storage import RunArtifacts, canonical_storage_breakdown, validate_run
from .workloads import generate_workload


class TestClock:
    def now(self): return 1000


def _last_span(scheme, name):
    values = scheme.spans_ns.get(name, ())
    return values[-1] if values else NOT_OBSERVED


def _observed(value):
    return NOT_OBSERVED if value is None else value


def _context(scheme, spec):
    # Fresh request context is independent of workload_seed and crypto RNG.
    context_id = secrets.token_bytes(32)
    return PolicyContext(scheme.sys_id, context_id, 1,
                         compute_ctx_priv(scheme.sys_id, context_id, 1))


def _register(scheme, spec):
    holder = new_private_key()
    uid = 'SYNTHETIC-UID-' + uuid.uuid4().hex
    user = scheme.KeyGen(uid=uid, attributes=spec.user_attributes(),
        auth_public_key=public_key_bytes(holder), validity=Validity(100,2000))
    return uid, user, holder


def _pairing_precheck(auth, partial):
    t_i = len(partial.occurrence_slots)
    return (auth.tee_pairings == 1 and partial.csp_pairings == 1 + t_i and
            auth.tee_pairings + partial.csp_pairings == 2 + t_i)


def _success_case(scheme, spec, experiment_id):
    uid, user, holder = _register(scheme, spec)
    message = secrets.token_bytes(spec.message_length)
    ct = scheme.Encrypt(message=message, policy=spec.policy(),
        context=_context(scheme,spec), data_id=secrets.token_bytes(16))
    started = time.perf_counter_ns()
    auth = scheme.TEEAuthorize(user=user, ciphertext=ct,
                                auth_private_key=holder, expiry=1500)
    breakdown = dict(scheme.authorize_breakdown_ns[-1])
    partial = scheme.Transform(ciphertext=ct, public_auth=auth)
    recovered = scheme.FinalDec(partial=partial, recovery_key=user.recovery_key)
    request_e2e_ns = time.perf_counter_ns()-started
    primary_spans = {name:_last_span(scheme,name) for name in
        ('KeyGen','Encrypt','TEEAuthorize','Transform','FinalDec')}
    encrypt_breakdown = dict(scheme.encrypt_breakdown_ns[-1])
    transform_breakdown = dict(scheme.transform_breakdown_ns[-1])
    correct = recovered == message and _pairing_precheck(auth, partial)
    if spec.family == 'W-REPEAT-ABACA':
        correct = correct and spec.occurrence_ranks == (1,1,2,1,3)
        correct = correct and partial.occurrence_slots == (2,3)
    extra = {}
    if experiment_id == 'Exp4':
        same_auth = scheme.TEEAuthorize(user=user, ciphertext=ct,
            auth_private_key=holder, expiry=1500)
        other_ct = scheme.Encrypt(message=secrets.token_bytes(spec.message_length),
            policy=spec.policy(), context=_context(scheme,spec),
            data_id=secrets.token_bytes(16))
        cross_auth = scheme.TEEAuthorize(user=user, ciphertext=other_ct,
            auth_private_key=holder, expiry=1500)
        tokens = lambda item: tuple(x.token for x in item.authorization.bundle.items)
        extra['same_context_equal'] = tokens(auth) == tokens(same_auth)
        extra['cross_context_equal_observed'] = tokens(auth) == tokens(cross_auth)
        correct = correct and extra['same_context_equal']
    if experiment_id == 'Exp7':
        second = scheme.TEEAuthorize(user=user, ciphertext=ct,
            auth_private_key=holder, expiry=1500)
        second_partial = scheme.Transform(ciphertext=ct, public_auth=second)
        second_message = scheme.FinalDec(partial=second_partial,
                                         recovery_key=user.recovery_key)
        first_w = scheme.crypto.gt_div(auth.authorization.bundle.t0_q, partial.t_a)
        second_w = scheme.crypto.gt_div(second.authorization.bundle.t0_q,
                                        second_partial.t_a)
        extra['known_w_stable'] = (scheme.crypto.serialize_gt(first_w) ==
                                   scheme.crypto.serialize_gt(second_w))
        # Inspect only in-memory public repr; neither canary nor W bytes are written.
        transcript = '\n'.join(map(repr, (user, auth, ct, partial,
                                           scheme.authorize_breakdown_ns)))
        canaries = (uid,) + tuple(attr.value for attr in spec.user_attributes())
        extra['audit_status'] = 'PASS' if (
            all(canary not in transcript for canary in canaries) and
            hashlib.sha256(user.blob.opaque).hexdigest() not in transcript) else 'FAIL'
        correct = correct and second_message == message and extra['known_w_stable']
        correct = correct and extra['audit_status'] == 'PASS'
    return dict(correct=correct, expected_outcome='SUCCESS', actual_outcome='SUCCESS'
        if correct else 'CORRECTNESS_REGRESSION', error_class=None,
        request_e2e_ns=request_e2e_ns, ct=ct, auth=auth, partial=partial,
        user=user, breakdown=breakdown, extra=extra,
        primary_spans=primary_spans, encrypt_breakdown=encrypt_breakdown,
        transform_breakdown=transform_breakdown)


def _revoked_case(scheme, spec, target_rl):
    # Independent synthetic state-only probe. These are not the enclave's
    # hidden RevSet bytes and never become a public RevSet wire format.
    state = set()
    handles = tuple(secrets.token_bytes(32) for _ in range(target_rl))
    started = time.perf_counter_ns()
    state.update(handles)
    state_insert_ns = time.perf_counter_ns()-started
    logical_bytes = len(encode(tuple(sorted(state))))
    started = time.perf_counter_ns()
    all_found = all(handle in state for handle in handles)
    state_lookup_ns = time.perf_counter_ns()-started
    started = time.perf_counter_ns()
    for handle in handles:
        state.remove(handle)
    state_delete_ns = time.perf_counter_ns()-started
    filler_uids = []
    for _ in range(target_rl-1):
        filler_uid, _, _ = _register(scheme,spec)
        update = scheme.Rev(uid=filler_uid, operation=REVOKE)
        scheme.RevStateUpt(update)
        filler_uids.append(filler_uid)
    uid, user, holder = _register(scheme,spec)
    message = secrets.token_bytes(spec.message_length)
    ct = scheme.Encrypt(message=message, policy=spec.policy(),
        context=_context(scheme,spec), data_id=secrets.token_bytes(16))
    ct_before = serialize_ciphertext(ct,scheme.crypto)
    before = scheme.TEEAuthorize(user=user, ciphertext=ct,
                                 auth_private_key=holder, expiry=1500)
    recovery_key_before = user.recovery_key
    update = scheme.Rev(uid=uid, operation=REVOKE)
    scheme.RevStateUpt(update)
    rev_ns, update_ns = _last_span(scheme,'Rev'), _last_span(scheme,'RevStateUpt')
    started = time.perf_counter_ns()
    actual, error_class = 'ERROR', None
    try:
        scheme.TEEAuthorize(user=user, ciphertext=ct,
                            auth_private_key=holder, expiry=1500)
    except (MyABE08Error, RpcError) as exc:
        error_class = type(exc).__name__
        if 'revoked' in str(exc).lower() or 'REVOKED' in str(exc):
            actual = 'REVOKED'
    request_e2e_ns = time.perf_counter_ns()-started
    # Previously issued, unconsumed Auth retains the original request semantics.
    historical = scheme.Transform(ciphertext=ct, public_auth=before)
    historical_valid = scheme.FinalDec(partial=historical,
                                      recovery_key=user.recovery_key) == message
    update = scheme.Rev(uid=uid, operation=ACTIVATE)
    scheme.RevStateUpt(update)
    after = scheme.TEEAuthorize(user=user, ciphertext=ct,
                                auth_private_key=holder, expiry=1500)
    tokens = lambda auth: tuple(item.token for item in auth.authorization.bundle.items)
    token_unchanged = tokens(before) == tokens(after)
    ct_unchanged = serialize_ciphertext(ct, scheme.crypto) == ct_before
    rk_unchanged = user.recovery_key == recovery_key_before
    for filler_uid in filler_uids:
        update = scheme.Rev(uid=filler_uid, operation=ACTIVATE)
        scheme.RevStateUpt(update)
    correct = (actual == 'REVOKED' and all_found and not state and
               historical_valid and token_unchanged and
               ct_unchanged and rk_unchanged)
    return dict(correct=correct, expected_outcome='REVOKED', actual_outcome=actual,
        error_class=error_class, request_e2e_ns=request_e2e_ns,
        ct=ct, auth=before, partial=historical, user=user, breakdown={},
        extra=dict(token_updated=not token_unchanged, ct_updated=not ct_unchanged,
                   rk_updated=not rk_unchanged, rev_ns=rev_ns,
                   revstateupt_ns=update_ns, requested_RL_size=target_rl,
                   acknowledged_revoked_count=target_rl,
                   historical_auth_valid=historical_valid,
                   state_only_insert_ns=state_insert_ns,
                   state_only_lookup_ns=state_lookup_ns,
                   state_only_delete_ns=state_delete_ns,
                   state_only_revset_logical_bytes=logical_bytes))


def _case(scheme, spec, experiment_id):
    if experiment_id == 'Exp6':
        return _revoked_case(scheme,spec,1 if spec.family == 'W-SINGLE' else 2)
    return _success_case(scheme,spec,experiment_id)


def _trust_metadata(scheme, environment):
    meta = scheme.metadata
    result = dict(TEEProfile=scheme.backend_id,
        ExperimentTrustMode=scheme.experiment_trust_mode,
        CurrentHeadMode=scheme.current_head_mode,
        QVLApiReturn=meta.get('QVLApiReturn','NOT_APPLICABLE'),
        CollateralExpirationStatus=meta.get('CollateralExpirationStatus','NOT_APPLICABLE'),
        QVLResult=meta.get('QVLResult','NOT_APPLICABLE'),
        StrictRA2=meta.get('StrictRA2','NOT_APPLICABLE'),
        EnclaveDebug=meta.get('EnclaveDebug',False),
        PCCSReachable=environment['pccs']['reachable'],
        PCCSDeploymentMode=environment['pccs']['deployment_mode'])
    if scheme.backend_id == SGX_DEBUG_GRAMINE_V1 and (
        result['QVLApiReturn'] != 0 or result['CollateralExpirationStatus'] != 0 or
        result['QVLResult'] != 'SGX_QL_QV_RESULT_OUT_OF_DATE' or
        result['StrictRA2'] != 'BLOCKED_BY_TCB_POLICY' or
        result['EnclaveDebug'] is not True or not result['PCCSReachable']):
        raise ValueError('real SGX feasibility trust metadata mismatch')
    return result


def _new_scheme(backend, state_path, build_dir=None, client=None):
    sys_id = b'MYABE08-EXP-TEST-' + secrets.token_bytes(12)
    if backend == SGX_DEBUG_GRAMINE_V1:
        audit_path = Path(build_dir or '/tmp/myabe08-sgx-ra-probe')/'build_audit.json'
        audit = json.loads(audit_path.read_text())
        if audit.get('debug') is not True or audit.get('remote_attestation') != 'dcap':
            raise ValueError('real SGX DEBUG DCAP build audit required')
        policy = SgxIdentityPolicy('phase4f-exact', SGX_DEBUG_GRAMINE_V1,
            mrenclave=bytes.fromhex(audit['mrenclave']), allow_debug=True)
        return PublicMyABE08(sys_id=sys_id, namespace='synthetic', backend=backend,
            experiment_trust_mode=FEASIBILITY_MODE, identity_policy=policy,
            state_path=state_path, clock=TestClock(),
            client=client or SgxDebugClient(), test_tee_bootstrap=True)
    return PublicMyABE08(sys_id=sys_id, namespace='synthetic', backend=backend,
        experiment_trust_mode=EMULATED_TEST_MODE, state_path=state_path,
        clock=TestClock())


def _row(scheme, spec, experiment_id, result, artifacts, trust, code_hash):
    extra = result['extra']
    partial, auth = result['partial'], result['auth']
    variables = dict(ell=spec.ell, d=spec.d, u=spec.u, N=spec.N,
        cmax=spec.cmax, k=len(partial.reconstruction_rows),
        requested_J=spec.requested.get('J',NOT_OBSERVED),
        actual_J=len(partial.candidate_rows),
        requested_tI=spec.requested.get('tI',NOT_OBSERVED),
        actual_tI=len(partial.occurrence_slots),
        L_hit=spec.requested.get('L_hit',NOT_OBSERVED),
        policy_shape=spec.policy_shape, repeat_count=spec.ell-spec.u,
        occurrence_ranks=spec.occurrence_ranks,
        message_length=spec.message_length,
        benchmark_scope='REVOCATION_STATE_ONLY' if experiment_id == 'Exp6' else
            DEFAULT_SCOPES[experiment_id],
        known_leakage=('same_context_token_equality','AF_hit_count','J/I',
            'access_timing','revocation_behavior','stable_W') if experiment_id == 'Exp7' else (),
        requested_RL_size=extra.get('requested_RL_size',NOT_OBSERVED),
        n_reg=NOT_OBSERVED, request_rate=NOT_OBSERVED,
        acknowledged_revoked_count=extra.get('acknowledged_revoked_count',NOT_OBSERVED),
        historical_auth_valid=extra.get('historical_auth_valid',NOT_OBSERVED),
        revocation_ciphertext_component_count=0,
        public_revocation_update_key_count=0, tree_TK_count=0)
    breakdown = result['breakdown']
    primary_spans = result.get('primary_spans', {})
    encrypt_breakdown = result.get('encrypt_breakdown', {})
    transform_breakdown = result.get('transform_breakdown', {})
    metrics = dict(request_e2e_ns=result['request_e2e_ns'],
        encrypt_core_ns=_observed(encrypt_breakdown.get('encrypt_core_ns')),
        setup_ns=NOT_OBSERVED, keygen_ns=primary_spans.get('KeyGen',_last_span(scheme,'KeyGen')),
        encrypt_ns=primary_spans.get('Encrypt',_last_span(scheme,'Encrypt')),
        rev_ns=extra.get('rev_ns',NOT_OBSERVED),
        revstateupt_ns=extra.get('revstateupt_ns',NOT_OBSERVED),
        tee_authorize_ns=primary_spans.get('TEEAuthorize',_last_span(scheme,'TEEAuthorize')) if
            experiment_id != 'Exp6' else NOT_OBSERVED,
        transform_ns=primary_spans.get('Transform',_last_span(scheme,'Transform')) if
            experiment_id != 'Exp6' else NOT_OBSERVED,
        finaldec_ns=primary_spans.get('FinalDec',_last_span(scheme,'FinalDec')) if
            experiment_id != 'Exp6' else NOT_OBSERVED,
        attestation_preflight_ns=NOT_OBSERVED,
        keygen_crypto_ns=NOT_OBSERVED, credential_ns=NOT_OBSERVED,
        blob_provisioning_ns=NOT_OBSERVED, total_keygen_ns=_last_span(scheme,'KeyGen'),
        af_build_ns=_observed(encrypt_breakdown.get('af_build_ns')),
        af_query_ns=_observed(transform_breakdown.get('af_query_ns')),
        policy_token_ns=_observed(encrypt_breakdown.get('policy_token_ns')),
        user_token_ns=_observed(breakdown.get('tokenization_ns',NOT_OBSERVED))
            if experiment_id == 'Exp4' else NOT_OBSERVED,
        state_coordination_ns=_observed(breakdown.get('state_coordination_ns')),
        rpc_roundtrip_ns=_observed(breakdown.get('rpc_roundtrip_ns',NOT_OBSERVED)),
        state_only_insert_ns=extra.get('state_only_insert_ns',NOT_OBSERVED),
        state_only_lookup_ns=extra.get('state_only_lookup_ns',NOT_OBSERVED),
        state_only_delete_ns=extra.get('state_only_delete_ns',NOT_OBSERVED),
        authorized_subset_ns=_observed(transform_breakdown.get('authorized_subset_ns')),
        t_a_ns=_observed(transform_breakdown.get('t_a_ns')),
        g1_exp_count=NOT_OBSERVED, g2_exp_count=NOT_OBSERVED,
        gt_exp_count=NOT_OBSERVED, prf_count=NOT_OBSERVED,
        hash_to_group_count=NOT_OBSERVED, signature_sign_count=NOT_OBSERVED,
        signature_verify_count=NOT_OBSERVED,
        af_decoded_payload_count=_observed(transform_breakdown.get('af_decoded_payload_count')),
        seed_retry_count=_observed(encrypt_breakdown.get('seed_retry_count')),
        host_to_tee_bytes=_observed(breakdown.get('rpc_send_bytes',NOT_OBSERVED)),
        tee_to_host_bytes=_observed(breakdown.get('rpc_receive_bytes',NOT_OBSERVED)),
        request_state_bytes=NOT_OBSERVED, revset_logical_bytes=NOT_OBSERVED,
        state_only_revset_logical_bytes=extra.get(
            'state_only_revset_logical_bytes',NOT_OBSERVED),
        same_context_equal=extra.get('same_context_equal',NOT_OBSERVED),
        cross_context_equal_observed=extra.get('cross_context_equal_observed',NOT_OBSERVED),
        known_w_stable=extra.get('known_w_stable',NOT_OBSERVED),
        audit_status=extra.get('audit_status',NOT_OBSERVED),
        token_updated=extra.get('token_updated',NOT_OBSERVED),
        ct_updated=extra.get('ct_updated',NOT_OBSERVED),
        rk_updated=extra.get('rk_updated',NOT_OBSERVED),
        rejection_ns=result['request_e2e_ns'] if experiment_id == 'Exp6' else NOT_OBSERVED)
    policy_ns=metrics['policy_token_ns']
    user_ns=metrics['user_token_ns']
    metrics['policy_token_ops_per_s']=(spec.ell*1e9/policy_ns if
        type(policy_ns) is int and policy_ns>0 else NOT_OBSERVED)
    metrics['user_token_ops_per_s']=(spec.N*1e9/user_ns if
        type(user_ns) is int and user_ns>0 else NOT_OBSERVED)
    for name in ('host_pre_rpc_ns','rpc_send_ns','rpc_receive_ns','host_post_rpc_ns',
        'enclave_total_ns','credential_verify_ns','revset_lookup_ns',
        'tokenization_ns','rerandomization_ns','t0_pairing_ns','cap_sign_ns'):
        metrics[name] = _observed(breakdown.get(name,NOT_OBSERVED))
    if experiment_id == 'Exp3':
        metrics.update(canonical_storage_breakdown(result['ct'],auth,partial,
                                                   result['user'],scheme.crypto))
    else:
        metrics.update(dict(ct_wire_bytes=len(serialize_ciphertext(result['ct'],scheme.crypto)),
            auth_wire_bytes=NOT_OBSERVED, ctprime_wire_bytes=NOT_OBSERVED,
            publication_wire_bytes=NOT_OBSERVED))
    if experiment_id == 'Exp6':
        tee_pairings = NOT_OBSERVED
        csp_pairings = NOT_OBSERVED
        system_pairings = NOT_OBSERVED
        finaldec_pairings = NOT_OBSERVED
    else:
        tee_pairings = auth.tee_pairings
        csp_pairings = partial.csp_pairings
        system_pairings = tee_pairings+csp_pairings
        finaldec_pairings = 0
    counters = dict(tee_pairing_count=tee_pairings,
        csp_pairing_count=csp_pairings, system_pairing_count=system_pairings,
        finaldec_pairing_count=finaldec_pairings,
        candidate_row_count=len(partial.candidate_rows),
        reconstruction_row_count=len(partial.reconstruction_rows),
        occurrence_slot_count=len(partial.occurrence_slots),
        af_hit_count=len(partial.candidate_rows),
        host_to_tee_bytes=metrics['host_to_tee_bytes'],
        tee_to_host_bytes=metrics['tee_to_host_bytes'])
    metrics.update(counters)
    return dict(schema_version=SCHEMA_VERSION, run_id=artifacts.run_id,
        experiment_id=experiment_id, sample_id=uuid.uuid4().hex,
        backend=scheme.backend_id, measurement_scope=DEFAULT_SCOPES[experiment_id],
        workload_id=spec.workload_id, workload_seed=spec.workload_seed,
        warmup_or_measured='MEASURED',
        sample_status=('FAILED' if not result['correct'] else
            ('OK' if result['actual_outcome']=='SUCCESS' else 'EXPECTED_REJECT')),
        error_class=result['error_class'] if result['correct'] else 'CorrectnessRegression',
        expected_outcome=result['expected_outcome'],
        actual_outcome=result['actual_outcome'], correctness_verified=result['correct'],
        variables=variables, metrics=metrics, counters=counters,
        trust_metadata=trust,
        implementation_module='core.myabe08.public.PublicMyABE08',
        code_manifest_sha256=code_hash, service_state='WARM')


def _failure_row(scheme, spec, experiment_id, artifacts, trust, code_hash,
                 error, attempt_ns):
    """Preserve a failed measured attempt without serializing the exception."""
    status = 'TIMEOUT' if isinstance(error,TimeoutError) else 'FAILED'
    expected = 'REVOKED' if experiment_id == 'Exp6' else spec.expected_outcome
    metrics = {name:NOT_OBSERVED for name in METRIC_UNITS}
    metrics['sample_attempt_ns'] = attempt_ns
    return dict(schema_version=SCHEMA_VERSION, run_id=artifacts.run_id,
        experiment_id=experiment_id, sample_id=uuid.uuid4().hex,
        backend=scheme.backend_id, measurement_scope=DEFAULT_SCOPES[experiment_id],
        workload_id=spec.workload_id, workload_seed=spec.workload_seed,
        warmup_or_measured='MEASURED', sample_status=status,
        error_class=type(error).__name__, expected_outcome=expected,
        actual_outcome=status, correctness_verified=False,
        variables=dict(ell=spec.ell,d=spec.d,u=spec.u,N=spec.N,cmax=spec.cmax,
                       policy_shape=spec.policy_shape,message_length=spec.message_length,
                       requested_J=spec.requested.get('J',NOT_OBSERVED),
                       requested_tI=spec.requested.get('tI',NOT_OBSERVED),
                       actual_J=NOT_OBSERVED,actual_tI=NOT_OBSERVED),
        metrics=metrics,counters={},trust_metadata=trust,
        implementation_module='core.myabe08.public.PublicMyABE08',
        code_manifest_sha256=code_hash,service_state='WARM')


def run_smoke(experiment_ids, backend, *, root=None, seeds=(17,), warmups=0,
              repetitions=1, max_samples=32, allow_large_run=False,
              build_dir=None, client=None, run_id=None):
    plan = finalize_plan_hash(build_plan(tuple(experiment_ids), backend,
        seeds=tuple(seeds), warmups=warmups, repetitions=repetitions,
        max_samples=max_samples, allow_large_run=allow_large_run))
    if all(REGISTRY[name].status == BLOCKED for name in experiment_ids):
        return dict(status='BLOCKED_COMMON_BACKEND', experiments=list(experiment_ids),
                    run_path=None)
    specification = spec_manifest()
    code = code_manifest()
    with tempfile.TemporaryDirectory(prefix='myabe08-exp-state-') as temporary:
        scheme = _new_scheme(backend,Path(temporary)/'kgc',build_dir,client)
        setup_started = time.perf_counter_ns()
        scheme.Setup(c_max=3,validity=Validity(100,2000))
        setup_with_preflight_ns = time.perf_counter_ns()-setup_started
        environment = environment_manifest()
        trust = _trust_metadata(scheme,environment)
        cohort = ':'.join((backend,trust['ExperimentTrustMode'],trust['QVLResult']))
        artifacts = RunArtifacts(plan,environment,code,specification,git_provenance(),
            root=root,run_id=run_id,trust_cohort=cohort,trust_metadata=trust,
            setup_with_preflight_ns=setup_with_preflight_ns)
        try:
            for entry in plan['entries']:
                experiment_id = entry['experiment_id']
                if entry['status'] == 'BLOCKED_COMMON_BACKEND':
                    continue
                for family in entry['families']:
                    for seed in plan['seeds']:
                        requested = {}
                        if experiment_id == 'Exp5':
                            requested = {'J':1 if family=='W-SINGLE' else 3,
                                         'tI':1 if family=='W-SINGLE' else 2}
                        spec = generate_workload(family,seed,requested=requested)
                        try:
                            precheck = _case(scheme,spec,experiment_id)
                        except Exception as exc:
                            artifacts.record_precheck(dict(experiment_id=experiment_id,
                                workload_id=spec.workload_id,
                                workload_spec_sha256=spec.workload_spec_sha256,
                                expected_outcome='REVOKED' if experiment_id=='Exp6'
                                    else spec.expected_outcome,
                                actual_outcome='ERROR',passed=False,
                                error_class=type(exc).__name__))
                            artifacts.finalize('FAILED')
                            return dict(status='CORRECTNESS_PRECHECK_FAILED',
                                error_class=type(exc).__name__,
                                run_path=str(artifacts.path))
                        artifacts.record_precheck(dict(experiment_id=experiment_id,
                            workload_id=spec.workload_id, workload_spec_sha256=spec.workload_spec_sha256,
                            expected_outcome=precheck['expected_outcome'],
                            actual_outcome=precheck['actual_outcome'],
                            passed=precheck['correct']))
                        if not precheck['correct']:
                            artifacts.finalize('FAILED')
                            return dict(status='CORRECTNESS_PRECHECK_FAILED',
                                run_path=str(artifacts.path))
                        for _ in range(plan['warmups']):
                            try:
                                warm = _case(scheme,spec,experiment_id)
                            except Exception as exc:
                                artifacts.record_precheck(dict(experiment_id=experiment_id,
                                    workload_id=spec.workload_id,
                                    phase='WARMUP',passed=False,
                                    error_class=type(exc).__name__))
                                artifacts.finalize('FAILED')
                                return dict(status='CORRECTNESS_PRECHECK_FAILED',
                                    error_class=type(exc).__name__,
                                    run_path=str(artifacts.path))
                            if not warm['correct']:
                                artifacts.finalize('FAILED')
                                return dict(status='CORRECTNESS_PRECHECK_FAILED',
                                    run_path=str(artifacts.path))
                        for _ in range(plan['repetitions']):
                            attempt_started = time.perf_counter_ns()
                            try:
                                result = _case(scheme,spec,experiment_id)
                            except Exception as exc:
                                row = _failure_row(scheme,spec,experiment_id,
                                    artifacts,trust,code['tree_sha256'],exc,
                                    time.perf_counter_ns()-attempt_started)
                                artifacts.append_row(row)
                                artifacts.finalize('FAILED')
                                return dict(status='CORRECTNESS_REGRESSION',
                                    error_class=type(exc).__name__,
                                    run_path=str(artifacts.path))
                            row = _row(scheme,spec,experiment_id,result,artifacts,
                                       trust,code['tree_sha256'])
                            artifacts.append_row(row)
                            if not result['correct']:
                                artifacts.finalize('FAILED')
                                return dict(status='CORRECTNESS_REGRESSION',
                                    run_path=str(artifacts.path))
            path = artifacts.finalize('COMPLETE')
            validation = validate_run(path)
            return dict(status='COMPLETE',run_path=str(path),validation=validation,
                        measured_rows=artifacts.raw_count)
        except KeyboardInterrupt:
            if artifacts.manifest['status'] == 'RUNNING':
                artifacts.finalize('INTERRUPTED')
            raise
        except Exception:
            if artifacts.manifest['status'] == 'RUNNING':
                artifacts.finalize('FAILED')
            raise
