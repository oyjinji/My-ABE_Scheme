"""Phase 5D-S paired structural workload acquisition.

The CORE arm times existing algebra stage hooks, excluding the AF query that
the unchanged transform implementation executes to obtain its witness. The
FULL arms use PublicMyABE08. No cryptographic RNG is seeded by the schedule.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import random
import secrets
import subprocess
import sys
import time
import uuid
import tempfile

from ..af import ProtectedPayloadAF, compute_ctx_af
from ..algebra import (AlgebraOperationCounts, derive_ephemeral_algebra,
                       encrypt_algebra_core, finaldec_algebra_core,
                       keygen_algebra_core, setup_algebra_core,
                       transform_algebra_core)
from ..crypto import BLS12381Backend, compute_ctx_priv
from ..encoding import encode_attribute
from ..errors import MyABE08Error, Unauthorized
from ..experiments import GENERATOR_VERSION
from ..experiments.phase5c_collect import _service
from ..experiments.provenance import (REPO, code_manifest,
                                      environment_manifest, file_sha256,
                                      spec_manifest, git_provenance)
from ..experiments.runner import TestClock
from ..experiments.workloads import (WorkloadSpec, canonical_json,
                                     generate_benchmark_workload,
                                     generate_workload, occurrence_ranks,
                                     sha256_json)
from ..lsss import LSSSMatrix, prepare_policy_rows
from ..profile import EMULATED_TEE_PROFILE, SGX_DEBUG_GRAMINE_V1
from ..public import (EMULATED_TEST_MODE, PublicMyABE08,
                      serialize_authorization, serialize_ciphertext,
                      serialize_partial)
from ..publication import make_af_header
from ..experiments.storage import canonical_storage_breakdown
from ..real_tee.attested_session import FEASIBILITY_MODE
from ..real_tee.identity_policy import SgxIdentityPolicy
from ..signing import new_private_key, public_key_bytes
from ..types import PolicyContext, Validity


ROOT = REPO / 'artifacts/myabe08/baselines/phase5d_s'
BUILD = Path(os.environ.get('MYABE08_SGX_DEBUG_BUILD_DIR',
                            '/tmp/myabe08-phase5ds-build'))
R_RUN = REPO / 'artifacts/myabe08/baselines/phase5d_r'
R_ABLATION = R_RUN / 'ablation/20260927T112557Z-389ead9f765c'
R_CORE = R_RUN / 'core/20260927T154528Z-fd1052f3416d'
R_ABLATION_ANALYSIS = R_RUN / 'analysis/ablation/20260927T112557Z-389ead9f765c'
R_CORE_ANALYSIS = R_RUN / 'analysis/core/20260927T154528Z-fd1052f3416d'
PROFILES = ('CORE', 'FULL_EMULATED', 'FULL_REAL_SGX')
REAL = SGX_DEBUG_GRAMINE_V1
EMU = EMULATED_TEE_PROFILE


def _and_spec(ell: int, seed: int) -> WorkloadSpec:
    """AND policy shape only; no ABE cryptographic formula is implemented."""
    if ell < 2:
        raise ValueError('AND needs at least two rows')
    rows = []
    for i in range(ell):
        row = [0] * ell
        if i == 0:
            row[0], row[1] = 1, 1
        elif i == ell - 1:
            row[i] = -1
        else:
            row[i], row[i + 1] = -1, 1
        rows.append(tuple(row))
    matrix = tuple(rows)
    codes = tuple(range(1, ell + 1))
    ranks = occurrence_ranks(codes)
    structural = dict(generator_version=GENERATOR_VERSION,
        family='B-AND-PAIRED', seed=seed, matrix=matrix,
        row_codes=codes, user_codes=codes, cmax=1,
        message_length=32, expected_outcome='SUCCESS',
        requested={'ell': ell}, occurrence_ranks=ranks)
    digest = sha256_json(structural)
    return WorkloadSpec('WL-' + digest[:16], 'B-AND-PAIRED', seed,
        'AND', matrix, codes, codes, 1, 32, 'SUCCESS',
        {'ell': ell}, ranks, digest)


def design():
    """Seven balanced configurations; includes the requested 10/40/80 points."""
    return (
        ('W1-AND-10', _and_spec(10, 5101)),
        ('W2-OR-20', generate_benchmark_workload(shape='OR', ell=20,
            cmax=1, N=1, hit_codes=1, seed=5102)),
        ('W3-2OF3', generate_workload('W-2OF3', 5103, cmax=1)),
        ('W4-3OF5', generate_workload('W-3OF5', 5104, cmax=1)),
        ('W5-ABACA', generate_workload('W-REPEAT-ABACA', 5105, cmax=3)),
        ('W6-LARGE-REPEATED-80', generate_benchmark_workload(
            shape='repeated', ell=80, cmax=4, N=20, hit_codes=3,
            threshold=3, seed=5106)),
        ('W7-AND-40', _and_spec(40, 5107)),
    )


def plan(*, repetitions=20, warmups=5):
    if repetitions not in (20, 30) or warmups != 5:
        raise ValueError('formal paired sampling requires 20/30 samples and 5 warmups')
    blocks = (7, 7, 6) if repetitions == 20 else (10, 10, 10)
    configs = []
    for name, spec in design():
        configs.append(dict(name=name, workload=spec.artifact(),
            configuration_id='CFG-' + spec.workload_spec_sha256[:20],
            sys_id_hex=_sys_id(spec).hex(),
            policy_context_id_hex=_context_id(spec).hex()))
    value = dict(phase='PHASE_5D_S', protocol='PAIRED_CORE_FULL_WORKLOAD_V1',
        profiles=PROFILES, configurations=configs, warmups=warmups,
        repetitions=repetitions, blocks=blocks,
        reduced_real_sgx_repetitions=repetitions == 20,
        reduction_reason=('Seven structural workloads include 80-row real SGX '
            'public E2E; 20 samples per profile retain three interleaved blocks'
            if repetitions == 20 else 'NOT_APPLICABLE'),
        profile_order_seed=20260928,
        crypto_randomness='OS_CSPRNG_UNSEEDED_INDEPENDENT_PER_SAMPLE',
        expected_measured_rows=len(configs)*len(PROFILES)*repetitions)
    value['plan_sha256'] = sha256_json(value)
    return value


def verify_5dr() -> dict:
    script = REPO / 'scripts/phase5dr_verify_frozen.py'
    results = {}
    for name, run, analysis in (
            ('ablation', R_ABLATION, R_ABLATION_ANALYSIS),
            ('core', R_CORE, R_CORE_ANALYSIS)):
        result = subprocess.run((sys.executable, str(script), str(run),
            '--analysis', str(analysis)), cwd=REPO,
            capture_output=True, text=True, check=True)
        parsed = json.loads(result.stdout)
        if parsed['status'] != 'PASS' or parsed['outliers_removed'] != 0:
            raise ValueError('5D-R frozen artifact validation failed')
        results[name] = parsed
    old = json.loads((R_CORE/'PHASE5D_R_CODE_MANIFEST.json').read_text())
    expected = {item['path']: item['sha256'] for item in old['files']}
    for name in ('algebra.py', 'crypto.py', 'lsss.py', 'af.py'):
        actual = file_sha256(REPO/'src/core/myabe08'/name)
        if actual != expected[name]:
            raise RuntimeError('CORE_CODE_DRIFT: ' + name)
    return results


def _sys_id(spec: WorkloadSpec) -> bytes:
    return b'MYABE08-5DS-' + bytes.fromhex(spec.workload_spec_sha256[:32])


def _context_id(spec: WorkloadSpec) -> bytes:
    return hashlib.sha256(b'PHASE5DS-CONTEXT-' +
                          spec.workload_spec_sha256.encode()).digest()


def _context(sys_id: bytes, spec: WorkloadSpec) -> PolicyContext:
    context_id = _context_id(spec)
    return PolicyContext(sys_id, context_id, 1,
        compute_ctx_priv(sys_id, context_id, 1))


def _core_tokens(spec: WorkloadSpec):
    codes = set(spec.row_codes) | set(spec.user_codes)
    return {code: hashlib.sha256(b'PHASE5DS-CORE-LABEL-' +
        encode_attribute('synthetic', 'attribute',
                         spec.attribute(code).value)).digest()
        for code in codes}


def _new_core(spec: WorkloadSpec, sys_id: bytes):
    backend = BLS12381Backend(sys_id)
    matrix = LSSSMatrix(spec.matrix, backend.scalar_order, spec.ell, spec.d)
    tokens = _core_tokens(spec)
    policy_tokens = tuple(tokens[code] for code in spec.row_codes)
    user_tokens = tuple(sorted(tokens[code] for code in spec.user_codes))
    start = time.perf_counter_ns()
    pp, msk = setup_algebra_core(backend, spec.cmax)
    setup_ns = time.perf_counter_ns() - start
    start = time.perf_counter_ns()
    base, rk = keygen_algebra_core(pp, msk, backend)
    keygen_ns = time.perf_counter_ns() - start
    entries, _ = prepare_policy_rows(matrix, policy_tokens, spec.cmax)
    header = make_af_header(matrix, policy_tokens,
                            _context(sys_id, spec), spec.cmax, backend)
    ctx_af = compute_ctx_af(header)
    index = ProtectedPayloadAF().build(entries, header=header, ctx_af=ctx_af)
    return dict(backend=backend, matrix=matrix, tokens=policy_tokens,
        user_tokens=user_tokens, pp=pp, base=base, rk=rk, index=index,
        header=header, ctx_af=ctx_af, setup_ns=setup_ns,
        keygen_ns=keygen_ns, sys_id=sys_id)


def _core_sample(state, spec):
    backend = state['backend']
    started = time.perf_counter_ns()
    ct = encrypt_algebra_core(state['pp'], state['matrix'],
                              state['tokens'], backend)
    encrypt_ns = time.perf_counter_ns() - started
    derive_stages = {}
    bundle = derive_ephemeral_algebra(state['pp'], state['base'],
        state['user_tokens'], ct.c, backend, stage_timings_ns=derive_stages)
    transform_stages = {}
    counts = AlgebraOperationCounts()
    transformed = transform_algebra_core(state['pp'], ct, bundle,
        state['index'], state['header'], state['ctx_af'], backend,
        counts=counts, stage_timings_ns=transform_stages)
    started = time.perf_counter_ns()
    _, recovered = finaldec_algebra_core(bundle.t0_q, transformed.t_a,
                                         state['rk'], backend)
    finaldec_ns = time.perf_counter_ns() - started
    if recovered != ct.e or counts.pairing_terms != 1 + len(transformed.occurrence_slots):
        raise AssertionError('CORE correctness or pairing invariant failed')
    required = ('rerandomization_ns', 't0_pairing_ns')
    if any(type(derive_stages.get(key)) is not int for key in required):
        raise AssertionError('CORE T0 stage instrumentation missing')
    required = ('af_query_ns', 'authorized_subset_ns', 't_a_ns')
    if any(type(transform_stages.get(key)) is not int for key in required):
        raise AssertionError('CORE transform stage instrumentation missing')
    core_access_ns = sum((derive_stages['rerandomization_ns'],
        derive_stages['t0_pairing_ns'],
        transform_stages['authorized_subset_ns'],
        transform_stages['t_a_ns'], finaldec_ns))
    group_bytes = (sum(len(x.encoded) for x in ct.c_i) +
                   sum(len(x.encoded) for x in ct.d_j) + len(ct.c.encoded))
    return dict(encrypt_ns=encrypt_ns, access_ns=core_access_ns,
        core_access_metric='EXCLUSIVE_ABE_STAGE_SUM_NOT_CONTIGUOUS_WALLCLOCK',
        core_af_query_excluded_ns=transform_stages['af_query_ns'],
        rerandomization_ns=derive_stages['rerandomization_ns'],
        t0_pairing_ns=derive_stages['t0_pairing_ns'],
        authorized_subset_ns=transform_stages['authorized_subset_ns'],
        t_a_ns=transform_stages['t_a_ns'], finaldec_crypto_ns=finaldec_ns,
        core_group_bytes=group_bytes, d_count=len(ct.d_j),
        candidate_count=len(transformed.candidate_rows),
        reconstruction_count=len(transformed.reconstruction_rows),
        actual_tI=len(transformed.occurrence_slots),
        tee_pairings=1, csp_pairings=counts.pairing_terms,
        finaldec_pairings=0, correctness='PASS')


def _new_full(spec: WorkloadSpec, state_path: Path, backend: str, client=None):
    """One public facade and one TEST state per configuration/profile."""
    sys_id = _sys_id(spec)
    if backend == REAL:
        audit = json.loads((BUILD/'build_audit.json').read_text())
        if audit.get('debug') is not True or audit.get('remote_attestation') != 'dcap':
            raise RuntimeError('real SGX DEBUG/DCAP build audit required')
        policy = SgxIdentityPolicy('phase5ds-exact', REAL,
            mrenclave=bytes.fromhex(audit['mrenclave']), allow_debug=True)
        scheme = PublicMyABE08(sys_id=sys_id,namespace='synthetic',backend=REAL,
            experiment_trust_mode=FEASIBILITY_MODE,identity_policy=policy,
            state_path=state_path,clock=TestClock(),client=client,
            test_tee_bootstrap=True)
    else:
        scheme = PublicMyABE08(sys_id=sys_id,namespace='synthetic',backend=EMU,
            experiment_trust_mode=EMULATED_TEST_MODE,state_path=state_path,
            clock=TestClock())
    setup = scheme.Setup(c_max=spec.cmax, validity=Validity(100, 2000))
    if backend == REAL:
        required = dict(TEEProfile=REAL, ExperimentTrustMode=FEASIBILITY_MODE,
            QVLApiReturn=0, CollateralExpirationStatus=0,
            QVLResult='SGX_QL_QV_RESULT_OUT_OF_DATE',
            StrictRA2='BLOCKED_BY_TCB_POLICY', EnclaveDebug=True)
        if any(setup.metadata.get(key) != value for key, value in required.items()):
            raise RuntimeError('real SGX trust cohort changed; fail closed')
    holder = new_private_key()
    user = scheme.KeyGen(uid='SYNTHETIC-' + uuid.uuid4().hex,
        attributes=spec.user_attributes(),
        auth_public_key=public_key_bytes(holder),
        validity=Validity(100, 2000))
    return dict(scheme=scheme, user=user, holder=holder,
        trust={key: setup.metadata.get(key) for key in (
            'TEEProfile', 'ExperimentTrustMode', 'QVLApiReturn',
            'CollateralExpirationStatus', 'QVLResult', 'StrictRA2',
            'EnclaveDebug', 'CurrentHeadMode')})


def _full_sample(state, spec):
    scheme, user, holder = state['scheme'], state['user'], state['holder']
    message = secrets.token_bytes(spec.message_length)
    ct = scheme.Encrypt(message=message, policy=spec.policy(),
        context=_context(scheme.sys_id, spec),
        data_id=secrets.token_bytes(16))
    started = time.perf_counter_ns()
    auth = scheme.TEEAuthorize(user=user, ciphertext=ct,
        auth_private_key=holder, expiry=1500)
    partial = scheme.Transform(ciphertext=ct, public_auth=auth)
    recovered = scheme.FinalDec(partial=partial,
        recovery_key=user.recovery_key)
    request_e2e_ns = time.perf_counter_ns() - started
    if recovered != message or auth.tee_pairings != 1 or (
            partial.csp_pairings != 1 + len(partial.occurrence_slots)):
        raise AssertionError('public correctness or pairing invariant failed')
    serialization_started = time.perf_counter_ns()
    storage = canonical_storage_breakdown(ct, auth, partial, user,
        scheme.crypto)
    serialization_ns = time.perf_counter_ns() - serialization_started
    encrypt = dict(scheme.encrypt_breakdown_ns[-1])
    authorize = dict(scheme.authorize_breakdown_ns[-1])
    transform = dict(scheme.transform_breakdown_ns[-1])
    finaldec = dict(scheme.finaldec_breakdown_ns[-1])
    for stages, fields in ((encrypt, ('policy_token_ns', 'af_build_ns',
        'encrypt_core_ns', 'dem_encrypt_ns', 'publication_sign_ns')),
        (transform, ('af_query_ns', 'authorized_subset_ns', 't_a_ns')),
        (finaldec, ('finaldec_crypto_ns', 'dem_decrypt_ns'))):
        if any(type(stages.get(field)) is not int for field in fields):
            raise AssertionError('required public stage timing missing')
    if scheme.backend_id == REAL and any(type(authorize.get(field)) is not int
            for field in ('rpc_send_ns', 'rpc_receive_ns',
                'enclave_total_ns', 'credential_verify_ns',
                'revset_lookup_ns', 'tokenization_ns',
                'rerandomization_ns', 't0_pairing_ns', 'cap_sign_ns')):
        raise AssertionError('real SGX enclave/transport stage timing missing')
    result = dict(encrypt_ns=scheme.spans_ns['Encrypt'][-1],
        request_e2e_ns=request_e2e_ns,
        teeauthorize_ns=scheme.spans_ns['TEEAuthorize'][-1],
        transform_ns=scheme.spans_ns['Transform'][-1],
        finaldec_ns=scheme.spans_ns['FinalDec'][-1],
        serialization_ns=serialization_ns,
        actual_tI=len(partial.occurrence_slots),
        candidate_count=len(partial.candidate_rows),
        reconstruction_count=len(partial.reconstruction_rows),
        tee_pairings=auth.tee_pairings,
        csp_pairings=partial.csp_pairings,
        finaldec_pairings=0, correctness='PASS')
    result.update(storage)
    result.update({'encrypt_' + key: value for key, value in encrypt.items()})
    result.update({'authorize_' + key: value for key, value in authorize.items()})
    result.update({'transform_' + key: value for key, value in transform.items()})
    result.update({'finaldec_' + key: value for key, value in finaldec.items()})
    return result


def _write_json(path: Path, value):
    with path.open('xb') as output:
        output.write(canonical_json(value) + b'\n')


def _utc():
    return datetime.now(timezone.utc).isoformat()


def _order(config_index: int, block: int, sample: int, frozen: dict):
    values = list(PROFILES)
    random.Random(frozen['profile_order_seed'] +
                  config_index * 100_000 + block * 1_000 + sample).shuffle(values)
    return values


def acquire(*, output_root=ROOT, repetitions=20, smoke=False):
    """Acquire append-only paired rows; a partial run is never COMPLETE."""
    if smoke:
        raise ValueError('smoke acquisition is test-only; use smoke_probe()')
    old = verify_5dr()
    frozen = plan(repetitions=repetitions)
    environment = environment_manifest(build_dir=BUILD)
    code = code_manifest()
    specification = spec_manifest()
    run_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:12]
    output = Path(output_root) / run_id
    output.mkdir(parents=True, exist_ok=False)
    _write_json(output/'PHASE5D_S_PLAN.json', frozen)
    _write_json(output/'CODE_MANIFEST.json', code)
    _write_json(output/'ENVIRONMENT.json', environment)
    _write_json(output/'SOURCE_MANIFEST.json', dict(specification=specification,
        phase5dr=old, phase5dr_ablation_raw_sha256=file_sha256(R_ABLATION/'raw.jsonl'),
        phase5dr_core_raw_sha256=file_sha256(R_CORE/'raw.jsonl')))
    _write_json(output/'GIT_PROVENANCE.json', git_provenance())
    manifest = dict(phase='PHASE_5D_S', status='RUNNING', started_utc=_utc(),
        run_id=run_id, plan_sha256=frozen['plan_sha256'],
        code_tree_sha256=code['tree_sha256'], rows=0)
    _write_json(output/'MANIFEST.json', manifest)
    rows = 0
    try:
        with (output/'raw.jsonl').open('xb') as stream:
            for config_index, (name, spec) in enumerate(design()):
                with tempfile.TemporaryDirectory(prefix='myabe08-5ds-state-') as tmp:
                    core = _new_core(spec, _sys_id(spec))
                    emulated = _new_full(spec, Path(tmp)/'emulated', EMU)
                    # A fresh isolated Gramine process is necessary: TEST
                    # bootstrap is one-time per enclave instance.
                    with _service(BUILD) as (client, log, service_tmp):
                        real = _new_full(spec, Path(tmp)/'real', REAL, client=client)
                        states = dict(CORE=core, FULL_EMULATED=emulated,
                                      FULL_REAL_SGX=real)
                        for profile in PROFILES:
                            for _ in range(frozen['warmups']):
                                (_core_sample(core, spec) if profile == 'CORE' else
                                 _full_sample(states[profile], spec))
                        for block, count in enumerate(frozen['blocks']):
                            for sample in range(count):
                                for profile in _order(config_index, block, sample, frozen):
                                    metrics = (_core_sample(core, spec) if profile == 'CORE'
                                        else _full_sample(states[profile], spec))
                                    row = dict(configuration_id=frozen['configurations'][config_index]['configuration_id'],
                                        workload_id=name, workload_spec_sha256=spec.workload_spec_sha256,
                                        profile=profile, block=block, sample=sample,
                                        structural=dict(ell=spec.ell, d=spec.d,
                                            cmax=spec.cmax, policy_shape=spec.policy_shape,
                                            message_length=spec.message_length,
                                            sys_id_hex=_sys_id(spec).hex(),
                                            policy_context_id_hex=_context_id(spec).hex(),
                                            row_codes=spec.row_codes, user_codes=spec.user_codes,
                                            occurrence_ranks=spec.occurrence_ranks),
                                        trust=(states[profile]['trust'] if profile != 'CORE'
                                            else dict(TEEProfile='NO_TEE_ALGEBRA_CORE_ONLY')),
                                        metrics=metrics, status='PASS')
                                    stream.write(canonical_json(row)+b'\n')
                                    stream.flush(); os.fsync(stream.fileno())
                                    rows += 1
                        client.stop_test_service()
                        if 'MYABE08_TEST_ERROR' in log.read_text(errors='replace'):
                            raise RuntimeError('SGX service reported TEST error')
                print(name, 'completed', flush=True)
        manifest.update(status='COMPLETE', ended_utc=_utc(), rows=rows,
            raw_sha256=file_sha256(output/'raw.jsonl'))
        if rows != frozen['expected_measured_rows']:
            raise RuntimeError('paired sample count mismatch')
        _write_json(output/'COMPLETION.json', manifest)
        print(output)
        return output
    except BaseException as exc:
        _write_json(output/'ABORTED.json', dict(status='ABORTED', rows=rows,
            error_class=type(exc).__name__, ended_utc=_utc()))
        raise


def smoke_probe(*, real=False):
    """Correctness probe excluded from formal data, limited to one small policy."""
    _, spec = design()[2]
    with tempfile.TemporaryDirectory(prefix='myabe08-5ds-smoke-') as tmp:
        core = _core_sample(_new_core(spec, _sys_id(spec)), spec)
        emu = _full_sample(_new_full(spec, Path(tmp)/'emu', EMU), spec)
        result = dict(core=core['correctness'], emulated=emu['correctness'])
        if real:
            with _service(BUILD) as (client, _, _):
                sgx = _new_full(spec, Path(tmp)/'sgx', REAL, client=client)
                result['real_sgx'] = _full_sample(sgx, spec)['correctness']
                result['trust'] = sgx['trust']
                client.stop_test_service()
        return result


def unauthorized_probe(*, real=False):
    """Active outsider must reach authorization then fail at policy transform."""
    _, spec = design()[2]
    core = _new_core(spec, _sys_id(spec))
    backend = core['backend']
    ct = encrypt_algebra_core(core['pp'], core['matrix'], core['tokens'], backend)
    stranger = hashlib.sha256(b'MYABE08-5DS-OUTSIDER').digest()
    bundle = derive_ephemeral_algebra(core['pp'], core['base'],
                                      (stranger,), ct.c, backend)
    try:
        transform_algebra_core(core['pp'], ct, bundle, core['index'],
            core['header'], core['ctx_af'], backend)
    except Unauthorized:
        result = dict(CORE='UNAUTHORIZED')
    else:
        raise AssertionError('CORE outsider authorized')

    def check(state):
        scheme = state['scheme']
        holder = new_private_key()
        outsider = scheme.KeyGen(uid='SYNTHETIC-OUTSIDER-' + uuid.uuid4().hex,
            attributes=(spec.attribute(9999),),
            auth_public_key=public_key_bytes(holder),
            validity=Validity(100, 2000))
        ciphertext = scheme.Encrypt(message=secrets.token_bytes(spec.message_length),
            policy=spec.policy(), context=_context(scheme.sys_id, spec),
            data_id=secrets.token_bytes(16))
        authorized = scheme.TEEAuthorize(user=outsider, ciphertext=ciphertext,
            auth_private_key=holder, expiry=1500)
        if authorized.tee_pairings != 1:
            raise AssertionError('active outsider T0 pairing absent')
        try:
            scheme.Transform(ciphertext=ciphertext, public_auth=authorized)
        except Unauthorized:
            return 'UNAUTHORIZED'
        raise AssertionError('Full outsider authorized')

    with tempfile.TemporaryDirectory(prefix='myabe08-5ds-unau-') as tmp:
        result['FULL_EMULATED'] = check(_new_full(spec, Path(tmp)/'emu', EMU))
        if real:
            with _service(BUILD) as (client, _, _):
                result['FULL_REAL_SGX'] = check(_new_full(spec,
                    Path(tmp)/'sgx', REAL, client=client))
                client.stop_test_service()
    return result


def validate(run: Path):
    frozen = json.loads((run/'PHASE5D_S_PLAN.json').read_text())
    complete = json.loads((run/'COMPLETION.json').read_text())
    source = json.loads((run/'SOURCE_MANIFEST.json').read_text())
    saved_code = json.loads((run/'CODE_MANIFEST.json').read_text())
    if canonical_json(frozen) != canonical_json(plan(repetitions=frozen['repetitions'])) or (
            complete['status'] != 'COMPLETE' or
            complete['raw_sha256'] != file_sha256(run/'raw.jsonl') or
            complete['code_tree_sha256'] != saved_code['tree_sha256'] or
            source['specification'] != spec_manifest() or
            source['phase5dr_ablation_raw_sha256'] != file_sha256(R_ABLATION/'raw.jsonl') or
            source['phase5dr_core_raw_sha256'] != file_sha256(R_CORE/'raw.jsonl')):
        raise ValueError('paired plan/manifest/hash mismatch')
    rows = [json.loads(line) for line in (run/'raw.jsonl').read_text().splitlines()]
    expected = set()
    expected_order = []
    for index, config in enumerate(frozen['configurations']):
        for block, count in enumerate(frozen['blocks']):
            for sample in range(count):
                expected_order.extend((config['configuration_id'], profile, block, sample)
                    for profile in _order(index, block, sample, frozen))
                expected.update((config['configuration_id'], profile, block, sample)
                    for profile in PROFILES)
    actual = [(r['configuration_id'], r['profile'], r['block'], r['sample'])
              for r in rows]
    if len(rows) != complete['rows'] or len(rows) != len(expected) or (
            len(set(actual)) != len(actual) or set(actual) != expected or
            actual != expected_order):
        raise ValueError('paired rows missing/duplicated')
    config_by_id = {c['configuration_id']: c for c in frozen['configurations']}
    for row in rows:
        artifact = config_by_id[row['configuration_id']]['workload']
        if row['workload_spec_sha256'] != artifact['workload_spec_sha256'] or (
                row['structural']['ell'] != artifact['ell'] or
                row['structural']['d'] != artifact['d'] or
                row['structural']['cmax'] != artifact['cmax'] or
                row['structural']['sys_id_hex'] !=
                    config_by_id[row['configuration_id']]['sys_id_hex'] or
                row['structural']['policy_context_id_hex'] !=
                    config_by_id[row['configuration_id']]['policy_context_id_hex'] or
                row['structural']['row_codes'] != artifact['row_codes'] or
                row['structural']['user_codes'] != artifact['user_codes'] or
                row['structural']['occurrence_ranks'] != artifact['occurrence_ranks'] or
                row['status'] != 'PASS' or row['metrics']['correctness'] != 'PASS'):
            raise ValueError('paired structure/correctness mismatch')
        if row['profile'] == 'FULL_REAL_SGX':
            trust = row['trust']
            if (trust.get('QVLResult') != 'SGX_QL_QV_RESULT_OUT_OF_DATE' or
                trust.get('StrictRA2') != 'BLOCKED_BY_TCB_POLICY' or
                trust.get('ExperimentTrustMode') != FEASIBILITY_MODE):
                raise ValueError('SGX trust claim mismatch')
        for key, value in row['metrics'].items():
            if key.endswith('_ns') and value is not None and (
                    type(value) is not int or value < 0):
                raise ValueError('invalid timing: '+key)
    return dict(status='PASS', rows=len(rows), raw_sha256=complete['raw_sha256'],
        outliers_removed=0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--plan-only', action='store_true')
    action.add_argument('--smoke', action='store_true')
    action.add_argument('--real-smoke', action='store_true')
    action.add_argument('--unauthorized-probe', action='store_true')
    action.add_argument('--run', action='store_true')
    action.add_argument('--validate', type=Path)
    parser.add_argument('--output-root', type=Path, default=ROOT)
    args = parser.parse_args()
    if args.plan_only:
        print(json.dumps(plan(), indent=2, sort_keys=True))
    elif args.smoke or args.real_smoke:
        print(json.dumps(smoke_probe(real=args.real_smoke), sort_keys=True))
    elif args.unauthorized_probe:
        print(json.dumps(unauthorized_probe(real=True), sort_keys=True))
    elif args.run:
        acquire(output_root=args.output_root)
    else:
        print(json.dumps(validate(args.validate), sort_keys=True))


if __name__ == '__main__':
    main()
