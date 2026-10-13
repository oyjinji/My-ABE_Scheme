"""Public eight-algorithm integration on real QVL-checked SGX DEBUG TEST mode."""
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

import pytest

if os.environ.get('MYABE08_RUN_SGX_PUBLIC') != '1':
    pytest.skip('set MYABE08_RUN_SGX_PUBLIC=1 for real public SGX path',
                allow_module_level=True)

from core.myabe08.crypto import compute_ctx_priv
from core.myabe08.encoding import decode, encode
from core.myabe08.errors import AuthenticationError, ContractError, Unauthorized
from core.myabe08.profile import SGX_DEBUG_GRAMINE_V1
from core.myabe08.public import (PublicMyABE08, parse_authorization,
    parse_ciphertext, parse_partial, serialize_authorization,
    serialize_ciphertext, serialize_partial)
from core.myabe08.real_tee.attested_session import FEASIBILITY_MODE, STRICT_MODE
from core.myabe08.real_tee.client import SgxDebugClient
from core.myabe08.real_tee.identity_policy import SgxIdentityPolicy
from core.myabe08.revocation import REVOKE, ACTIVATE
from core.myabe08.signing import new_private_key, public_key_bytes
from core.myabe08.types import Attribute, PolicyContext, PolicyInput, Validity

ROOT = Path(__file__).resolve().parents[5]
BUILD = Path(os.environ.get('MYABE08_SGX_DEBUG_BUILD_DIR', '/tmp/myabe08-sgx-ra-probe'))
SYS_ID = b'MYABE08-4EF-PUBLIC-TEST'


class Clock:
    def now(self):
        return 1000


@pytest.fixture(scope='module')
def sgx_service(tmp_path_factory):
    audit = json.loads((BUILD/'build_audit.json').read_text())
    log = tmp_path_factory.mktemp('public-sgx')/'service.log'
    output = log.open('wb')
    process = subprocess.Popen(('bash', str(ROOT/'src/core/myabe08/real_tee/gramine/run_sgx.sh')),
        cwd=ROOT, env=dict(os.environ, MYABE08_SGX_DEBUG_BUILD_DIR=str(BUILD)),
        stdout=output, stderr=subprocess.STDOUT)
    client = SgxDebugClient()
    try:
        for _ in range(200):
            if process.poll() is not None:
                pytest.fail('Gramine exited before public test readiness')
            try:
                client.health()
                break
            except (ConnectionError, OSError, TimeoutError):
                time.sleep(.1)
        else:
            pytest.fail('Gramine not ready')
        yield client, audit, log, process
    finally:
        if process.poll() is None:
            try:
                client.stop_test_service()
                process.wait(timeout=10)
            except Exception:
                process.terminate()
                process.wait(timeout=10)
        output.close()


def _facade(client, audit, path, mode):
    policy = SgxIdentityPolicy('phase4ef-exact', SGX_DEBUG_GRAMINE_V1,
        mrenclave=bytes.fromhex(audit['mrenclave']), allow_debug=True)
    return PublicMyABE08(sys_id=SYS_ID, namespace='ns', backend=SGX_DEBUG_GRAMINE_V1,
        experiment_trust_mode=mode, identity_policy=policy, state_path=path,
        clock=Clock(), client=client, test_tee_bootstrap=True)


def _label(value):
    return Attribute('ns', 'label', value)


def _context(seed):
    context_id = bytes([seed])*32
    return PolicyContext(SYS_ID, context_id, 1, compute_ctx_priv(SYS_ID, context_id, 1))


@pytest.mark.sgx
@pytest.mark.real_sgx_public
def test_public_eight_algorithm_real_sgx_feasibility(sgx_service, tmp_path):
    client, audit, log, process = sgx_service
    strict = _facade(client, audit, tmp_path/'strict', STRICT_MODE)
    with pytest.raises(AuthenticationError, match='BLOCKED_BY_TCB_POLICY'):
        strict.Setup(c_max=3, validity=Validity(100, 2000))
    scheme = _facade(client, audit, tmp_path/'kgc-state', FEASIBILITY_MODE)
    setup = scheme.Setup(c_max=3, validity=Validity(100, 2000))
    assert setup.metadata['QVLResult'] == 'SGX_QL_QV_RESULT_OUT_OF_DATE'
    assert setup.metadata['StrictRA2'] == 'BLOCKED_BY_TCB_POLICY'
    assert setup.metadata['ExperimentTrustMode'] == FEASIBILITY_MODE
    assert setup.metadata['CollateralExpirationStatus'] == 0
    assert setup.metadata['EnclaveDebug'] is True
    assert setup.metadata['MRENCLAVE'] == audit['mrenclave']
    assert setup.metadata['MRSIGNER'] == audit['mrsigner']
    holder = new_private_key()
    user = scheme.KeyGen(uid='PRIVATE-TEST-USER', attributes=tuple(_label(x) for x in 'ABCDE'),
        auth_public_key=public_key_bytes(holder), validity=Validity(100, 2000))
    assert 'PRIVATE-TEST-USER' not in repr(user)
    workloads = (
        ('single', ('A',), ((1,),)),
        ('or', ('A','B'), ((1,),(1,))),
        ('and', ('A','B'), ((1,1),(0,-1))),
        ('two_of_three', ('A','B','C'), ((1,1),(1,2),(1,3))),
        ('three_of_five', tuple('ABCDE'),
         ((1,1,1),(1,2,4),(1,3,9),(1,4,16),(1,5,25))),
        ('repeated', ('A','B','A','C','A'),
         ((0,0),(0,0),(1,1),(0,0),(0,-1))),
    )
    for index,(name, labels, matrix) in enumerate(workloads, 1):
        message = ('phase4ef-'+name).encode()
        ct = scheme.Encrypt(message=message,
            policy=PolicyInput(matrix, tuple(_label(x) for x in labels)),
            context=_context(index), data_id=name.encode())
        auth = scheme.TEEAuthorize(user=user, ciphertext=ct,
                                   auth_private_key=holder, expiry=1500)
        partial = scheme.Transform(ciphertext=ct, public_auth=auth)
        if name == 'single':
            ct_wire = serialize_ciphertext(ct, scheme.crypto)
            auth_wire = serialize_authorization(auth, ct, scheme.crypto)
            assert serialize_ciphertext(parse_ciphertext(ct_wire, scheme.crypto),
                                        scheme.crypto) == ct_wire
            assert serialize_authorization(parse_authorization(auth_wire, ct, scheme.crypto),
                                           ct, scheme.crypto) == auth_wire
            wire = serialize_partial(partial, scheme.crypto)
            partial = parse_partial(wire, scheme.crypto)
            with pytest.raises(Exception):
                parse_partial(wire[:-1], scheme.crypto)
            with pytest.raises(Exception):
                parse_partial(wire+b'\x00', scheme.crypto)
            with pytest.raises(Exception):
                parse_partial(encode(('WRONG-VERSION',)+decode(wire)[1:]),
                              scheme.crypto)
            with pytest.raises(Exception):
                parse_partial(wire, type(scheme.crypto)(b'OTHER-SYS-ID'))
        assert scheme.FinalDec(partial=partial, recovery_key=user.recovery_key) == message
        assert auth.tee_pairings == 1
        assert partial.csp_pairings == 1 + len(partial.occurrence_slots)
        meta = scheme.workload_metadata(partial, policy_shape=name)
        assert meta['TEEProfile'] == SGX_DEBUG_GRAMINE_V1
        assert meta['ExperimentTrustMode'] == FEASIBILITY_MODE
        assert meta['QVLResult'] == 'SGX_QL_QV_RESULT_OUT_OF_DATE'
        assert meta['tI'] == len(partial.occurrence_slots)
        if name == 'repeated':
            assert partial.reconstruction_rows == (3,5)
            assert partial.occurrence_slots == (2,3)

    # Empty message is rejected before a service call.
    with pytest.raises(ContractError, match='UnsupportedMessage'):
        scheme.Encrypt(message=b'', policy=None, context=None, data_id=b'x')

    limited_key = new_private_key()
    limited = scheme.KeyGen(uid='LIMITED-TEST-USER', attributes=(_label('A'),),
        auth_public_key=public_key_bytes(limited_key), validity=Validity(100, 2000))
    and_ct = scheme.Encrypt(message=b'and-deny',
        policy=PolicyInput(((1,1),(0,-1)), (_label('A'),_label('B'))),
        context=_context(9), data_id=b'and-deny')
    limited_auth = scheme.TEEAuthorize(user=limited, ciphertext=and_ct,
        auth_private_key=limited_key, expiry=1500)
    assert limited_auth.tee_pairings == 1
    with pytest.raises(Unauthorized):
        scheme.Transform(ciphertext=and_ct, public_auth=limited_auth)

    ct = scheme.Encrypt(message=b'historical',
        policy=PolicyInput(((1,),), (_label('A'),)),
        context=_context(10), data_id=b'historical')
    first_auth = scheme.TEEAuthorize(user=user, ciphertext=ct,
                                     auth_private_key=holder, expiry=1500)
    second_auth = scheme.TEEAuthorize(user=user, ciphertext=ct,
                                      auth_private_key=holder, expiry=1500)
    second_partial = scheme.Transform(ciphertext=ct, public_auth=second_auth)
    assert scheme.FinalDec(partial=second_partial,
                           recovery_key=user.recovery_key) == b'historical'
    # W is stable for the same user and CT even with fresh request rerandomization.
    first_partial = scheme.Transform(ciphertext=ct, public_auth=first_auth)
    gt = scheme.crypto
    w1 = gt.gt_div(first_auth.authorization.bundle.t0_q, first_partial.t_a)
    w2 = gt.gt_div(second_auth.authorization.bundle.t0_q, second_partial.t_a)
    assert gt.serialize_gt(w1) == gt.serialize_gt(w2)
    with pytest.raises(Exception):
        scheme.FinalDec(partial=first_partial,
            recovery_key=limited.recovery_key)
    with pytest.raises(Exception):
        scheme.Transform(ciphertext=and_ct, public_auth=first_auth)
    with pytest.raises(Exception):
        scheme.FinalDec(partial=replace(first_partial,
            t_a=second_auth.authorization.bundle.t0_q),
            recovery_key=user.recovery_key)
    damaged = replace(ct, encrypted_message=ct.encrypted_message[:-1] +
        bytes([ct.encrypted_message[-1] ^ 1]))
    with pytest.raises(Exception):
        scheme.Transform(ciphertext=damaged, public_auth=first_auth)
    tamper_auth = scheme.TEEAuthorize(user=user, ciphertext=ct,
                                     auth_private_key=holder, expiry=1500)
    raw_auth = tamper_auth.authorization
    flip = lambda value: value[:-1] + bytes([value[-1] ^ 1])
    ct_mutations = (
        replace(ct, header=replace(ct.header, data_id=b'wrong-data-id')),
        replace(ct, header=replace(ct.header, c=replace(ct.header.c,
            encoded=flip(ct.header.c.encoded)))),
        replace(ct, row_components=(replace(ct.row_components[0],
            encoded=flip(ct.row_components[0].encoded)),)),
        replace(ct, occurrence_components=(replace(ct.occurrence_components[0],
            encoded=flip(ct.occurrence_components[0].encoded)),) +
            ct.occurrence_components[1:]),
        replace(ct, anonymous_filter=replace(ct.anonymous_filter,
            slots=(flip(ct.anonymous_filter.slots[0]),) +
                  ct.anonymous_filter.slots[1:])),
        replace(ct, anonymous_filter=replace(ct.anonymous_filter,
            metadata=replace(ct.anonymous_filter.metadata,
                seed_af=flip(ct.anonymous_filter.metadata.seed_af)))),
        replace(ct, dem_nonce=flip(ct.dem_nonce)),
        replace(ct, encrypted_message=flip(ct.encrypted_message)),
        replace(ct, publication_signature=flip(ct.publication_signature)),
    )
    for changed in ct_mutations:
        with pytest.raises(Exception):
            scheme.Transform(ciphertext=changed, public_auth=tamper_auth)
    cap = raw_auth.capability
    bundle = raw_auth.bundle
    auth_mutations = (
        replace(raw_auth, capability=replace(cap, rev_version=cap.rev_version+1)),
        replace(raw_auth, capability=replace(cap, request_nonce=b'X'*32)),
        replace(raw_auth, capability=replace(cap, expiry=cap.expiry+1)),
        replace(raw_auth, capability=replace(cap, signature=flip(cap.signature))),
        replace(raw_auth, bundle=replace(bundle, k1_q=replace(bundle.k1_q,
            encoded=flip(bundle.k1_q.encoded)))),
        replace(raw_auth, bundle=replace(bundle, t0_q=replace(bundle.t0_q,
            encoded=flip(bundle.t0_q.encoded)))),
        replace(raw_auth, bundle=replace(bundle, items=(replace(bundle.items[0],
            token=flip(bundle.items[0].token)),) + bundle.items[1:])),
        replace(raw_auth, bundle=replace(bundle, items=(replace(bundle.items[0],
            k_tau_q=replace(bundle.items[0].k_tau_q,
                encoded=flip(bundle.items[0].k_tau_q.encoded))),) + bundle.items[1:])),
        replace(raw_auth, bundle=second_auth.authorization.bundle),
    )
    for changed in auth_mutations:
        with pytest.raises(Exception):
            scheme.Transform(ciphertext=ct, public_auth=replace(tamper_auth,
                authorization=changed))
    assert scheme.FinalDec(partial=scheme.Transform(ciphertext=ct,
        public_auth=tamper_auth), recovery_key=user.recovery_key) == b'historical'
    historical = scheme.TEEAuthorize(user=user, ciphertext=ct,
                                     auth_private_key=holder, expiry=1500)
    update = scheme.Rev(uid='PRIVATE-TEST-USER', operation=REVOKE)
    ack = scheme.RevStateUpt(update)
    assert ack.version == 1
    assert scheme.FinalDec(partial=scheme.Transform(ciphertext=ct,
        public_auth=historical), recovery_key=user.recovery_key) == b'historical'
    before = client.health()[4].value
    with pytest.raises(Exception, match='REVOKED'):
        scheme.TEEAuthorize(user=user, ciphertext=ct,
                            auth_private_key=holder, expiry=1500)
    assert client.health()[4].value == before
    update = scheme.Rev(uid='PRIVATE-TEST-USER', operation=ACTIVATE)
    assert scheme.RevStateUpt(update).version == 2
    auth = scheme.TEEAuthorize(user=user, ciphertext=ct,
                               auth_private_key=holder, expiry=1500)
    partial = scheme.Transform(ciphertext=ct, public_auth=auth)
    assert scheme.FinalDec(partial=partial, recovery_key=user.recovery_key) == b'historical'
    with pytest.raises(Exception):
        scheme.Transform(ciphertext=ct, public_auth=auth)

    client.stop_test_service()
    process.wait(timeout=10)
    with pytest.raises(Exception, match='STATE_UNAVAILABLE'):
        scheme.TEEAuthorize(user=user, ciphertext=ct,
                            auth_private_key=holder, expiry=1500)
    output = log.read_text(errors='replace')
    assert 'PRIVATE-TEST-USER' not in output
    assert scheme._k_rev.hex() not in output
    assert hashlib.sha256(user.blob.opaque).hexdigest() not in output
    assert all(name in scheme.spans_ns for name in
        ('Setup','KeyGen','Encrypt','Rev','RevStateUpt','TEEAuthorize','Transform','FinalDec'))
    assert scheme.authorize_breakdown_ns
    assert scheme.authorize_breakdown_ns[0]['host_pre_rpc_ns'] >= 0
    required = ('host_pre_rpc_ns', 'rpc_send_ns', 'rpc_receive_ns',
        'host_post_rpc_ns', 'enclave_total_ns', 'credential_verify_ns',
        'revset_lookup_ns', 'tokenization_ns', 'rerandomization_ns',
        't0_pairing_ns', 'cap_sign_ns')
    for observation in scheme.authorize_breakdown_ns:
        assert all(type(observation[name]) is int and observation[name] >= 0
                   for name in required)
        assert sum(observation[name] for name in required[5:]) <= observation['enclave_total_ns']

    # A new process starts unbootstrapped; the old facade cannot reuse its
    # previous quote, keys, RevSet or instance identity.
    with log.open('ab') as restarted_output:
        restarted = subprocess.Popen(('bash', str(ROOT/'src/core/myabe08/real_tee/gramine/run_sgx.sh')),
            cwd=ROOT, env=dict(os.environ, MYABE08_SGX_DEBUG_BUILD_DIR=str(BUILD)),
            stdout=restarted_output, stderr=subprocess.STDOUT)
        try:
            for _ in range(200):
                if restarted.poll() is not None:
                    pytest.fail('restarted Gramine exited before readiness')
                try:
                    health = client.health()
                    break
                except (ConnectionError, OSError, TimeoutError):
                    time.sleep(.1)
            else:
                pytest.fail('restarted Gramine not ready')
            assert health[3] != scheme._instance and health[2].value == 0
            with pytest.raises(Exception, match='STATE_UNAVAILABLE'):
                scheme.TEEAuthorize(user=user, ciphertext=ct,
                                    auth_private_key=holder, expiry=1500)
        finally:
            if restarted.poll() is None:
                client.stop_test_service()
                restarted.wait(timeout=10)
