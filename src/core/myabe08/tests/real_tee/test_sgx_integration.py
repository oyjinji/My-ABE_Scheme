"""Explicit real Gramine SGX DEBUG integration; never an attestation test."""
import json
import os
from pathlib import Path
import secrets
import subprocess
import time

import pytest

if os.environ.get('MYABE08_RUN_SGX_TESTS') != '1':
    pytest.skip('real SGX tests require MYABE08_RUN_SGX_TESTS=1', allow_module_level=True)

from core.myabe08.af import ProtectedPayloadAF, compute_ctx_af
from core.myabe08.algebra import (AlgebraOperationCounts, encrypt_algebra_core,
    finaldec_algebra_core, keygen_algebra_core, setup_algebra_core)
from core.myabe08.capability import csp_transform_verified
from core.myabe08.credential import (encode_private_ingress, issue_credential,
    sign_possession)
from core.myabe08.crypto import BLS12381Backend, compute_ctx_priv, dem_decrypt, DEMCiphertext
from core.myabe08.encoding import UInt32
from core.myabe08.lsss import LSSSMatrix, prepare_policy_rows
from core.myabe08.publication import (build_publication, compute_ctx_ct,
    issue_do_certificate, make_af_header)
from core.myabe08.real_tee.client import SgxDebugClient, SgxHeadRpcProxy
from core.myabe08.real_tee.messages import encode_registration
from core.myabe08.real_tee.rpc import RpcError
from core.myabe08.revocation import (ACTIVATE, REVOKE,
    EmulatedPersistentKGCStateStore, KGCRevocationManager,
    sign_management_command)
from core.myabe08.signing import new_private_key, public_key_bytes
from core.myabe08.state import CSPRequestState, DURequestState
from core.myabe08.tee import (encode_policy_labels, make_emulated_host_request,
    sign_do_policy_proof)
from core.myabe08.types import Attribute, PolicyContext, SealedUserBlob, Validity

ROOT = Path(__file__).resolve().parents[5]
BUILD = Path(os.environ.get('MYABE08_SGX_DEBUG_BUILD_DIR',
                            '/tmp/myabe08-sgx-debug-build-v2'))
SYS_ID = b'MYABE08-SGX-DEBUG-TEST'


def _await_ready(client, process):
    for _ in range(200):
        if process.poll() is not None:
            raise AssertionError('gramine-sgx exited before service readiness')
        try:
            return client.health()
        except (ConnectionError, OSError, TimeoutError):
            time.sleep(.1)
    raise AssertionError('gramine-sgx service did not become ready')


@pytest.fixture(scope='module')
def sgx_service(tmp_path_factory):
    script = ROOT / 'src/core/myabe08/real_tee/gramine/run_sgx.sh'
    assert (BUILD / 'myabe08_tee.manifest.sgx').is_file(), 'sign TEST manifest first'
    log = tmp_path_factory.mktemp('sgx-log') / 'service.log'
    client = SgxDebugClient()
    launches = []

    def launch():
        output = log.open('ab')
        process = subprocess.Popen(('bash', str(script)), cwd=ROOT,
            stdout=output, stderr=subprocess.STDOUT, env=os.environ.copy())
        launches.append((process, output))
        health = _await_ready(client, process)
        assert health[2] == UInt32(0)
        return health

    try:
        launch()
        yield client, launch, launches, log
    finally:
        for process, output in launches:
            if process.poll() is None:
                try:
                    client.stop_test_service()
                    process.wait(timeout=10)
                except Exception:
                    process.terminate()
                    process.wait(timeout=10)
            output.close()


@pytest.mark.sgx
def test_real_sgx_debug_end_to_end_and_restart(sgx_service, tmp_path):
    client, launch, launches, log = sgx_service
    audit = json.loads((BUILD / 'build_audit.json').read_text())
    profile = client.profile_info()
    assert profile[1] == 'SGX_DEBUG_GRAMINE_V1'
    assert profile[6].hex() == audit['mrenclave']
    assert profile[7].hex() == audit['mrsigner']
    assert profile[8].value & 2  # SGX REPORT DEBUG bit, from enclave local report.
    assert audit['debug'] is True
    with pytest.raises(RpcError, match='STATE_UNAVAILABLE'):
        client.open_test_session(SYS_ID, 'DU')

    backend = BLS12381Backend(SYS_ID)
    kgc, publisher, holder, admin = (new_private_key() for _ in range(4))
    k_rev = secrets.token_bytes(32)  # TEST KGC material, sent over unauthenticated TEST ingress.
    pp, msk = setup_algebra_core(backend, 2)
    base, recovery = keygen_algebra_core(pp, msk, backend)
    bootstrap = client.test_bootstrap(SYS_ID, k_rev, public_key_bytes(kgc),
                                      'ns', pp, backend, 1000)
    assert bootstrap[0] == 'MYABE08-SGX-DEBUG-BOOT-OK'
    cap_public, ack_public = bootstrap[1:3]
    assert len(cap_public) == len(ack_public) == 32

    validity = Validity(100, 2000)
    cert = issue_do_certificate(kgc, SYS_ID, 'ns', public_key_bytes(publisher), validity)
    labels = (Attribute('ns', 'label', 'A'), Attribute('ns', 'label', 'B'))
    credential = issue_credential(kgc, SYS_ID, 'TEST-PRIVATE-UID',
        tuple(sorted(labels)), validity, 1, public_key_bytes(holder))
    kgc_session = client.open_test_session(SYS_ID, 'KGC')
    blob_bytes = client.register_test_user(kgc_session,
        kgc_session.send(encode_registration(credential, base, backend)))
    blob = SealedUserBlob(blob_bytes)
    assert credential.uid.encode() not in blob_bytes
    assert backend.serialize_scalar(base.mu) not in blob_bytes
    assert backend.serialize_g2(base.k0) not in blob_bytes

    do_session = client.open_test_session(SYS_ID, 'DO')
    ctx = PolicyContext(SYS_ID, b'P'*32, 1, compute_ctx_priv(SYS_ID, b'P'*32, 1))
    raw = encode_policy_labels(labels)
    proof = sign_do_policy_proof(publisher, ctx, raw, do_session.binding)
    tokens = client.policy_tokenize(do_session, cert, proof, ctx, do_session.send(raw))
    assert len(tokens) == 2 and tokens[0] != tokens[1]
    assert client.policy_tokenize(do_session, cert, proof, ctx,
        do_session.send(raw)) == tokens
    ctx_other = PolicyContext(SYS_ID, b'Q'*32, 1,
        compute_ctx_priv(SYS_ID, b'Q'*32, 1))
    proof_other = sign_do_policy_proof(publisher, ctx_other, raw, do_session.binding)
    assert client.policy_tokenize(do_session, cert, proof_other, ctx_other,
        do_session.send(raw)) != tokens

    matrix = LSSSMatrix(((1,), (1,)), backend.scalar_order, 2, 1)
    entries, _ = prepare_policy_rows(matrix, tokens, 2)
    af_header = make_af_header(matrix, tokens, ctx, 2, backend)
    af = ProtectedPayloadAF().build(entries, header=af_header,
                                    ctx_af=compute_ctx_af(af_header))
    core = encrypt_algebra_core(pp, matrix, tokens, backend)
    message = b'MYABE08 real SGX DEBUG integration TEST'
    publication = build_publication(core, af, af_header, ctx, b'TEST-DATA',
        message, publisher, cert, backend, tee_profile_id='SGX_DEBUG_GRAMINE_V1')
    du_session = client.open_test_session(SYS_ID, 'DU')
    csp_state = CSPRequestState()
    emulated_ct = build_publication(core, af, af_header, ctx, b'TEST-DATA',
        message, publisher, cert, backend)
    wrong_profile_request = make_emulated_host_request(emulated_ct, backend,
                                                       du_session, 1500)
    with pytest.raises(RpcError, match='INVALID_REQUEST'):
        client.authorize(du_session, emulated_ct, wrong_profile_request,
                         du_session.send(b'TEST'), backend)
    # A rejected request need not consume its channel record; use a fresh session.
    du_session = client.open_test_session(SYS_ID, 'DU')

    def authorize():
        request = make_emulated_host_request(publication, backend, du_session, 1500)
        proof = sign_possession(holder, SYS_ID, du_session.binding,
                                request.header_digest, request.request_nonce)
        ingress = du_session.send(encode_private_ingress(credential, blob, proof))
        authz, sgx_pairs = client.authorize(du_session, publication,
                                            request, ingress, backend)
        DURequestState.from_host_request(request).verify_response_binding(request, authz)
        return authz, sgx_pairs

    authz, sgx_pairs = authorize()
    assert sgx_pairs == 1
    counts = AlgebraOperationCounts()
    transformed = csp_transform_verified(authz, publication, pp, backend,
        cap_public, public_key_bytes(kgc), 'ns', lambda_clock(), csp_state,
        counts=counts)
    assert transformed.candidate_rows == (1, 2)
    assert len(transformed.reconstruction_rows) == 1
    assert transformed.occurrence_slots == (1,)
    assert counts.pairing_terms == 1 + len(transformed.occurrence_slots)
    expected_t0 = backend.gt_mul(
        backend.gt_pow(core.e, backend.scalar_inv(recovery.rk)), transformed.t_a)
    assert backend.serialize_gt(authz.bundle.t0_q) == backend.serialize_gt(expected_t0)
    quotient, recovered = finaldec_algebra_core(authz.bundle.t0_q,
        transformed.t_a, recovery, backend)
    assert recovered == core.e
    assert dem_decrypt(compute_ctx_ct(publication.header, backend),
        backend.serialize_gt(recovered), DEMCiphertext(publication.dem_nonce,
            publication.encrypted_message)) == message
    assert client.health()[4].value == 1

    kgc_store = EmulatedPersistentKGCStateStore(tmp_path/'kgc-test-state',
        secrets.token_bytes(32), SYS_ID)
    manager = KGCRevocationManager(SYS_ID, k_rev, public_key_bytes(admin),
        kgc, ack_public, kgc_store)
    manager.register(credential.uid)
    for operation in (REVOKE, ACTIVATE):
        command = sign_management_command(admin, SYS_ID, credential.uid,
                                          operation, manager.version)
        update = manager.rev(credential.uid, operation, command, kgc_session)
        ack = client.rev_state_update(kgc_session, update)
        manager.commit_ack(ack, SgxHeadRpcProxy(client))
        if operation == REVOKE:
            before = client.health()[4].value
            with pytest.raises(RpcError, match='REVOKED'):
                authorize()
            assert client.health()[4].value == before
        else:
            assert authorize()[1] == 1

    first_instance = client.health()[3]
    client.stop_test_service()
    launches[-1][0].wait(timeout=10)
    launch()
    assert client.health()[3] != first_instance
    assert client.health()[2] == UInt32(0)
    with pytest.raises(RpcError, match='STATE_UNAVAILABLE'):
        client.open_test_session(SYS_ID, 'DU')
    stale_request = make_emulated_host_request(publication, backend, du_session, 1500)
    stale_proof = sign_possession(holder, SYS_ID, du_session.binding,
                                  stale_request.header_digest, stale_request.request_nonce)
    with pytest.raises(RpcError, match='STATE_UNAVAILABLE'):
        client.authorize(du_session, publication, stale_request,
            du_session.send(encode_private_ingress(credential, blob, stale_proof)), backend)
    assert len(launches) == 2
    output = log.read_text(errors='replace')
    assert 'MYABE08_SGX_DEBUG_SERVICE_READY' in output
    for secret in (credential.uid, k_rev.hex(), backend.serialize_scalar(base.mu).hex()):
        assert secret not in output


def lambda_clock():
    class TestClock:
        def now(self): return 1000
    return TestClock()
