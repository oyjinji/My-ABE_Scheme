"""Explicit real SGX/QVL OUT_OF_DATE DEBUG feasibility; never canonical RA PASS."""
from dataclasses import replace
import json
import os
from pathlib import Path
import secrets
import subprocess
import time

import pytest

if os.environ.get('MYABE08_RUN_SGX_RA_FEASIBILITY') != '1':
    pytest.skip('set MYABE08_RUN_SGX_RA_FEASIBILITY=1 for real QVL feasibility',
                allow_module_level=True)

from core.myabe08.channel import x25519_private_new,x25519_public_bytes
from core.myabe08.encoding import UInt64,encode,decode
from core.myabe08.errors import AuthenticationError
from core.myabe08.real_tee import client as client_module
from core.myabe08.real_tee.attested_session import (
    channel_endpoint,FEASIBILITY_MODE,OUTDATED_TCB)
from core.myabe08.real_tee.client import SgxDebugClient
from core.myabe08.real_tee.identity_policy import SgxIdentityPolicy
from core.myabe08.real_tee.qvl_policy import (
    QvlCheckedNonTerminalQuote,decide_policy,verify_real_quote)
from core.myabe08.real_tee.rpc import (
    call,RpcError,RA_SESSION_OPEN,RA_SESSION_ACTIVATE,RA_DUMMY_PROVISION)
from core.myabe08.revocation import parse_record,record_wire

ROOT=Path(__file__).resolve().parents[5]
BUILD=Path(os.environ.get('MYABE08_SGX_DEBUG_BUILD_DIR',
                          '/tmp/myabe08-sgx-ra-probe'))
SYS_ID=b'MYABE08-4D-TCB'


@pytest.fixture(scope='module')
def sgx(tmp_path_factory):
    audit=json.loads((BUILD/'build_audit.json').read_text())
    assert audit['remote_attestation']=='dcap' and audit['debug']
    path=tmp_path_factory.mktemp('tcb-feas')/'gramine.log'
    with path.open('wb') as output:
        p=subprocess.Popen(('bash',str(ROOT/'src/core/myabe08/real_tee/gramine/run_sgx.sh')),
            cwd=ROOT,env=dict(os.environ,MYABE08_SGX_DEBUG_BUILD_DIR=str(BUILD)),
            stdout=output,stderr=subprocess.STDOUT)
        client=SgxDebugClient()
        try:
            for _ in range(200):
                if p.poll() is not None:pytest.fail('Gramine exited before readiness')
                try:client.profile_info();break
                except (OSError,ConnectionError,TimeoutError):time.sleep(.1)
            else:pytest.fail('Gramine not ready')
            yield client,audit
        finally:
            if p.poll() is None:
                try:client.stop_test_service();p.wait(timeout=10)
                except Exception:p.terminate();p.wait(timeout=10)


def _open_raw(client):
    challenge=secrets.token_bytes(32);sid=secrets.token_bytes(32)
    result=call(client.address,RA_SESSION_OPEN,
        ('MYABE-RA-SESSION-OPEN-V1',SYS_ID,challenge,sid))
    assert result[0]=='MYABE-RA-SESSION-QUOTE-V1' and result[1]==sid
    public,report_data,quote=result[2:]
    evaluation,checked=verify_real_quote(quote)
    assert type(checked) is QvlCheckedNonTerminalQuote
    assert evaluation.api_return==0 and evaluation.collateral_expiration_status==0
    assert evaluation.qv_result==OUTDATED_TCB
    assert report_data==checked.fields.report_data
    checked.check_binding(SYS_ID,challenge,public)
    return challenge,sid,public,checked


@pytest.mark.sgx
def test_real_strict_reject_and_feasibility_identity_channel_dummy(sgx,monkeypatch):
    client,audit=sgx
    measurement=bytes.fromhex(audit['mrenclave'])
    signer=bytes.fromhex(audit['mrsigner'])
    exact=SgxIdentityPolicy('phase4dtcb-exact','SGX_DEBUG_GRAMINE_V1',
                            mrenclave=measurement,allow_debug=True)
    with pytest.raises(AuthenticationError,match='BLOCKED_BY_TCB_POLICY'):
        client.open_quote_bound_test_session(SYS_ID,exact)

    session=client.open_quote_bound_test_session(SYS_ID,exact,
        allow_outdated_debug_feasibility=True)
    checked=session.checked_quote
    assert checked.check_identity(exact)
    assert session.metadata['TEEProfile']=='SGX_DEBUG_GRAMINE_V1'
    assert session.metadata['StrictRA2']=='BLOCKED_BY_TCB_POLICY'
    assert session.metadata['INSECURE_TEST_OVERRIDE_USED']
    assert not session.decision.strict_accepted and session.decision.feasibility_accepted
    assert not checked.check_identity(SgxIdentityPolicy('wrong-m','SGX_DEBUG_GRAMINE_V1',
        mrenclave=b'X'*32,allow_debug=True))
    assert not checked.check_identity(SgxIdentityPolicy('no-debug','SGX_DEBUG_GRAMINE_V1',
        mrenclave=measurement,allow_debug=False))
    signer_policy=lambda m,s,p: SgxIdentityPolicy('signer','SGX_DEBUG_GRAMINE_V1',
        mrsigner=m,product_id=p,min_svn=s,allow_debug=True)
    assert checked.check_identity(signer_policy(signer,0,0))
    assert not checked.check_identity(signer_policy(b'Y'*32,0,0))
    assert not checked.check_identity(signer_policy(signer,0,1))
    assert not checked.check_identity(signer_policy(signer,1,0))
    with pytest.raises(AuthenticationError):
        checked.check_binding(SYS_ID,b'Z'*32,
                              session.endpoint.binding.peer_ephemeral_public_key)
    with pytest.raises(AuthenticationError):
        checked.check_binding(SYS_ID,session.challenge,b'B'*32)
    assert decide_policy(session.evaluation,
        allow_outdated_debug_feasibility=False,enclave_debug=True).strict_accepted is False

    # A second genuine quote/session proves freshness and supplies a cross-session target.
    second=client.open_quote_bound_test_session(SYS_ID,exact,
        allow_outdated_debug_feasibility=True)
    assert second.challenge!=session.challenge and second.session_id!=session.session_id
    assert second.checked_quote.quote_digest!=checked.quote_digest
    with pytest.raises(AuthenticationError):
        checked.check_binding(SYS_ID,second.challenge,
                              session.endpoint.binding.peer_ephemeral_public_key)

    original_call=client_module.call
    captured=[]
    def inspect_encrypted_dummy(address,kind,value,**kwargs):
        if kind==RA_DUMMY_PROVISION:
            assert value[1]==session.session_id
            wire=value[2];captured.append(wire)
            record=parse_record(wire)
            mutations=(replace(record,direction='ENCLAVE->CLIENT'),
                       replace(record,sequence=1),
                       replace(record,ciphertext=record.ciphertext[:-1]+
                               bytes([record.ciphertext[-1]^1])))
            for changed in mutations:
                with pytest.raises(RpcError):
                    original_call(address,kind,(value[0],session.session_id,
                                                record_wire(changed)))
            with pytest.raises(RpcError):
                original_call(address,kind,(value[0],second.session_id,wire))
        return original_call(address,kind,value,**kwargs)
    monkeypatch.setattr(client_module,'call',inspect_encrypted_dummy)
    result=client.provision_random_test_dummy(session)
    assert result[0]=='PROVISION_TEST_OK' and result[1]==32
    assert session.dummy_sent_count==1 and len(captured)==1
    with pytest.raises(RpcError):
        original_call(client.address,RA_DUMMY_PROVISION,
                      ('MYABE-RA-DUMMY-PROVISION-V1',session.session_id,captured[0]))
    # A second record with a rolled-back sequence fails before dummy processing.
    rollback=replace(session.endpoint.send(b'not another dummy'),sequence=0)
    with pytest.raises(RpcError):
        original_call(client.address,RA_DUMMY_PROVISION,
            ('MYABE-RA-DUMMY-PROVISION-V1',session.session_id,record_wire(rollback)))


@pytest.mark.sgx
def test_real_quote_digest_qv_and_client_key_substitution(sgx):
    client,_=sgx
    challenge,sid,public,checked=_open_raw(client)
    private=x25519_private_new();client_public=x25519_public_bytes(private)
    activate=lambda s,d,q,m:call(client.address,RA_SESSION_ACTIVATE,
        ('MYABE-RA-SESSION-ACTIVATE-V1',s,client_public,d,UInt64(q),m))
    with pytest.raises(RpcError):activate(b'X'*32,checked.quote_digest,OUTDATED_TCB,FEASIBILITY_MODE)
    with pytest.raises(RpcError):activate(sid,b'X'*32,OUTDATED_TCB,FEASIBILITY_MODE)
    with pytest.raises(RpcError):activate(sid,checked.quote_digest,0,FEASIBILITY_MODE)
    with pytest.raises(RpcError):activate(sid,checked.quote_digest,OUTDATED_TCB,'STRICT_CURRENT_TCB')
    response=activate(sid,checked.quote_digest,OUTDATED_TCB,FEASIBILITY_MODE)
    assert response[:2]==('MYABE-RA-SESSION-READY-V1',sid)
    wrong_private=x25519_private_new()
    wrong=channel_endpoint(wrong_private,public,enclave_side=False,sys_id=SYS_ID,
        session_id=sid,challenge=challenge,quote_digest=checked.quote_digest,
        qv_result=OUTDATED_TCB,mode=FEASIBILITY_MODE)
    with pytest.raises(AuthenticationError):wrong.receive(parse_record(response[2]))


@pytest.mark.sgx
def test_strict_subprocess_has_no_insecure_ra_tls_override(sgx):
    env=dict(os.environ)
    assert 'RA_TLS_ALLOW_OUTDATED_TCB_INSECURE' not in env
    assert 'RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE' not in env
    p=subprocess.run(('python3','-c',
        "import os;assert 'RA_TLS_ALLOW_OUTDATED_TCB_INSECURE' not in os.environ;"
        "assert 'RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE' not in os.environ"),
        env=env,capture_output=True)
    assert p.returncode==0
