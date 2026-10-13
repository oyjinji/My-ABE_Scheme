"""Strict QVL policy and TEST-only record mechanics; no simulated QVL pass."""
from dataclasses import replace
from datetime import datetime,timezone
import os
import subprocess
import sys

import pytest

from core.myabe08.channel import x25519_private_new,x25519_public_bytes
from core.myabe08.errors import AuthenticationError,ContractError,ReplayRejectedError
from core.myabe08.real_tee.attested_session import (
    channel_endpoint,FEASIBILITY_MODE,STRICT_MODE,OUTDATED_TCB)
from core.myabe08.real_tee.qvl_policy import (
    QvlEvaluation,decide_policy,StrictVerifiedSgxQuote,
    QvlCheckedNonTerminalQuote)
from core.myabe08.real_tee.tcb_diagnosis import (
    collateral_current,match_platform_tcb_level,match_qe_tcb_level)


def _evaluation(api=0,expiration=0,qv=OUTDATED_TCB):
    return QvlEvaluation(api,expiration,qv,(3,0),536,b'Q'*32)


def test_strict_and_feasibility_decisions_are_disjoint():
    outdated=_evaluation()
    assert decide_policy(outdated).reason=='BLOCKED_BY_TCB_POLICY'
    assert not decide_policy(outdated,
        allow_outdated_debug_feasibility=True,enclave_debug=False).feasibility_accepted
    allowed=decide_policy(outdated,allow_outdated_debug_feasibility=True,
                          enclave_debug=True)
    assert not allowed.strict_accepted and allowed.feasibility_accepted
    assert allowed.reason=='INSECURE_TEST_OVERRIDE_USED'
    current=decide_policy(_evaluation(qv=0),
        allow_outdated_debug_feasibility=True,enclave_debug=True)
    assert current.strict_accepted and not current.feasibility_accepted
    for rejected in (_evaluation(api=0xe019),_evaluation(expiration=1),
                     *(_evaluation(qv=q) for q in (0xA004,0xA005,0xA006,0xA099))):
        d=decide_policy(rejected,allow_outdated_debug_feasibility=True,
                        enclave_debug=True)
        assert not d.strict_accepted and not d.feasibility_accepted
    with pytest.raises(ContractError):
        StrictVerifiedSgxQuote(None,b'quote',outdated,None)
    with pytest.raises(ContractError):
        QvlCheckedNonTerminalQuote(None,b'quote',outdated,None)


def _pair(*,sid=b'S'*32,challenge=b'C'*32,digest=b'Q'*32):
    enclave_private=x25519_private_new()
    client_private=x25519_private_new()
    common=dict(sys_id=b'SYS',session_id=sid,challenge=challenge,
                quote_digest=digest,qv_result=OUTDATED_TCB,mode=FEASIBILITY_MODE)
    server=channel_endpoint(enclave_private,x25519_public_bytes(client_private),
                            enclave_side=True,**common)
    client=channel_endpoint(client_private,x25519_public_bytes(enclave_private),
                            enclave_side=False,**common)
    return enclave_private,client_private,server,client,common


def test_channel_bidirectional_and_record_rejections():
    _,_,server,client,_=_pair()
    request=client.send(b'one-time TEST dummy')
    assert server.receive(request)==b'one-time TEST dummy'
    with pytest.raises(ReplayRejectedError):server.receive(request)
    answer=server.send(b'PROVISION_TEST_OK')
    assert client.receive(answer)==b'PROVISION_TEST_OK'
    with pytest.raises(ReplayRejectedError):client.receive(answer)
    second=client.send(b'another record')
    with pytest.raises(ReplayRejectedError):server.receive(replace(second,sequence=0))
    with pytest.raises(ReplayRejectedError):server.receive(replace(second,direction='ENCLAVE->CLIENT'))
    with pytest.raises(AuthenticationError):
        server.receive(replace(second,ciphertext=second.ciphertext[:-1]+
                            bytes([second.ciphertext[-1]^1])))
    assert server.receive(second)==b'another record'


def test_context_and_key_substitution_fail_aead():
    enclave_private,client_private,server,client,context=_pair()
    record=server.send(b'key confirmation')
    assert client.receive(record)==b'key confirmation'
    for changes in (dict(session_id=b'T'*32),dict(challenge=b'D'*32),
                    dict(quote_digest=b'R'*32)):
        altered=dict(context,**changes)
        wrong=channel_endpoint(client_private,x25519_public_bytes(enclave_private),
                               enclave_side=False,**altered)
        with pytest.raises((ReplayRejectedError,AuthenticationError)):
            wrong.receive(record)
    wrong_private=x25519_private_new()
    wrong=channel_endpoint(wrong_private,x25519_public_bytes(enclave_private),
                           enclave_side=False,**context)
    with pytest.raises(AuthenticationError):wrong.receive(record)
    other_enclave=x25519_private_new()
    wrong=channel_endpoint(client_private,x25519_public_bytes(other_enclave),
                           enclave_side=False,**context)
    with pytest.raises(AuthenticationError):wrong.receive(record)
    with pytest.raises(ContractError):
        channel_endpoint(client_private,x25519_public_bytes(enclave_private),
                         enclave_side=False,**dict(context,qv_result=0))
    with pytest.raises(ContractError):
        channel_endpoint(client_private,x25519_public_bytes(enclave_private),
                         enclave_side=False,**dict(context,mode=STRICT_MODE))


def test_test_override_does_not_pollute_new_strict_subprocess():
    env=dict(os.environ)
    env.pop('RA_TLS_ALLOW_OUTDATED_TCB_INSECURE',None)
    env.pop('RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE',None)
    result=subprocess.run((sys.executable,'-c',
        "import os;assert 'RA_TLS_ALLOW_OUTDATED_TCB_INSECURE' not in os.environ;"
        "assert 'RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE' not in os.environ"),
        env=env,capture_output=True)
    assert result.returncode==0


def test_tcb_diagnosis_matches_pck_components_not_qe_status():
    def level(first,status):
        values=[first,first,2,2,3,1,0,255]+[0]*8
        return dict(tcb={'pcesvn':11,'sgxtcbcomponents':
                    [{'svn':n} for n in values]},tcbStatus=status)
    tcb=dict(issueDate='2026-09-24T14:15:36Z',
             nextUpdate='2026-10-24T14:15:36Z',
             tcbLevels=[level(9,'UpToDate'),level(7,'OutOfDate')])
    current=datetime(2026,9,25,tzinfo=timezone.utc)
    assert collateral_current(tcb,current)
    assert not collateral_current(tcb,datetime(2026,11,1,tzinfo=timezone.utc))
    assert match_platform_tcb_level(tcb,[7,7,2,2,3,1,0,255]+[0]*8,11)['tcbStatus']=='OutOfDate'
    with pytest.raises(ContractError):
        match_platform_tcb_level(tcb,[0]*16,11)
    qe=dict(mrsigner='AA',isvprodid=1,tcbLevels=[
        dict(tcb={'isvsvn':8},tcbStatus='UpToDate'),
        dict(tcb={'isvsvn':6},tcbStatus='OutOfDate')])
    assert match_qe_tcb_level(qe,mrsigner='aa',product_id=1,svn=11)['tcbStatus']=='UpToDate'
    with pytest.raises(ContractError):
        match_qe_tcb_level(qe,mrsigner='bb',product_id=1,svn=11)
