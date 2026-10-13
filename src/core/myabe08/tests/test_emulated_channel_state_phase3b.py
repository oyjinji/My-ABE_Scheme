"""Software evidence/channel and atomic nonce state; no hardware claims."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import secrets

import pytest

from core.myabe08.attestation import (EmulatedChallengeStore,issue_emulated_evidence,
    verify_emulated_evidence)
from core.myabe08.channel import (establish_emulated_channel,x25519_private_new,
                                  x25519_public_bytes)
from core.myabe08.errors import AuthenticationError,ContractError,ProtocolRejectedError,ReplayRejectedError
from core.myabe08.signing import new_private_key,public_key_bytes
from core.myabe08.state import CSPRequestState,TEEIssueStore
from core.myabe08.tests.protocol_fixtures import MEASUREMENT,SYS_ID,channel_pair


def test_emulated_evidence_and_channel_negative_gates():
    root=new_private_key();store=EmulatedChallengeStore()
    challenge=secrets.token_bytes(32);session=secrets.token_bytes(32)
    server_key=x25519_private_new();client_key=x25519_private_new()
    e=issue_emulated_evidence(root,SYS_ID,MEASUREMENT,3,challenge,
                              x25519_public_bytes(server_key),session)
    with pytest.raises(AuthenticationError):
        verify_emulated_evidence(e,public_key_bytes(new_private_key()),SYS_ID,
                                 MEASUREMENT,2,challenge,EmulatedChallengeStore())
    for kwargs in ({'measurement':b'Z'*32},{'security_version':1},
                   {'challenge':b'Z'*32},{'tee_profile_id':'SGX_PROFILE'}):
        bad=replace(e,**kwargs)
        with pytest.raises((ProtocolRejectedError,ContractError,AuthenticationError)):
            verify_emulated_evidence(bad,public_key_bytes(root),SYS_ID,
                                     MEASUREMENT,2,challenge,EmulatedChallengeStore())
    with pytest.raises(AuthenticationError):
        establish_emulated_channel(client_key,x25519_private_new(),e,
            public_key_bytes(root),SYS_ID,MEASUREMENT,2,challenge,EmulatedChallengeStore())
    client,server=establish_emulated_channel(client_key,server_key,e,
        public_key_bytes(root),SYS_ID,MEASUREMENT,2,challenge,store)
    record=client.send(b'confidential credential/blob TEST payload')
    assert server.receive(record)==b'confidential credential/blob TEST payload'
    with pytest.raises(ReplayRejectedError): server.receive(record)
    with pytest.raises(ReplayRejectedError): client.receive(record)
    with pytest.raises(ReplayRejectedError):
        establish_emulated_channel(client_key,server_key,e,public_key_bytes(root),
                                   SYS_ID,MEASUREMENT,2,challenge,store)
    return_record=server.send(b'authorized TEST response')
    assert client.receive(return_record)==b'authorized TEST response'


def test_record_tamper_ad_sequence_and_direction_keys():
    root=new_private_key();client,server,e,_,_=channel_pair(root,EmulatedChallengeStore())
    record=client.send(b'nonempty record')
    for modified in (replace(record,ciphertext=record.ciphertext[:-1]+bytes([record.ciphertext[-1]^1])),
                     replace(record,nonce=b'Z'*12)):
        with pytest.raises(AuthenticationError): server.receive(modified)
    for modified in (replace(record,session_id=b'Z'*32),
                     replace(record,direction='TEE->DU'),
                     replace(record,sequence=1)):
        with pytest.raises(ReplayRejectedError): server.receive(modified)
    assert server.receive(record)==b'nonempty record'
    next_record=client.send(b'next record')
    assert next_record.sequence==1 and next_record.nonce!=record.nonce
    assert server.receive(next_record)==b'next record'
    with pytest.raises(ReplayRejectedError): server.receive(record)
    with pytest.raises(ReplayRejectedError): client.receive(next_record)


def test_concurrent_record_replay_only_one_receive():
    root=new_private_key();client,server,_,_,_=channel_pair(root,EmulatedChallengeStore())
    record=client.send(b'one payload')
    def attempt(_):
        try: return server.receive(record)
        except ReplayRejectedError: return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        out=list(pool.map(attempt,range(2)))
    assert out.count(b'one payload')==1 and out.count(None)==1


@pytest.mark.parametrize('store,method',[(TEEIssueStore,'reserve'),(CSPRequestState,'consume_once')])
def test_concurrent_nonce_state_allows_one(store,method):
    state=store();nonce=b'N'*32
    def attempt(_):
        try:
            getattr(state,method)(SYS_ID,nonce)
            return True
        except ReplayRejectedError: return False
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(attempt,range(2)))==[False,True]
    if isinstance(state,TEEIssueStore):
        assert state.state(SYS_ID,nonce)=='reserved'
        state.mark_issued(SYS_ID,nonce)
        assert state.state(SYS_ID,nonce)=='issued'
    else: assert state.count()==1
