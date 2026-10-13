"""EMULATED protocol integration with TEST state coordinator only."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import fields,replace
import inspect

import pytest

from core.myabe08.algebra import AlgebraOperationCounts
from core.myabe08.capability import (authorization_bytes,csp_transform_verified,
    verify_and_consume,verify_capability)
from core.myabe08.credential import (encode_private_ingress,sign_possession)
from core.myabe08.crypto import BLS12381Backend
from core.myabe08.errors import (AuthenticationError,ProtocolRejectedError,
    ReplayRejectedError,StateSynchronizationError,Unauthorized)
from core.myabe08.metrics import ProtocolOperationCounts
from core.myabe08.signing import new_private_key,public_key_bytes
from core.myabe08.state import CSPRequestState
from core.myabe08.tee import (EmulatedAnonymousAuthorizationEnclave,
    EmulatedHostRequest,encode_policy_labels,sign_do_policy_proof)
from core.myabe08.tests.protocol_fixtures import (authorize,bootstrap,complete)
from core.myabe08.types import (AuthorizationBundle,EphemeralTokenComponent,
    SignedCapability,TEEAuthorization)


def _flip(raw): return bytes([raw[0]^1])+raw[1:]


def _pair_counter(monkeypatch):
    original=BLS12381Backend.pair
    calls={'n':0}
    def counted(self,g1,g2):
        calls['n']+=1
        return original(self,g1,g2)
    monkeypatch.setattr(BLS12381Backend,'pair',counted)
    return calls


def test_emulated_test_state_full_nonempty_message_roundtrip(monkeypatch):
    x=bootstrap();calls=_pair_counter(monkeypatch)
    auth=authorize(x)
    message,tr,csp,recovered=complete(x,auth)
    assert message==x['plaintext']
    assert recovered==x['core'].e
    assert (len(tr.candidate_rows),len(tr.reconstruction_rows),len(tr.occurrence_slots))==(2,2,1)
    assert (x['metrics'].t0_pairings,csp.pairing_terms,calls['n'])==(1,2,3)
    assert x['metrics'].credential_verifications==1
    assert x['metrics'].possession_verifications==1
    assert x['metrics'].publication_verifications==1
    assert x['metrics'].blob_unseals==1
    assert x['metrics'].user_token_prf_count==2
    assert x['metrics'].cap_signatures==1
    assert x['metrics'].cap_verifications==1
    assert x['metrics'].request_consumptions==1
    assert x['metrics'].auth_canonical_bytes==len(authorization_bytes(auth,x['backend']))
    assert x['issue_store'].state(x['backend'].binding.sys_id,x['request'].request_nonce)=='issued'
    assert x['csp_state'].count()==1


def test_authorized_identity_but_unsatisfied_lsss(monkeypatch):
    x=bootstrap(user_labels=('A',));calls=_pair_counter(monkeypatch)
    auth=authorize(x)
    assert x['metrics'].t0_pairings==calls['n']==1
    csp=AlgebraOperationCounts()
    with pytest.raises(Unauthorized):
        csp_transform_verified(auth,x['publication'],x['pp'],x['backend'],
            public_key_bytes(x['cap']),public_key_bytes(x['kgc']),'ns',x['clock'],
            x['csp_state'],counts=csp)
    assert csp.pairing_terms==0 and calls['n']==1
    assert x['csp_state'].count()==1


@pytest.mark.parametrize('mode',('INACTIVE','UNAVAILABLE','STALE'))
def test_state_gate_blocks_before_t0(mode,monkeypatch):
    x=bootstrap(state_mode=mode);calls=_pair_counter(monkeypatch)
    with pytest.raises(StateSynchronizationError): authorize(x)
    assert calls['n']==0 and x['metrics'].t0_pairings==0
    assert x['metrics'].request_issue_rejections==1
    assert x['issue_store'].state(x['backend'].binding.sys_id,x['request'].request_nonce) is None


def test_runtime_default_coordinator_and_missing_clock_fail_closed(monkeypatch):
    x=bootstrap();calls=_pair_counter(monkeypatch)
    x['enclave']=EmulatedAnonymousAuthorizationEnclave(clock=x['clock'])
    with pytest.raises(StateSynchronizationError): authorize(x)
    assert calls['n']==0
    y=bootstrap();calls=_pair_counter(monkeypatch)
    y['enclave']=EmulatedAnonymousAuthorizationEnclave(coordinator=y['coordinator'])
    with pytest.raises(ProtocolRejectedError): authorize(y)
    assert calls['n']==0


@pytest.mark.parametrize('kind',('credential','possession','blob','publication','state'))
def test_invalid_request_rejected_before_t0(kind,monkeypatch):
    x=bootstrap();calls=_pair_counter(monkeypatch)
    if kind in ('credential','possession','blob'):
        # Advance receive sequence; then submit a new encrypted private record.
        x['du_server'].receive(x['private_record'])
        credential,blob,proof=x['credential'],x['blob'],x['proof']
        if kind=='credential': credential=replace(credential,signature=_flip(credential.signature))
        if kind=='possession': proof=replace(proof,challenge_signature=_flip(proof.challenge_signature))
        if kind=='blob': blob=replace(blob,opaque=blob.opaque[:-1]+bytes([blob.opaque[-1]^1]))
        x['private_record']=x['du_client'].send(encode_private_ingress(credential,blob,proof))
    if kind=='publication':
        slots=list(x['publication'].anonymous_filter.slots)
        slots[0]=_flip(slots[0])
        x['publication']=replace(x['publication'],anonymous_filter=replace(
            x['publication'].anonymous_filter,slots=tuple(slots)))
    if kind=='state': x['coordinator'].mode='INACTIVE'
    with pytest.raises((AuthenticationError,ProtocolRejectedError,StateSynchronizationError)):
        authorize(x)
    assert calls['n']==0 and x['metrics'].t0_pairings==0
    assert x['metrics'].request_issue_rejections==1


def test_tee_duplicate_issue_and_csp_concurrent_double_consume(monkeypatch):
    x=bootstrap();calls=_pair_counter(monkeypatch)
    auth=authorize(x)
    assert calls['n']==1
    new_record=x['du_client'].send(encode_private_ingress(x['credential'],x['blob'],x['proof']))
    with pytest.raises(ReplayRejectedError): authorize(x,private_record=new_record)
    assert calls['n']==1 and x['metrics'].request_issue_rejections==1
    state=CSPRequestState()
    def consume(_):
        try:
            verify_and_consume(auth,x['publication'],x['backend'],
                public_key_bytes(x['cap']),public_key_bytes(x['kgc']),'ns',x['clock'],state)
            return True
        except ReplayRejectedError: return False
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(consume,range(2)))==[False,True]
    assert state.count()==1


def test_cross_request_component_substitution_rejected_by_capability():
    x=bootstrap();auth_a=authorize(x)
    new_nonce=b'B'*32
    req_b=replace(x['request'],request_nonce=new_nonce)
    proof_b=sign_possession(x['auth'],x['backend'].binding.sys_id,
                            x['du_client'].binding,req_b.header_digest,new_nonce)
    record_b=x['du_client'].send(encode_private_ingress(x['credential'],x['blob'],proof_b))
    auth_b=authorize(x,request=req_b,private_record=record_b)
    mixed=replace(auth_a,bundle=replace(auth_a.bundle,items=auth_b.bundle.items))
    with pytest.raises(ProtocolRejectedError):
        verify_capability(mixed,x['publication'],x['backend'],
                          public_key_bytes(x['cap']),x['clock'])
    assert auth_a.capability.bundle_digest!=auth_b.capability.bundle_digest


def test_do_tokenization_requires_certificate_and_possession():
    x=bootstrap()
    raw=encode_policy_labels(x['policy_labels'])
    record=x['do_client'].send(raw)
    with pytest.raises(ProtocolRejectedError):
        x['enclave'].tokenize_policy_emulated(record,x['do_server'],
            certificate=x['cert'],do_proof=x['do_proof'],context=x['context'],
            expected_namespace='other',kgc_public_key=public_key_bytes(x['kgc']),
            k_tok=x['k_tok'],backend=x['backend'])
    wrong_proof=sign_do_policy_proof(new_private_key(),x['context'],raw,x['do_client'].binding)
    with pytest.raises(AuthenticationError):
        x['enclave'].tokenize_policy_emulated(record,x['do_server'],
            certificate=x['cert'],do_proof=wrong_proof,context=x['context'],
            expected_namespace='ns',kgc_public_key=public_key_bytes(x['kgc']),
            k_tok=x['k_tok'],backend=x['backend'])
    assert 'requested_attributes' not in inspect.signature(
        EmulatedAnonymousAuthorizationEnclave.authorize_with_state_coordinator).parameters


def test_host_and_auth_field_privacy_boundary():
    forbidden={'uid','rh_id','mu','mu_q','delta_q','k0','k0_q','credential',
               'credential_digest','blob','blob_digest','attributes','plaintext_s_id'}
    for cls in (EmulatedHostRequest,AuthorizationBundle,EphemeralTokenComponent,
                SignedCapability,TEEAuthorization):
        assert not forbidden.intersection(f.name.lower() for f in fields(cls))
    x=bootstrap();auth=authorize(x)
    public_repr=repr(auth)+repr(x['request'])+repr(x['private_record'])+repr(x['metrics'])
    for secret in ('PRIVATE-UID','MYABE08.SealedUserV1','credential_digest','uid_handle'):
        assert secret not in public_repr
    raw=authorization_bytes(auth,x['backend'])
    assert b'PRIVATE-UID' not in raw
    assert x['credential'].uid not in repr(x['request'])
    from core.myabe08.credential import credential_digest
    private_markers=(x['credential'].uid.encode(),credential_digest(x['credential']),
                     x['blob'].opaque,x['backend'].serialize_g2(x['base'].k0))
    assert all(marker not in raw for marker in private_markers)
    def field_names(value):
        if hasattr(value,'__dataclass_fields__'):
            return {f.name.lower() for f in fields(value)} | set().union(
                *(field_names(getattr(value,f.name)) for f in fields(value)))
        if isinstance(value,(tuple,list)):
            return set().union(*(field_names(item) for item in value))
        return set()
    assert not forbidden.intersection(field_names(auth)|field_names(x['request']))


def test_du_local_request_state_rejects_changed_response_binding():
    x=bootstrap();auth=authorize(x)
    x['du_request_state'].verify_response_binding(x['request'],auth)
    with pytest.raises(ProtocolRejectedError):
        x['du_request_state'].verify_response_binding(
            replace(x['request'],expiry=x['request'].expiry+1),auth)
    with pytest.raises(ProtocolRejectedError):
        x['du_request_state'].verify_response_binding(x['request'],replace(
            auth,capability=replace(auth.capability,request_nonce=b'Z'*32)))
