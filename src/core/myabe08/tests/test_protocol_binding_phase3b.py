"""Ed25519 credential/publication/capability and software sealing negatives."""
from dataclasses import replace
import hashlib

import pytest

from core.myabe08.capability import (bundle_bytes,bundle_digest,verify_capability,
    verify_and_consume,from_ephemeral,sign_capability)
from core.myabe08.credential import (CredentialVersionRegistry,certified_user_tokens,
    credential_digest,issue_credential,sign_possession,verify_credential,verify_possession)
from core.myabe08.crypto import BLS12381Backend
from core.myabe08.errors import AuthenticationError,ContractError,ProtocolRejectedError,ReplayRejectedError
from core.myabe08.publication import (core_components_digest,filter_digest,
    indexed_bytes,verify_do_certificate,verify_publication)
from core.myabe08.sealing import EmulatedSealingService
from core.myabe08.encoding import StructuredRecord, decode, encode
from core.myabe08.crypto import AES256GCMSIV
from core.myabe08.profile import EMULATED_TEE_PROFILE
from core.myabe08.signing import new_private_key,public_key_bytes
from core.myabe08.state import CSPRequestState
from core.myabe08.tests.protocol_fixtures import (DeterministicTestClock,SYS_ID,
    authorize,bootstrap)
from core.myabe08.types import Attribute,Validity


@pytest.fixture(scope='module')
def env(): return bootstrap()


def _flip(data): return bytes([data[0]^1])+data[1:]


def test_credentials_signature_validity_version_and_possession(env):
    x=env;c=x['credential'];pk=public_key_bytes(x['kgc'])
    assert verify_credential(pk,c,SYS_ID,x['registry'],x['clock'])==c
    for key,credential,sysid,clock in [
        (public_key_bytes(new_private_key()),c,SYS_ID,x['clock']),
        (pk,replace(c,signature=_flip(c.signature)),SYS_ID,x['clock']),
        (pk,c,b'OTHER',x['clock']),
        (pk,c,SYS_ID,DeterministicTestClock(2000)),
        (pk,c,SYS_ID,DeterministicTestClock(99)),
    ]:
        with pytest.raises((AuthenticationError,ProtocolRejectedError)):
            verify_credential(key,credential,sysid,x['registry'],clock)
    with pytest.raises(ContractError):
        issue_credential(x['kgc'],SYS_ID,'UID',(c.attributes[0],c.attributes[0]),
                         Validity(100,2000),1,c.pk_auth)
    with pytest.raises(ContractError):
        issue_credential(x['kgc'],SYS_ID,'UID',
            (Attribute('ns','label','e\u0301'),),Validity(100,2000),1,c.pk_auth)
    proof=sign_possession(x['auth'],SYS_ID,x['du_client'].binding,
                          x['request'].header_digest,x['request'].request_nonce)
    verify_possession(c,proof,x['du_server'].binding,x['request'].header_digest,
                      x['request'].request_nonce)
    stolen=sign_possession(new_private_key(),SYS_ID,x['du_client'].binding,
                          x['request'].header_digest,x['request'].request_nonce)
    with pytest.raises(AuthenticationError):
        verify_possession(c,stolen,x['du_server'].binding,
                          x['request'].header_digest,x['request'].request_nonce)
    with pytest.raises(AuthenticationError):
        verify_possession(c,proof,x['du_server'].binding,b'X'*32,
                          x['request'].request_nonce)
    renewed=issue_credential(x['kgc'],SYS_ID,c.uid,c.attributes,c.validity,2,c.pk_auth)
    registry=CredentialVersionRegistry();registry.register(c);registry.register(renewed)
    with pytest.raises(ProtocolRejectedError):
        verify_credential(pk,c,SYS_ID,registry,x['clock'])
    assert verify_credential(pk,renewed,SYS_ID,registry,x['clock'])==renewed
    assert certified_user_tokens(c,x['k_tok'],x['context'].policy_context_id,1)==tuple(sorted(set(x['tokens'])))


def test_do_cert_and_complete_publication_digest_binding(env):
    x=env;ct=x['publication'];b=x['backend'];pk=public_key_bytes(x['kgc'])
    assert verify_publication(ct,b,pk,'ns',x['clock'])
    with pytest.raises(ProtocolRejectedError):
        verify_do_certificate(x['cert'],pk,SYS_ID,'other',x['clock'])
    with pytest.raises(ProtocolRejectedError):
        verify_do_certificate(x['cert'],pk,SYS_ID,'ns',DeterministicTestClock(2000))
    with pytest.raises(AuthenticationError):
        verify_do_certificate(x['cert'],public_key_bytes(new_private_key()),
                              SYS_ID,'ns',x['clock'])
    with pytest.raises(AuthenticationError):
        verify_publication(replace(ct,publisher_certificate=replace(x['cert'],
            kgc_signature=_flip(x['cert'].kgc_signature))),b,pk,'ns',x['clock'])
    with pytest.raises(AuthenticationError):
        verify_publication(replace(ct,publication_signature=_flip(ct.publication_signature)),
                           b,pk,'ns',x['clock'])
    wrong_do=replace(x['cert'],publisher_public_key=public_key_bytes(new_private_key()))
    with pytest.raises(AuthenticationError):
        verify_publication(replace(ct,publisher_certificate=wrong_do),b,pk,'ns',x['clock'])
    assert indexed_bytes((b'a',b'b'))!=indexed_bytes((b'b',b'a'))
    assert core_components_digest(ct.row_components,ct.occurrence_components,b)!=\
           core_components_digest(ct.row_components[::-1],ct.occurrence_components,b)
    slots=list(ct.anonymous_filter.slots);slots[0]=_flip(slots[0])
    bad_filter=replace(ct.anonymous_filter,slots=tuple(slots))
    variants=[
        replace(ct,header=replace(ct.header,data_id=b'OTHER')),
        replace(ct,anonymous_filter=bad_filter),
        replace(ct,row_components=(x['pp'].g1,)+ct.row_components[1:]),
        replace(ct,occurrence_components=(x['pp'].g2,)+ct.occurrence_components[1:]),
        replace(ct,row_components=ct.row_components[::-1]),
        replace(ct,occurrence_components=ct.occurrence_components[::-1]),
        replace(ct,dem_nonce=_flip(ct.dem_nonce)),
        replace(ct,encrypted_message=_flip(ct.encrypted_message)),
    ]
    for bad in variants:
        with pytest.raises((AuthenticationError,ProtocolRejectedError,ContractError)):
            verify_publication(bad,b,pk,'ns',x['clock'])
    assert filter_digest(ct.anonymous_filter)!=filter_digest(bad_filter)


def test_software_seal_binding_and_renewal(env):
    x=env;blob=x['blob'];credential=x['credential']
    base=x['sealing'].unseal(blob,credential)
    assert base.uid_handle==credential.uid and base.mu==x['base'].mu
    assert len(blob.opaque)>28
    assert x['sealing'].seal(x['private_base']).opaque!=blob.opaque
    wrong=EmulatedSealingService(b'W'*32,x['backend'])
    with pytest.raises(AuthenticationError): wrong.unseal(blob,credential)
    with pytest.raises(AuthenticationError):
        x['sealing'].unseal(replace(blob,opaque=blob.opaque[:-1]+bytes([blob.opaque[-1]^1])),credential)
    other_backend=BLS12381Backend(b'OTHER-SYS')
    with pytest.raises(AuthenticationError):
        EmulatedSealingService(x['k_seal'],other_backend).unseal(blob,credential)
    with pytest.raises(ContractError):
        EmulatedSealingService(x['k_seal'],x['backend'],schema_version='OTHER')
    nonce,encrypted=blob.opaque[:12],blob.opaque[12:]
    ad=encode(('MYABE-SEAL',SYS_ID,EMULATED_TEE_PROFILE,x['sealing'].schema_version))
    plaintext=AES256GCMSIV().decrypt(x['k_seal'],nonce,encrypted,ad)
    record=decode(plaintext)
    assert isinstance(record,StructuredRecord)
    fields=tuple((name,'OTHER-SCHEMA' if name=='schema_version' else value)
                 for name,value in record.fields)
    malformed=encode(StructuredRecord(record.schema,fields))
    bad_blob=replace(blob,opaque=nonce+AES256GCMSIV().encrypt(
        x['k_seal'],nonce,malformed,ad))
    with pytest.raises(ContractError): x['sealing'].unseal(bad_blob,credential)
    changed=replace(credential,credential_version=2)
    with pytest.raises(ProtocolRejectedError): x['sealing'].unseal(blob,changed)
    changed2=replace(credential,signature=_flip(credential.signature))
    with pytest.raises(ProtocolRejectedError): x['sealing'].unseal(blob,changed2)
    renewed=issue_credential(x['kgc'],SYS_ID,credential.uid,credential.attributes,
                             credential.validity,2,credential.pk_auth)
    with pytest.raises(ProtocolRejectedError): x['sealing'].unseal(blob,renewed)
    new_base=replace(base,credential_digest=credential_digest(renewed),credential_version=2)
    new_blob=x['sealing'].seal(new_base)
    with pytest.raises(ProtocolRejectedError): x['sealing'].unseal(new_blob,credential)


def test_capability_binds_every_material_field(env):
    x=env;auth=authorize(x);b=x['backend'];ct=x['publication']
    cap_pk=public_key_bytes(x['cap'])
    assert verify_capability(auth,ct,b,cap_pk,x['clock'])==auth
    with pytest.raises(AuthenticationError):
        verify_capability(auth,ct,b,public_key_bytes(new_private_key()),x['clock'])
    cap=auth.capability
    for field,value in [('signature',_flip(cap.signature)),('header_digest',b'X'*32),
                        ('ctx_priv',b'Y'*32),('rev_version',cap.rev_version+1),
                        ('request_nonce',b'Z'*32),('expiry',cap.expiry+1)]:
        with pytest.raises((AuthenticationError,ProtocolRejectedError,ContractError)):
            verify_capability(replace(auth,capability=replace(cap,**{field:value})),
                              ct,b,cap_pk,x['clock'])
    item=auth.bundle.items[0]
    changed_items=[
        (replace(item,token=b'Z'*32),)+auth.bundle.items[1:],
        (replace(item,k_tau_q=x['pp'].g1),)+auth.bundle.items[1:],
    ]
    for items in changed_items:
        with pytest.raises((AuthenticationError,ProtocolRejectedError,ContractError)):
            verify_capability(replace(auth,bundle=replace(auth.bundle,items=items)),
                              ct,b,cap_pk,x['clock'])
    for field,value in [('k1_q',x['pp'].g2),('t0_q',x['pp'].gt_alpha)]:
        with pytest.raises((AuthenticationError,ProtocolRejectedError,ContractError)):
            verify_capability(replace(auth,bundle=replace(auth.bundle,**{field:value})),
                              ct,b,cap_pk,x['clock'])
    with pytest.raises(ContractError):
        bundle_bytes(replace(auth.bundle,items=auth.bundle.items[::-1]),b)
    x['clock'].value=1500
    with pytest.raises(ProtocolRejectedError): verify_capability(auth,ct,b,cap_pk,x['clock'])
    x['clock'].value=1000
    state=CSPRequestState()
    verify_and_consume(auth,ct,b,cap_pk,public_key_bytes(x['kgc']),'ns',x['clock'],state)
    with pytest.raises(ReplayRejectedError):
        verify_and_consume(auth,ct,b,cap_pk,public_key_bytes(x['kgc']),'ns',x['clock'],state)
