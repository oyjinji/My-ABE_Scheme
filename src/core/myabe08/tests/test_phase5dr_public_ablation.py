"""Explicit EMULATED TEST public E2E for the row-independent internal ablation."""
from dataclasses import replace

import pytest

from core.myabe08.algebra import UserRecoveryScalar
from core.myabe08.crypto import compute_ctx_priv
from core.myabe08.errors import MyABE08Error, Unauthorized, UnsupportedProfileError
from core.myabe08.profile import (EMULATED_TEE_PROFILE, SGX_DEBUG_GRAMINE_V1,
    MYABE08_ROW_ABLATION_ENCODING_V1)
from core.myabe08.public import (EMULATED_TEST_MODE, PublicMyABE08,
    parse_authorization, parse_ciphertext, parse_partial,
    serialize_authorization, serialize_ciphertext, serialize_partial)
from core.myabe08.real_tee.attested_session import FEASIBILITY_MODE
from core.myabe08.real_tee.identity_policy import SgxIdentityPolicy
from core.myabe08.revocation import ACTIVATE, REVOKE
from core.myabe08.signing import new_private_key, public_key_bytes
from core.myabe08.types import Attribute, PolicyContext, PolicyInput, Validity

SYS_ID=b'MYABE08-ROW-ABLATION-TEST'


class Clock:
    def now(self): return 1000


def attr(name): return Attribute('ns','label',name)


def context(index):
    identity=bytes([index])*32
    return PolicyContext(SYS_ID,identity,1,compute_ctx_priv(SYS_ID,identity,1))


CASES=(
    (('A',),((1,),),('A',),1),
    (('A','B'),((1,1),(0,-1)),('A','B'),1),
    (('A','B'),((1,),(1,)),('B',),1),
    (('A','B','C'),((1,1),(1,2),(1,3)),('A','C'),1),
    (('A','B','C','D','E'),
     ((1,1,1),(1,2,4),(1,3,9),(1,4,16),(1,5,25)),('A','C','E'),1),
    (('A','B','A','C','A'),
     ((0,0),(0,0),(1,1),(0,0),(0,-1)),('A',),3),
    (('A',)*8,((1,),)*8,('A',),8),
)


@pytest.mark.parametrize('labels,rows,user_labels,cmax',CASES)
def test_row_public_e2e_and_wire_roundtrip(tmp_path,labels,rows,user_labels,cmax):
    scheme=PublicMyABE08(sys_id=SYS_ID,namespace='ns',backend=EMULATED_TEE_PROFILE,
        experiment_trust_mode=EMULATED_TEST_MODE,state_path=tmp_path/'state',
        clock=Clock(),component_allocation='ROW')
    setup=scheme.Setup(c_max=cmax,validity=Validity(100,2000))
    assert setup.metadata['InternalAblation']=='MYABE08_NO_OCCURRENCE_REUSE_V1'
    holder=new_private_key()
    user=scheme.KeyGen(uid='PRIVATE-ROW-USER',attributes=tuple(attr(x) for x in sorted(set(user_labels))),
        auth_public_key=public_key_bytes(holder),validity=Validity(100,2000))
    ct=scheme.Encrypt(message=b'row ablation E2E',
        policy=PolicyInput(rows,tuple(attr(x) for x in labels)),
        context=context(1),data_id=b'row-ablation')
    assert len(ct.occurrence_components)==len(labels)
    assert ct.header.c_max==cmax
    assert ct.header.kem_dem_info.profile.encoding_version==MYABE08_ROW_ABLATION_ENCODING_V1
    raw=serialize_ciphertext(ct,scheme.crypto)
    assert serialize_ciphertext(parse_ciphertext(raw,scheme.crypto,
        expected_profile=EMULATED_TEE_PROFILE),scheme.crypto)==raw
    auth=scheme.TEEAuthorize(user=user,ciphertext=ct,
        auth_private_key=holder,expiry=1500)
    auth_raw=serialize_authorization(auth,ct,scheme.crypto)
    assert serialize_authorization(parse_authorization(auth_raw,ct,scheme.crypto,
        expected_profile=EMULATED_TEE_PROFILE),ct,scheme.crypto)==auth_raw
    with pytest.raises(MyABE08Error):
        parse_ciphertext(raw+b'\x00',scheme.crypto,
            expected_profile=EMULATED_TEE_PROFILE)
    with pytest.raises(MyABE08Error):
        parse_ciphertext(raw,scheme.crypto,
            expected_profile=SGX_DEBUG_GRAMINE_V1)
    changed=replace(ct,occurrence_components=(setup.pp.g2,)+ct.occurrence_components[1:])
    if changed!=ct:
        with pytest.raises(MyABE08Error):
            scheme.Transform(ciphertext=changed,public_auth=auth)
    partial=scheme.Transform(ciphertext=ct,public_auth=auth)
    partial_raw=serialize_partial(partial,scheme.crypto)
    assert serialize_partial(parse_partial(partial_raw,scheme.crypto,
        expected_profile=EMULATED_TEE_PROFILE),scheme.crypto)==partial_raw
    assert scheme.FinalDec(partial=partial,recovery_key=user.recovery_key)==b'row ablation E2E'
    assert auth.tee_pairings==1
    assert partial.csp_pairings==1+len(partial.reconstruction_rows)
    wrong=UserRecoveryScalar(scheme.crypto.binding,scheme.crypto.scalar_from_int(2))
    if wrong!=user.recovery_key:
        with pytest.raises(MyABE08Error):
            scheme.FinalDec(partial=partial,recovery_key=wrong)


def test_row_public_unauthorized_tamper_revocation_and_profile(tmp_path):
    with pytest.raises(UnsupportedProfileError):
        PublicMyABE08(sys_id=SYS_ID,namespace='ns',backend=SGX_DEBUG_GRAMINE_V1,
            experiment_trust_mode=FEASIBILITY_MODE,state_path=tmp_path/'bad',
            clock=Clock(),component_allocation='ROW',test_tee_bootstrap=True,
            identity_policy=SgxIdentityPolicy('row-test',SGX_DEBUG_GRAMINE_V1,
                mrenclave=b'\x01'*32,allow_debug=True))
    scheme=PublicMyABE08(sys_id=SYS_ID,namespace='ns',backend=EMULATED_TEE_PROFILE,
        experiment_trust_mode=EMULATED_TEST_MODE,state_path=tmp_path/'state',
        clock=Clock(),component_allocation='ROW')
    scheme.Setup(c_max=1,validity=Validity(100,2000))
    holder=new_private_key()
    user=scheme.KeyGen(uid='PRIVATE-ROW-USER',attributes=(attr('A'),),
        auth_public_key=public_key_bytes(holder),validity=Validity(100,2000))
    ct=scheme.Encrypt(message=b'row protected',
        policy=PolicyInput(((1,1),(0,-1)),(attr('A'),attr('B'))),
        context=context(2),data_id=b'row-ablation')
    auth=scheme.TEEAuthorize(user=user,ciphertext=ct,
        auth_private_key=holder,expiry=1500)
    with pytest.raises(Unauthorized):
        scheme.Transform(ciphertext=ct,public_auth=auth)
    with pytest.raises(MyABE08Error):
        scheme.TEEAuthorize(user=user,ciphertext=replace(ct,header=replace(ct.header,
            data_id=b'tampered')),auth_private_key=holder,expiry=1500)
    update=scheme.Rev(uid='PRIVATE-ROW-USER',operation=REVOKE)
    assert scheme.RevStateUpt(update).version==1
    with pytest.raises(MyABE08Error):
        scheme.TEEAuthorize(user=user,ciphertext=ct,
            auth_private_key=holder,expiry=1500)
    update=scheme.Rev(uid='PRIVATE-ROW-USER',operation=ACTIVATE)
    assert scheme.RevStateUpt(update).version==2
    auth=scheme.TEEAuthorize(user=user,ciphertext=ct,
        auth_private_key=holder,expiry=1500)
    with pytest.raises(Unauthorized):
        scheme.Transform(ciphertext=ct,public_auth=auth)


def test_row_public_historical_auth_survives_revoke_but_new_auth_blocked(tmp_path):
    scheme=PublicMyABE08(sys_id=SYS_ID,namespace='ns',backend=EMULATED_TEE_PROFILE,
        experiment_trust_mode=EMULATED_TEST_MODE,state_path=tmp_path/'state',
        clock=Clock(),component_allocation='ROW')
    scheme.Setup(c_max=1,validity=Validity(100,2000))
    holder=new_private_key()
    user=scheme.KeyGen(uid='PRIVATE-ROW-HISTORY',attributes=(attr('A'),),
        auth_public_key=public_key_bytes(holder),validity=Validity(100,2000))
    ct=scheme.Encrypt(message=b'historical row request',
        policy=PolicyInput(((1,),),(attr('A'),)),
        context=context(3),data_id=b'row-history')
    old_auth=scheme.TEEAuthorize(user=user,ciphertext=ct,
        auth_private_key=holder,expiry=1500)
    update=scheme.Rev(uid='PRIVATE-ROW-HISTORY',operation=REVOKE)
    assert scheme.RevStateUpt(update).version==1
    partial=scheme.Transform(ciphertext=ct,public_auth=old_auth)
    assert scheme.FinalDec(partial=partial,recovery_key=user.recovery_key)==b'historical row request'
    with pytest.raises(MyABE08Error):
        scheme.Transform(ciphertext=ct,public_auth=old_auth)
    with pytest.raises(MyABE08Error):
        scheme.TEEAuthorize(user=user,ciphertext=ct,
            auth_private_key=holder,expiry=1500)
    update=scheme.Rev(uid='PRIVATE-ROW-HISTORY',operation=ACTIVATE)
    assert scheme.RevStateUpt(update).version==2
    auth=scheme.TEEAuthorize(user=user,ciphertext=ct,
        auth_private_key=holder,expiry=1500)
    restored=scheme.Transform(ciphertext=ct,public_auth=auth)
    assert scheme.FinalDec(partial=restored,recovery_key=user.recovery_key)==b'historical row request'
