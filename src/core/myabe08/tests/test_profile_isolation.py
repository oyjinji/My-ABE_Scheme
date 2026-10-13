from dataclasses import replace
import pytest
from core.myabe08.crypto import BLS12381Backend
from core.myabe08.errors import ContractError, BackendValidationError, UnsupportedProfileError
from core.myabe08.profile import (
    ProfileMeta, SECURITY_PROFILE_BLS12_381, FABEO_COMPAT_PROFILE, MYABE08_ENCODING_V1,
)


def test_profile_identity_fields_and_cross_profile_rejection():
    meta=ProfileMeta(SECURITY_PROFILE_BLS12_381,'BLS12-381','py_ecc-8.0.0')
    assert meta.encoding_profile_id==MYABE08_ENCODING_V1
    for changes in [dict(curve_id='MNT224'),dict(backend_id='other'),
                    dict(security_profile_id='unknown'),dict(encoding_profile_id='OTHER')]:
        with pytest.raises(UnsupportedProfileError):replace(meta,**changes)
    compat=ProfileMeta(FABEO_COMPAT_PROFILE,'MNT224','Charm-Crypto/PBC (candidate)')
    with pytest.raises(UnsupportedProfileError):BLS12381Backend(b'sys',profile_meta=compat)


def test_cross_sysid_arithmetic_and_import_rejected():
    a,b=BLS12381Backend(b'sys-a'),BLS12381Backend(b'sys-b')
    for call in [
        lambda:a.pair(a.g1_generator(),b.g2_generator()),
        lambda:a.g1_add(a.g1_generator(),b.g1_generator()),
        lambda:a.g2_mul(a.g2_generator(),b.scalar_from_int(1)),
        lambda:a.scalar_add(a.scalar_from_int(1),b.scalar_from_int(1)),
        lambda:a.deserialize_g1(b.g1_generator().encoded,binding=b.binding),
        lambda:a.hash_to_g1(bytes(32),binding=b.binding),
    ]:
        with pytest.raises(BackendValidationError):call()
    for change in [dict(curve_id='MNT224'),dict(backend_id='other'),
                   dict(security_profile_id=FABEO_COMPAT_PROFILE),dict(encoding_profile_id='old')]:
        with pytest.raises(ContractError):replace(a.binding,**change)
