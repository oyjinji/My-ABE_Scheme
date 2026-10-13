"""Identity predicate unit tests; they do not validate any SGX quote."""
import pytest

from core.myabe08.errors import ContractError
from core.myabe08.real_tee.identity_policy import SgxIdentityPolicy

M=b'M'*32
S=b'S'*32
FIELDS=dict(profile_id='SGX_DEBUG_GRAMINE_V1',mrenclave=M,mrsigner=S,
            product_id=7,svn=4,debug=True)


def test_exact_identity_and_debug_default():
    policy=SgxIdentityPolicy('deployment-v1','SGX_DEBUG_GRAMINE_V1',mrenclave=M)
    assert not policy.check_authenticated_fields(**FIELDS)
    debug_policy=SgxIdentityPolicy('test-deployment-v1','SGX_DEBUG_GRAMINE_V1',
                                    mrenclave=M,allow_debug=True)
    assert debug_policy.check_authenticated_fields(**FIELDS)
    for changes in ({'mrenclave':b'X'*32},{'profile_id':'OTHER'}):
        assert not debug_policy.check_authenticated_fields(**dict(FIELDS,**changes))


def test_signer_policy_requires_product_and_svn():
    with pytest.raises(ContractError):
        SgxIdentityPolicy('bad','SGX_DEBUG_GRAMINE_V1',mrsigner=S)
    with pytest.raises(ContractError):
        SgxIdentityPolicy('bad','SGX_DEBUG_GRAMINE_V1',mrenclave=M,mrsigner=S,
                          product_id=7,min_svn=4)
    policy=SgxIdentityPolicy('deployment-v1','SGX_DEBUG_GRAMINE_V1',
        mrsigner=S,product_id=7,min_svn=4,allow_debug=True)
    assert policy.check_authenticated_fields(**FIELDS)
    for changes in ({'mrsigner':b'X'*32},{'product_id':8},{'svn':3},
                    {'profile_id':'OTHER'}):
        assert not policy.check_authenticated_fields(**dict(FIELDS,**changes))
