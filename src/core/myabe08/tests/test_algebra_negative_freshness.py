"""Negative algebra instances and secure-randomness call-path checks."""
from dataclasses import replace

import pytest

from core.myabe08.algebra import (AlgebraOperationCounts, UserRecoveryScalar,
    derive_ephemeral_algebra, encrypt_algebra_core, finaldec_algebra_core,
    keygen_algebra_core, setup_algebra_core, transform_algebra_core)
from core.myabe08.crypto import BLS12381Backend
from core.myabe08.errors import Unauthorized
from core.myabe08.tests.algebra_fixtures import (SYS_ID, ScalarQueue, policy,
                                                 run_case, token)


@pytest.fixture(scope='module')
def case():
    return run_case(('A','B'),((1,1),(0,-1)),('A','B'),2)


def transform_with(case,bundle):
    return transform_algebra_core(case['pp'],case['ct'],bundle,case['index'],
        case['header'],case['ctx_af'],case['backend'])


def test_cross_request_component_mixing_does_not_recover_e(case):
    x=case; b=x['backend']
    other=derive_ephemeral_algebra(x['pp'],x['base'],x['bundle'].tokens,x['ct'].c,b,
        scalar_source=ScalarQueue(b,[41]))
    mixed=replace(x['bundle'],k_tau_q=other.k_tau_q)
    ta=transform_with(x,mixed).t_a
    _,recovered=finaldec_algebra_core(mixed.t0_q,ta,x['recovery'],b)
    assert recovered!=x['ct'].e
    mixed2=replace(x['bundle'],k1_q=other.k1_q)
    ta2=transform_with(x,mixed2).t_a
    assert finaldec_algebra_core(mixed2.t0_q,ta2,x['recovery'],b)[1]!=x['ct'].e


def test_cross_user_component_mixing_and_wrong_rk(case):
    x=case; b=x['backend']
    base_b,rk_b=keygen_algebra_core(x['pp'],x['msk'],b,
                                     scalar_source=ScalarQueue(b,[43,47]))
    bundle_b=derive_ephemeral_algebra(x['pp'],base_b,x['bundle'].tokens,x['ct'].c,b,
                                      scalar_source=ScalarQueue(b,[53]))
    mixed=replace(x['bundle'],k1_q=bundle_b.k1_q,k_tau_q=bundle_b.k_tau_q)
    ta=transform_with(x,mixed).t_a
    assert finaldec_algebra_core(mixed.t0_q,ta,x['recovery'],b)[1]!=x['ct'].e
    assert finaldec_algebra_core(mixed.t0_q,ta,rk_b,b)[1]!=x['ct'].e
    assert finaldec_algebra_core(x['bundle'].t0_q,x['tr'].t_a,rk_b,b)[1]!=x['ct'].e


def test_cross_context_miss_precedes_csp_pairing(case):
    x=case; b=x['backend']
    context_y=b'POLICY-CONTEXT-DIFFERENT-0000000'
    y_tokens=tuple(token(label,context_y) for label in ('A','B'))
    assert y_tokens[0]!=token('A')
    bundle_y=derive_ephemeral_algebra(x['pp'],x['base'],y_tokens,x['ct'].c,b,
                                      scalar_source=ScalarQueue(b,[59]))
    csp=AlgebraOperationCounts()
    with pytest.raises(Unauthorized):
        transform_algebra_core(x['pp'],x['ct'],bundle_y,x['index'],x['header'],
                               x['ctx_af'],b,counts=csp)
    assert csp.pairing_terms==0


def test_unauthorized_j_rejects_before_attribute_pairing(case):
    x=case; b=x['backend']
    tee,csp=AlgebraOperationCounts(),AlgebraOperationCounts()
    only_a=derive_ephemeral_algebra(x['pp'],x['base'],(token('A'),),x['ct'].c,b,
                                    scalar_source=ScalarQueue(b,[61]),counts=tee)
    with pytest.raises(Unauthorized):
        transform_algebra_core(x['pp'],x['ct'],only_a,x['index'],x['header'],
                               x['ctx_af'],b,counts=csp)
    assert (tee.pairing_terms,csp.pairing_terms)==(1,0)


def test_fresh_encrypt_and_ephemeral_randomness_observed(monkeypatch):
    b=BLS12381Backend(SYS_ID)
    pp,msk=setup_algebra_core(b,3)
    base,rk=keygen_algebra_core(pp,msk,b)
    matrix,tokens,ranks,header,ctx,index=policy(b,('A','B','A'),((1,),(1,),(1,)),3)
    calls={'n':0}
    from core.myabe08 import crypto
    original=crypto.secrets.randbelow
    def counted(n):
        calls['n']+=1
        return original(n)
    monkeypatch.setattr(crypto.secrets,'randbelow',counted)
    first=encrypt_algebra_core(pp,matrix,tokens,b)
    second=encrypt_algebra_core(pp,matrix,tokens,b)
    assert calls['n']>=8  # fresh s plus each r_j, for each ciphertext
    assert len(first.d_j)==len(second.d_j)==3
    assert all(a!=c for a,c in zip(first.d_j,second.d_j))
    assert all(a!=c for a,c in zip(first.c_i,second.c_i))
    assert first.c!=second.c and first.e!=second.e
    q1=derive_ephemeral_algebra(pp,base,(token('A'),),first.c,b)
    q2=derive_ephemeral_algebra(pp,base,(token('A'),),first.c,b)
    assert q1.k1_q!=q2.k1_q and q1.t0_q!=q2.t0_q


def test_injected_scalar_source_reproduces_ciphertext():
    b=BLS12381Backend(SYS_ID)
    pp,msk=setup_algebra_core(b,2,scalar_source=ScalarQueue(b,[7,11]))
    matrix,tokens,_,_,_,_=policy(b,('A','B'),((1,1),(0,-1)),2)
    sequence=[19,5,23,29]
    first=encrypt_algebra_core(pp,matrix,tokens,b,scalar_source=ScalarQueue(b,sequence))
    second=encrypt_algebra_core(pp,matrix,tokens,b,scalar_source=ScalarQueue(b,sequence))
    assert first==second
    third=encrypt_algebra_core(pp,matrix,tokens,b,scalar_source=ScalarQueue(b,[41,43,47,53]))
    assert first!=third and all(a!=c for a,c in zip(first.d_j,third.d_j))
