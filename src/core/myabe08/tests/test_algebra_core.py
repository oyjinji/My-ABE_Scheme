"""Real BLS12-381 algebra formulas and trust-domain structure."""
from dataclasses import fields

import pytest

from core.myabe08.algebra import (AlgebraOperationCounts, UserAlgebraBaseState,
    UserRecoveryScalar, EncryptCoreResult, EphemeralAlgebraBundle,
    derive_ephemeral_algebra, encrypt_algebra_core, keygen_algebra_core,
    pairing_summary, setup_algebra_core)
from core.myabe08.crypto import BLS12381Backend
from core.myabe08.errors import ContractError
from core.myabe08.lsss import LSSSMatrix
from core.myabe08.tests.algebra_fixtures import ScalarQueue, SYS_ID, token, run_case


def fixed_case():
    backend=BLS12381Backend(SYS_ID)
    setup=ScalarQueue(backend,[7,11])
    keygen=ScalarQueue(backend,[13,17])
    encrypt=ScalarQueue(backend,[19,5,23,29])
    ephemeral=ScalarQueue(backend,[37])
    case=run_case(('A','B'),((1,1),(0,-1)),('A','B'),2,
        sources={'setup':setup,'keygen':keygen,'encrypt':encrypt,'ephemeral':ephemeral})
    assert all(not s.values for s in (setup,keygen,encrypt,ephemeral))
    assert setup.calls==[(True,7),(True,11)]
    assert keygen.calls==[(True,13),(True,17)]
    assert encrypt.calls==[(True,19),(False,5),(True,23),(True,29)]
    assert ephemeral.calls==[(True,37)]
    return case


def test_fixed_setup_keygen_encrypt_ephemeral_and_final_formulas():
    x=fixed_case(); b=x['backend']; pp=x['pp']; msk=x['msk']; base=x['base']; rk=x['recovery']
    ct=x['ct']; bundle=x['bundle']; tr=x['tr']; p=b.scalar_order
    sc=lambda v:b.scalar_from_int(v%p)
    gt=b.pair(pp.g1,pp.g2)
    assert b.serialize_scalar(msk.alpha)==sc(7).encoded
    assert b.serialize_scalar(msk.a)==sc(11).encoded
    assert pp.g1_a==b.g1_mul(pp.g1,sc(11))
    assert pp.g2_a==b.g2_mul(pp.g2,sc(11))
    assert pp.gt_alpha==b.gt_pow(gt,sc(7))
    assert b.pair(pp.g1_a,pp.g2)==b.pair(pp.g1,pp.g2_a)==b.gt_pow(gt,sc(11))
    assert b.g2_mul(pp.g2_a,sc(37))==b.g2_mul(pp.g2,sc(11*37))
    assert base.mu==sc(17)
    assert base.k0==b.g2_mul(pp.g2,sc(13*7+11*17))
    assert rk.rk==sc(pow(13,-1,p))
    assert len(ct.c_i)==2 and len(ct.d_j)==2  # rank 2 unused, still sampled
    assert x['ranks']==(1,1)
    for row,tok,lam in zip((0,1),x['tokens'],(19+5,-5)):
        q=b.hash_to_g1(tok)
        expected=b.g1_add(b.g1_mul(pp.g1_a,sc(lam)),b.g1_mul(q,sc(-23)))
        assert ct.c_i[row]==expected
    assert ct.d_j==(b.g2_mul(pp.g2,sc(23)),b.g2_mul(pp.g2,sc(29)))
    assert ct.c==b.g1_mul(pp.g1,sc(19))
    assert ct.e==b.gt_pow(gt,sc(7*19))
    mu_q=17+37
    assert bundle.k1_q==b.g2_mul(pp.g2,sc(mu_q))
    assert bundle.k_tau_q==tuple(b.g1_mul(b.hash_to_g1(t),sc(mu_q)) for t in bundle.tokens)
    k0_q=b.g2_add(base.k0,b.g2_mul(pp.g2_a,sc(37)))
    assert k0_q==b.g2_mul(pp.g2,sc(13*7+11*mu_q))
    assert bundle.t0_q==b.pair(ct.c,k0_q)==b.gt_pow(gt,sc((13*7+11*mu_q)*19))
    assert tr.t_a==b.gt_pow(gt,sc(11*mu_q*19))
    assert x['quotient']==b.gt_pow(gt,sc(13*7*19))
    assert x['recovered']==ct.e
    assert x['setup_counts'].pairing_terms==1
    assert x['enc_counts'].g1_exponentiations==5
    assert x['enc_counts'].g2_exponentiations==2
    assert x['enc_counts'].g1_multiplications==2
    assert x['csp_counts'].g1_exponentiations==4
    assert x['csp_counts'].g1_multiplications==2
    assert x['csp_counts'].gt_multiplications==1
    assert x['final_counts'].pairing_terms==0
    assert x['final_counts'].gt_divisions==1
    assert x['final_counts'].gt_exponentiations==1
    assert pairing_summary(x['tee_counts'],x['csp_counts']).system_pairing_terms==3


def test_separate_state_types_and_no_long_lived_secret_in_public_results():
    assert set(f.name for f in fields(UserAlgebraBaseState))=={'binding','mu','k0'}
    assert set(f.name for f in fields(UserRecoveryScalar))=={'binding','rk'}
    from core.myabe08.algebra import AlgebraPublicParameters
    assert set(f.name for f in fields(AlgebraPublicParameters))=={'binding','g1','g2','g1_a','g2_a','gt_alpha','c_max'}
    assert set(f.name for f in fields(EncryptCoreResult))=={'binding','matrix','c_i','d_j','c','e','c_max'}
    assert set(f.name for f in fields(EphemeralAlgebraBundle))=={'binding','tokens','k1_q','k_tau_q','t0_q'}
    forbidden={'alpha','a','z','mu','mu_q','delta_q','r_j','s','k0','k0_q'}
    assert not forbidden.intersection(f.name for cls in (EncryptCoreResult,EphemeralAlgebraBundle)
                                      for f in fields(cls))


def test_mu_q_zero_and_k0_q_identity_resampled():
    b=BLS12381Backend(SYS_ID)
    pp,msk=setup_algebra_core(b,1,scalar_source=ScalarQueue(b,[7,11]))
    base,rk=keygen_algebra_core(pp,msk,b,scalar_source=ScalarQueue(b,[13,17]))
    c=b.g1_mul(pp.g1,b.scalar_from_int(19))
    p=b.scalar_order
    # First delta cancels mu. Second makes K0_q the identity; third succeeds.
    identity_delta=(-((13*7+11*17)*pow(11,-1,p)))%p
    source=ScalarQueue(b,[(-17)%p,identity_delta,37])
    counts=AlgebraOperationCounts()
    bundle=derive_ephemeral_algebra(pp,base,(token('A'),),c,b,
                                    scalar_source=source,counts=counts)
    assert len(source.calls)==3
    assert bundle.k1_q==b.g2_mul(pp.g2,b.scalar_from_int(54))
    assert counts.pairing_terms==1


def test_invalid_scalar_sources_and_cross_binding_fail_closed():
    b=BLS12381Backend(SYS_ID)
    with pytest.raises(ContractError):
        setup_algebra_core(b,1,scalar_source=lambda _:b.scalar_from_int(0))
    pp,msk=setup_algebra_core(b,1,scalar_source=ScalarQueue(b,[7,11]))
    other=BLS12381Backend(b'OTHER-SYS')
    with pytest.raises(ContractError):
        keygen_algebra_core(pp,msk,other)
