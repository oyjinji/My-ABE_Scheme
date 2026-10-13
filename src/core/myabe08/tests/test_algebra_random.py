"""A bounded set of fresh BLS12-381 correctness trials, not a benchmark."""
from core.myabe08.algebra import (AlgebraOperationCounts, derive_ephemeral_algebra,
    encrypt_algebra_core, finaldec_algebra_core, keygen_algebra_core,
    setup_algebra_core, transform_algebra_core)
from core.myabe08.crypto import BLS12381Backend
from core.myabe08.tests.algebra_fixtures import SYS_ID, policy, token


def test_twelve_fresh_random_small_algebra_trials():
    b=BLS12381Backend(SYS_ID)
    pp,msk=setup_algebra_core(b,3)
    base,rk=keygen_algebra_core(pp,msk,b)
    cases=(
        (('A',),((1,),),('A',)),
        (('A','B'),((1,1),(0,-1)),('A','B')),
        (('A','B','C'),((1,1),(1,2),(1,3)),('A','C')),
        (('A','B','A','C','A'),((0,0),(0,0),(1,1),(0,0),(0,-1)),('A',)),
    )
    prepared=[policy(b,labels,rows,3) for labels,rows,user in cases]
    prior_d=None
    for trial in range(12):
        labels,rows,user=cases[trial%len(cases)]
        matrix,tokens,ranks,header,ctx,index=prepared[trial%len(cases)]
        ct=encrypt_algebra_core(pp,matrix,tokens,b)
        if prior_d is not None:
            assert all(left!=right for left,right in zip(prior_d,ct.d_j))
        prior_d=ct.d_j
        tee,csp=AlgebraOperationCounts(),AlgebraOperationCounts()
        bundle=derive_ephemeral_algebra(pp,base,tuple(token(label) for label in user),ct.c,b,
                                        counts=tee)
        tr=transform_algebra_core(pp,ct,bundle,index,header,ctx,b,counts=csp)
        quotient,recovered=finaldec_algebra_core(bundle.t0_q,tr.t_a,rk,b)
        assert recovered==ct.e
        assert (tee.pairing_terms,csp.pairing_terms)==(1,1+len(tr.occurrence_slots))
