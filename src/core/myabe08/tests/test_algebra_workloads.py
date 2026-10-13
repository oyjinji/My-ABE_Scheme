"""Real BLS12-381 structural workloads, cancellation and pair-call tracing."""
import pytest

from core.myabe08.algebra import (AlgebraOperationCounts, pairing_summary,
                                  transform_algebra_core)
from core.myabe08.crypto import BLS12381Backend
from core.myabe08.lsss import authorized_subset, merge_af_hits
from core.myabe08.tests.algebra_fixtures import SYS_ID, run_case


WORKLOADS=[
    (('A',),((1,),),('A',),1,(1,1,1)),
    (('A','B'),((1,),(1,)),('B',),1,(1,1,1)),
    (('A','B'),((1,1),(0,-1)),('A','B'),2,(2,2,1)),
    (('A','B','C'),((1,1),(1,2),(1,3)),('A','C'),1,(2,2,1)),
    (('A','B','C','D','E'),((1,1,1),(1,2,4),(1,3,9),(1,4,16),(1,5,25)),('A','C','E'),1,(3,3,1)),
    (('A','B','C'),((1,0,1),(0,1,0),(0,0,-1)),('A','C'),1,(2,2,1)),
    (('X','A','B'),((0,1),(1,1),(0,-1)),('X','A','B'),1,(3,2,1)),
    (('A','B','A','C','A'),((0,0),(0,0),(1,1),(0,0),(0,-1)),('A',),3,(3,2,2)),
]


@pytest.mark.parametrize('labels,rows,user,cmax,expected',WORKLOADS)
def test_algebra_workloads(labels,rows,user,cmax,expected):
    x=run_case(labels,rows,user,cmax)
    ct,tr=x['ct'],x['tr']
    assert x['recovered']==ct.e
    assert (len(tr.candidate_rows),len(tr.reconstruction_rows),len(tr.occurrence_slots))==expected
    assert len(ct.d_j)==cmax
    assert len(tr.y_by_slot)==len(tr.occurrence_slots)
    trace=pairing_summary(x['tee_counts'],x['csp_counts'])
    assert (trace.tee_pairing_terms,trace.csp_pairing_terms,
            trace.system_pairing_terms)==(1,1+expected[2],2+expected[2])
    assert x['csp_counts'].t_i==expected[2]
    assert x['csp_counts'].candidate_rows==expected[0]
    assert x['csp_counts'].reconstruction_rows==expected[1]
    assert x['final_counts'].pairing_terms==0
    if labels==('A','B','A','C','A'):
        assert x['ranks']==(1,1,2,1,3)
        assert tr.reconstruction_rows==(3,5)
        assert tr.occurrence_slots==(2,3)
    if labels==('A','B') and rows==((1,1),(0,-1)):
        assert x['ranks']==(1,1)
        assert tr.reconstruction_rows==(1,2)
        assert tr.occurrence_slots==(1,)
        assert len(ct.d_j)==2  # second D_j is generated though unused


def test_pair_calls_are_actual_backend_calls(monkeypatch):
    original=BLS12381Backend.pair
    calls={'n':0}
    def counted(self,left,right):
        calls['n']+=1
        return original(self,left,right)
    monkeypatch.setattr(BLS12381Backend,'pair',counted)
    x=run_case(('A','B','A','C','A'),((0,0),(0,0),(1,1),(0,0),(0,-1)),('A',),3)
    # Setup uses one pair. The request itself uses 1 T0 + 1+t_I CSP calls.
    assert calls['n']==1+1+(1+2)
    assert x['setup_counts'].pairing_terms==1
    assert x['tee_counts'].pairing_terms==1
    assert x['csp_counts'].pairing_terms==3


def test_real_group_mask_cancellation_per_slot():
    from core.myabe08.tests.algebra_fixtures import ScalarQueue
    from core.myabe08.af import ProtectedPayloadAF
    b=BLS12381Backend(SYS_ID)
    sources={
        'setup':ScalarQueue(b,[7,11]), 'keygen':ScalarQueue(b,[13,17]),
        'encrypt':ScalarQueue(b,[19,5,23,29,31]),
        'ephemeral':ScalarQueue(b,[37]),
    }
    x=run_case(('A','B','A','C','A'),((0,0),(0,0),(1,1),(0,0),(0,-1)),('A',),3,
               sources=sources)
    ct=x['ct']; bundle=x['bundle']; tr=x['tr']; pp=x['pp']; p=b.scalar_order
    hits=[]
    for tok in bundle.tokens:
        result=ProtectedPayloadAF().query(x['index'],tok,header=x['header'],ctx_af=x['ctx_af'])
        if result.hit: hits.append((tok,result.rows))
    J,phi=merge_af_hits(tuple(hits))
    solution=authorized_subset(ct.matrix,J,b,witnesses=phi)
    witnesses={w.row:w for w in phi}
    one=b.gt_pow(tr.t_a,b.scalar_from_int(0))
    r=(23,29,31)
    mu_q=17+37
    # Full-policy ranks 1,1,2,1,3 select r1/r1/r2/r1/r3 exactly.
    expected_lambdas=(0,0,24,0,-5)
    for i,(tok,rank,lam) in enumerate(zip(x['tokens'],x['ranks'],expected_lambdas)):
        expected=b.g1_add(b.g1_mul(pp.g1_a,b.scalar_from_int(lam%p)),
                          b.g1_mul(b.hash_to_g1(tok),b.scalar_from_int((-r[rank-1])%p)))
        assert ct.c_i[i]==expected
    assert ct.d_j==tuple(b.g2_mul(pp.g2,b.scalar_from_int(value)) for value in r)
    for slot,y in tr.y_by_slot:
        mask=None
        ledger=0
        for term in solution.terms:
            w=witnesses[term.row]
            if w.occurrence_rank!=slot: continue
            omega=int.from_bytes(b.serialize_scalar(term.coefficient),'big')
            q=b.hash_to_g1(w.token)
            part=b.g1_mul(q,b.scalar_from_int((-r[slot-1]*omega)%p))
            mask=part if mask is None else b.g1_add(mask,part)
            ledger=(ledger-r[slot-1]*mu_q*omega+r[slot-1]*mu_q*omega)%p
        assert ledger==0
        correction=b.pair(y,ct.d_j[slot-1])
        assert b.gt_mul(b.pair(mask,bundle.k1_q),correction)==one
    gt=b.pair(pp.g1,pp.g2)
    assert tr.t_a==b.gt_pow(gt,b.scalar_from_int(11*mu_q*19))
    assert x['quotient']==b.gt_pow(gt,b.scalar_from_int(13*7*19))
    assert x['recovered']==ct.e
