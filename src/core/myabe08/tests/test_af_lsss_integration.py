"""AF -> J/phi -> Gaussian -> slots, with no ABE pairing or TEE."""
import hashlib

import pytest

from core.myabe08.af import ProtectedPayloadAF, compute_ctx_af
from core.myabe08.crypto import BLS12381Backend
from core.myabe08.errors import Unauthorized
from core.myabe08.lsss import LSSSMatrix, authorized_subset, merge_af_hits, prepare_policy_rows
from core.myabe08.types import AFHeader, AFParameters


def token(label):
    return hashlib.sha256(label.encode()).digest()


def seed_source(n):
    return hashlib.shake_256(b'integration-seed').digest(n)


def slot_source(n):
    return hashlib.shake_256(b'integration-slots').digest(n)


def run_pipeline(labels,rows,user_labels,c_max,backend):
    mat=LSSSMatrix(tuple(tuple(row) for row in rows),backend.scalar_order,len(rows),len(rows[0]))
    tokens=tuple(token(label) for label in labels)
    entries,ranks=prepare_policy_rows(mat,tokens,c_max)
    header=AFHeader(b'LSSS-TEST-SYS',b'P'*32,b'M'*32,mat.ell,len(entries),AFParameters(c_max))
    ctx=compute_ctx_af(header)
    index=ProtectedPayloadAF().build(entries,header=header,ctx_af=ctx,
                                      seed_source=seed_source,slot_source=slot_source)
    hits=[]
    for label in user_labels:
        t=token(label)
        result=ProtectedPayloadAF().query(index,t,header=header,ctx_af=ctx)
        if result.hit:
            hits.append((t,result.rows))
    J,phi=merge_af_hits(tuple(hits))
    result=authorized_subset(mat,J,backend,witnesses=phi)
    I=tuple(term.row for term in result.terms)
    total=[0]*mat.d
    for term in result.terms:
        coeff=int.from_bytes(backend.serialize_scalar(term.coefficient),'big')
        for col,value in enumerate(mat.rows[term.row-1]):
            total[col]=(total[col]+coeff*value)%backend.scalar_order
    assert total==[1]+[0]*(mat.d-1)
    assert 1 <= len(result.occurrence_slots) <= min(len(I),c_max)
    return J,phi,I,result.occurrence_slots,ranks


@pytest.mark.parametrize('labels,rows,user,cmax,expected',[
    (('A','B'),((1,),(1,)),('B',),1,(1,1,1)), # OR
    (('A','B'),((1,1),(0,-1)),('A','B'),1,(2,2,1)), # AND
    (('A','B','C'),((1,1),(1,2),(1,3)),('A','C'),1,(2,2,1)), # 2-of-3
    (('X','A','B'),((0,1),(1,1),(0,-1)),('X','A','B'),1,(3,2,1)), # extra row
    (('A','B','A','C','A'),((0,0),(0,0),(1,1),(0,0),(0,-1)),('A',),3,(3,2,2)),
])
def test_full_structural_gate(labels,rows,user,cmax,expected,monkeypatch):
    def forbidden_pair(*args, **kwargs):
        raise AssertionError('Phase 2B must not perform pairing')
    monkeypatch.setattr(BLS12381Backend,'pair',forbidden_pair)
    backend=BLS12381Backend(b'LSSS-TEST-SYS')
    J,phi,I,slots,ranks=run_pipeline(labels,rows,user,cmax,backend)
    assert (len(J),len(I),len(slots))==expected
    if labels==('A','B','A','C','A'):
        assert I==(3,5)
        assert slots==(2,3)
        assert ranks==(1,1,2,1,3)
        assert tuple((w.row,w.occurrence_rank) for w in phi)==((1,1),(3,2),(5,3))


def test_hit_without_authorization():
    backend=BLS12381Backend(b'LSSS-TEST-SYS')
    with pytest.raises(Unauthorized):
        run_pipeline(('A','B'),((1,1),(0,-1)),('A',),1,backend)
