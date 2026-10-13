"""Independent linear-combination verifier for deterministic field solver."""
import hashlib

import pytest

from core.myabe08.crypto import BLS12381Backend
from core.myabe08.errors import ContractError, Unauthorized, UnsupportedPolicy
from core.myabe08.lsss import (LSSSMatrix, assign_occurrence_ranks,
                               authorized_subset, merge_af_hits, prepare_policy_rows)


@pytest.fixture(scope='module')
def backend():
    return BLS12381Backend(b'LSSS-TEST-SYS')


def matrix(rows, backend):
    return LSSSMatrix(tuple(tuple(r) for r in rows),backend.scalar_order,len(rows),len(rows[0]))


def verify_linear_combination(mat,result,backend):
    """Direct sum only; deliberately does not call any solver routine."""
    total=[0]*mat.d
    for term in result.terms:
        coefficient=int.from_bytes(backend.serialize_scalar(term.coefficient),'big')
        assert coefficient != 0
        for j,value in enumerate(mat.rows[term.row-1]):
            total[j]=(total[j]+coefficient*value)%mat.field_order
    assert total == [1]+[0]*(mat.d-1)


@pytest.mark.parametrize('rows,J,expected_rows',[
    (((1,),(1,)),(2,),(2,)), # OR
    (((1,1),(0,-1)),(1,2),(1,2)), # AND
    (((1,1),(1,2),(1,3)),(1,3),(1,3)), # 2-of-3
    (((1,1,1),(1,2,4),(1,3,9),(1,4,16),(1,5,25)),(1,3,5),(1,3,5)), # 3-of-5
    (((0,1),(1,1),(0,-1)),(1,2,3),(1,2)), # redundant third row
    (((0,0),(1,0),(0,1)),(3,2,1),(2,)), # irrelevant and unordered J
    (((1,0,1),(0,1,0),(0,0,-1)),(1,3),(1,3)), # explicit general
])
def test_authorized_workloads(rows,J,expected_rows,backend):
    mat=matrix(rows,backend)
    answer=authorized_subset(mat,J,backend)
    assert tuple(t.row for t in answer.terms)==expected_rows
    verify_linear_combination(mat,answer,backend)
    assert answer==authorized_subset(mat,J,backend)
    assert answer==authorized_subset(mat,tuple(reversed(J)),backend)


@pytest.mark.parametrize('rows,J',[
    (((1,1),(0,-1)),(1,)), # AND missing B
    (((1,1),(1,2),(1,3)),(2,)), # threshold one row
    (((1,1,1),(1,2,4),(1,3,9),(1,4,16),(1,5,25)),(1,4)),
    (((0,1),(0,2)),(1,2)),
])
def test_unauthorized(rows,J,backend):
    with pytest.raises(Unauthorized):
        authorized_subset(matrix(rows,backend),J,backend)


def test_candidate_validation_and_field_binding(backend):
    mat=matrix(((1,),(1,)),backend)
    with pytest.raises(ContractError,match='duplicate'):
        authorized_subset(mat,(1,1),backend)
    with pytest.raises(ContractError):
        authorized_subset(mat,(3,),backend)
    with pytest.raises(ContractError):
        authorized_subset(LSSSMatrix(mat.rows,17,2,1),(1,),backend)
    with pytest.raises(ContractError):
        LSSSMatrix(((1,2),(3,)),backend.scalar_order,2,2)


def test_occurrence_full_policy_order_and_conflict(backend):
    toks=tuple(hashlib.sha256(x.encode()).digest() for x in ('A','B','A','C','A'))
    mat=matrix(((0,0),(0,0),(1,1),(0,0),(0,-1)),backend)
    entries,ranks=prepare_policy_rows(mat,toks,3)
    assert ranks==(1,1,2,1,3)
    mapping={item.token:item.rows for item in entries}
    assert mapping[toks[0]]==(1,3,5)
    J,phi=merge_af_hits(((toks[0],(1,3,5)),))
    assert J==(1,3,5)
    assert tuple((w.row,w.occurrence_rank) for w in phi)==((1,1),(3,2),(5,3))
    answer=authorized_subset(mat,J,backend,witnesses=phi)
    assert tuple(t.row for t in answer.terms)==(3,5)
    assert answer.occurrence_slots==(2,3)
    verify_linear_combination(mat,answer,backend)
    with pytest.raises(UnsupportedPolicy):
        assign_occurrence_ranks(toks,2)
    with pytest.raises(ContractError,match='conflicting'):
        merge_af_hits(((toks[0],(1,3)),(toks[1],(3,))))
