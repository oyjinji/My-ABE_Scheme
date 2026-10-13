"""TEST-only synthetic/direct contextual tokens and reproducible scalar draws."""
import hashlib

from core.myabe08.af import ProtectedPayloadAF, compute_ctx_af
from core.myabe08.algebra import (AlgebraOperationCounts, derive_ephemeral_algebra,
    encrypt_algebra_core, finaldec_algebra_core, keygen_algebra_core,
    setup_algebra_core, transform_algebra_core)
from core.myabe08.crypto import BLS12381Backend, compute_ctx_priv, contextual_token
from core.myabe08.encoding import encode_attribute
from core.myabe08.lsss import LSSSMatrix, prepare_policy_rows
from core.myabe08.types import AFHeader, AFParameters

SYS_ID=b'MYABE08-ALGEBRA-TEST'
TEST_KTOK=bytes(range(32))  # NOT PRODUCTION SECRET


class ScalarQueue:
    def __init__(self, backend, values):
        self.backend=backend
        self.values=list(values)
        self.calls=[]
    def __call__(self, nonzero):
        if not self.values: raise AssertionError('scalar fixture exhausted')
        value=self.values.pop(0)
        self.calls.append((nonzero,value))
        if nonzero and value==0: raise AssertionError('nonzero slot supplied zero')
        return self.backend.scalar_from_int(value)


def token(label,context_id=b'POLICY-CONTEXT-TEST-00000000000000'):
    ctx_priv=compute_ctx_priv(SYS_ID,context_id,1)
    return contextual_token(TEST_KTOK,SYS_ID,ctx_priv,
                            encode_attribute('test','label',label))


def policy(backend,labels,rows,c_max,context_id=b'POLICY-CONTEXT-TEST-00000000000000'):
    matrix=LSSSMatrix(tuple(tuple(x) for x in rows),backend.scalar_order,len(rows),len(rows[0]))
    tokens=tuple(token(label,context_id) for label in labels)
    entries,ranks=prepare_policy_rows(matrix,tokens,c_max)
    ctx_priv=compute_ctx_priv(SYS_ID,context_id,1)
    header=AFHeader(SYS_ID,ctx_priv,b'M'*32,len(rows),len(entries),AFParameters(c_max))
    ctx_af=compute_ctx_af(header)
    index=ProtectedPayloadAF().build(entries,header=header,ctx_af=ctx_af,
        seed_source=lambda n: hashlib.shake_256(b'phase3a-filter-seed').digest(n),
        slot_source=lambda n: hashlib.shake_256(b'phase3a-filter-slot').digest(n))
    return matrix,tokens,ranks,header,ctx_af,index


def run_case(labels,rows,user_labels,c_max,*, sources=None,
             context_id=b'POLICY-CONTEXT-TEST-00000000000000'):
    backend=BLS12381Backend(SYS_ID)
    src=sources or {}
    setup_counts=AlgebraOperationCounts()
    pp,msk=setup_algebra_core(backend,c_max,scalar_source=src.get('setup'),counts=setup_counts)
    base,recovery=keygen_algebra_core(pp,msk,backend,scalar_source=src.get('keygen'))
    matrix,tokens,ranks,header,ctx_af,index=policy(backend,labels,rows,c_max,context_id)
    enc_counts=AlgebraOperationCounts()
    ct=encrypt_algebra_core(pp,matrix,tokens,backend,scalar_source=src.get('encrypt'),counts=enc_counts)
    tee_counts,csp_counts,final_counts=(AlgebraOperationCounts() for _ in range(3))
    user_tokens=tuple(token(label,context_id) for label in user_labels)
    bundle=derive_ephemeral_algebra(pp,base,user_tokens,ct.c,backend,
                                    scalar_source=src.get('ephemeral'),counts=tee_counts)
    tr=transform_algebra_core(pp,ct,bundle,index,header,ctx_af,backend,counts=csp_counts)
    quotient,recovered=finaldec_algebra_core(bundle.t0_q,tr.t_a,recovery,backend,counts=final_counts)
    return locals()
