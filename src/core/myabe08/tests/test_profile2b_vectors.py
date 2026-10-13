"""Read-only byte and structural regression vectors. TEST material only."""
import hashlib
import json
from pathlib import Path

from core.myabe08.af import (build_af_row_ad, compute_ctx_af, encode_af_metadata,
                             fuse_positions, protect_row_payload, token_context, xor_slots)
from core.myabe08.crypto import BLS12381Backend
from core.myabe08.lsss import LSSSMatrix, authorized_subset, assign_occurrence_ranks
from core.myabe08.tests.test_af_phase2b import build

VECTOR = Path(__file__).parent / 'vectors' / 'profile_v1.json'
PHASE2A_PROJECTION_SHA256 = '958f1f7c302030af8eca1bbb0bceaa4f90fe1d00664fd1b9b740dea95e5d8651'


def test_phase2a_vector_fields_unchanged():
    data=json.loads(VECTOR.read_text())
    projection={k:v for k,v in data.items() if k not in ('phase2b','phase3a','phase3b','phase3c')}
    canonical=json.dumps(projection,sort_keys=True,separators=(',',':')).encode()
    assert hashlib.sha256(canonical).hexdigest()==PHASE2A_PROJECTION_SHA256


def test_phase2b_frozen_vectors():
    v=json.loads(VECTOR.read_text())['phase2b']
    h,ctx,entries,index,_=build()
    tok=bytes.fromhex(v['fuse_positions']['token_hex'])
    pos=fuse_positions(index.metadata.seed_af,tok,index.metadata.segment_length)
    assert ctx.hex()==v['ctx_af_hex']
    assert index.metadata.seed_af.hex()==v['fuse_positions']['seed_hex']
    assert list(pos)==v['fuse_positions']['positions']
    assert encode_af_metadata(index.metadata).hex()==v['metadata_hex']
    assert token_context(tok).hex()==v['tok_ctx_hex']
    assert build_af_row_ad(ctx,tok,index.metadata).hex()==v['af_ad_hex']
    assert protect_row_payload((1,3,5),ctx,tok,index.metadata).hex()==v['protected_payload_hex']
    assert xor_slots([index.slots[p] for p in pos]).hex()==v['three_slot_reconstruction_hex']
    assert [s.hex() for s in index.slots]==v['filter_snapshot']['slots_hex']
    assert v['protected_payload_hex']==v['three_slot_reconstruction_hex']
    occurrence=v['occurrence']
    assert list(assign_occurrence_ranks(tuple(hashlib.sha256(x.encode()).digest()
                                              for x in occurrence['tokens']),3))==occurrence['ranks']
    backend=BLS12381Backend(b'LSSS-TEST-SYS')
    av=v['authorized_subset']
    mat=LSSSMatrix(tuple(tuple(r) for r in av['matrix_rows']),backend.scalar_order,5,2)
    result=authorized_subset(mat,tuple(av['J']),backend)
    assert [x.row for x in result.terms]==av['I']
    assert [backend.serialize_scalar(x.coefficient).hex() for x in result.terms]==av['omega_hex']
