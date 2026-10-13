"""Protected payload and segmented XOR correctness/negative gates."""
import dataclasses
import hashlib
import json
from pathlib import Path

import pytest

from core.myabe08 import af
from core.myabe08.crypto import AES256GCMSIV, derive_af_nonce, derive_row_key
from core.myabe08.encoding import encode_fixed_rows
from core.myabe08.errors import AFBuildError, AuthenticationError, ContractError
from core.myabe08.metrics import AFMetrics
from core.myabe08.types import AFHeader, AFParameters, ProtectedAnonymousFilter, TokenRows


def token(label):
    return hashlib.sha256(label.encode()).digest()


def fixture(labels=('A', 'B', 'A', 'C', 'A'), c_max=3):
    h = AFHeader(b'TEST-SYS', b'P'*32, b'M'*32, len(labels), len(set(labels)), AFParameters(c_max))
    groups = {}
    for i, label in enumerate(labels, 1):
        groups.setdefault(label, []).append(i)
    entries = tuple(TokenRows(token(label), tuple(rows)) for label, rows in groups.items())
    return h, af.compute_ctx_af(h), entries


def deterministic_bytes(domain):
    state = {'n': 0}
    def draw(length):
        state['n'] += 1
        return hashlib.shake_256(domain + state['n'].to_bytes(4, 'big')).digest(length)
    return draw


def build(labels=('A', 'B', 'A', 'C', 'A'), seed_domain=b'seed', slot_domain=b'slot'):
    h, ctx, entries = fixture(labels)
    metrics = AFMetrics()
    index = af.ProtectedPayloadAF().build(entries, header=h, ctx_af=ctx, metrics=metrics,
                                           seed_source=deterministic_bytes(seed_domain),
                                           slot_source=deterministic_bytes(slot_domain))
    return h, ctx, entries, index, metrics


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _replace_member_payload(index, tok, replacement):
    pos = af.fuse_positions(index.metadata.seed_af, tok, index.metadata.segment_length)
    old = af.xor_slots([index.slots[p] for p in pos])
    slots = list(index.slots)
    slots[pos[0]] = _xor(slots[pos[0]], _xor(old, replacement))
    return dataclasses.replace(index, slots=tuple(slots))


@pytest.mark.parametrize('labels', [('A',), ('A','B','C','D','E','F','G'), ('A','B','A','C','A')])
def test_all_members_and_equations(labels):
    h, ctx, entries, index, metrics = build(labels)
    assert metrics.u == len(entries)
    assert metrics.m_af == 3*metrics.segment_length == len(index.slots)
    assert metrics.slot_payload_bytes == 4*(h.parameters.c_max+1)+16
    assert metrics.build_success and 1 <= metrics.attempts <= 32
    query = AFMetrics()
    for entry in entries:
        assert af.ProtectedPayloadAF().query(index, entry.token, header=h, ctx_af=ctx,
                                             metrics=query).rows == entry.rows
        p = af.fuse_positions(index.metadata.seed_af, entry.token, index.metadata.segment_length)
        assert af.xor_slots([index.slots[i] for i in p]) == af.protect_row_payload(entry.rows,ctx,entry.token,index.metadata)
    assert (query.queries,query.hits,query.misses,query.decoded_payloads) == (len(entries),len(entries),0,len(entries))


def test_fuse_segments_seed_token_and_determinism():
    a, b, c = token('A'), token('B'), bytes(range(16))
    p = af.fuse_positions(c,a,7)
    assert p == af.fuse_positions(c,a,7)
    assert [n//7 for n in p] == [0,1,2]
    assert len(set(p)) == 3
    assert af.fuse_positions(bytes([1])*16,a,7) != p
    assert af.fuse_positions(c,b,7) != p
    for length in (4,5,7,19,1000):
        for i in range(100):
            pos = af.fuse_positions(c, i.to_bytes(32,'big'),length)
            assert all(j*length <= value < (j+1)*length for j,value in enumerate(pos))
    with pytest.raises(ContractError):
        af.fuse_positions(b'short',a,7)


def test_deterministic_sources_and_seed_change():
    _,_,_,a,_ = build()
    _,_,_,b,_ = build()
    _,_,_,c,_ = build(seed_domain=b'other')
    assert a == b
    assert a.metadata.seed_af != c.metadata.seed_af
    assert a != c


def test_query_rejects_wrong_token_context_and_tampering():
    h, ctx, entries, index, _ = build()
    query = af.ProtectedPayloadAF().query
    member = entries[0].token
    variants = [
        (index,token('nonmember'),h,ctx),
        (index,member,h,b'X'*32),
        (dataclasses.replace(index,slots=index.slots[:-1]),member,h,ctx),
        (dataclasses.replace(index,slots=(index.slots[0][:-1],)+index.slots[1:]),member,h,ctx),
        (dataclasses.replace(index,metadata=dataclasses.replace(index.metadata,seed_af=b'Z'*16)),member,h,ctx),
        (dataclasses.replace(index,metadata=dataclasses.replace(index.metadata,ell=index.metadata.ell+1)),member,h,ctx),
        (index,member,dataclasses.replace(h,matrix_digest=b'Z'*32),ctx),
    ]
    pos = af.fuse_positions(index.metadata.seed_af,member,index.metadata.segment_length)[0]
    slots=list(index.slots); slots[pos]=bytes([slots[pos][0]^1])+slots[pos][1:]
    variants.append((dataclasses.replace(index,slots=tuple(slots)),member,h,ctx))
    m=AFMetrics()
    for obj,tok,header,context in variants:
        result=query(obj,tok,header=header,ctx_af=context,metrics=m)
        assert result.hit is False and result.rows == ()
    assert (m.queries,m.misses,m.hits)==(len(variants),len(variants),0)
    assert m.auth_failures >= 1 and m.parse_failures >= 1


@pytest.mark.parametrize('raw', [
    b'\0\0\0\x02' + b'\0\0\0\x03' + b'\0\0\0\x01' + b'\0\0\0\0', # descending
    b'\0\0\0\x02' + b'\0\0\0\x01'*2 + b'\0\0\0\0', # duplicate
    b'\0\0\0\x01' + b'\0\0\0\x06' + b'\0'*8, # out of range
    b'\0\0\0\x01' + b'\0\0\0\x01' + b'\0\0\0\x07' + b'\0'*4, # padding
    b'\0\0\0\x01' + b'\0\0\0\x01' + b'\0'*4, # truncated
])
def test_authenticated_but_malformed_rows_return_uniform_miss(raw):
    h, ctx, entries, index, _ = build()
    tok=entries[0].token
    malformed = AES256GCMSIV().encrypt(derive_row_key(ctx,tok),derive_af_nonce(ctx,tok),raw,
                                      af.build_af_row_ad(ctx,tok,index.metadata))
    altered=_replace_member_payload(index,tok,malformed)
    metrics=AFMetrics()
    assert af.ProtectedPayloadAF().query(altered,tok,header=h,ctx_af=ctx,metrics=metrics) == af.AFQueryResult(False,())
    assert metrics.misses==1
    if len(raw)==index.metadata.slot_payload_bytes-16:
        assert metrics.parse_failures==1


def test_payload_wrong_metadata_context_and_ad():
    h,ctx,entries,index,_=build()
    tok=entries[0].token
    v=af.protect_row_payload(entries[0].rows,ctx,tok,index.metadata)
    assert len(v)==index.metadata.slot_payload_bytes
    assert af.open_row_payload(v,ctx,tok,index.metadata)==entries[0].rows
    for context,meta in ((b'Q'*32,index.metadata), (ctx,dataclasses.replace(index.metadata,seed_af=b'Z'*16))):
        with pytest.raises(AuthenticationError):
            af.open_row_payload(v,context,tok,meta)
    with pytest.raises(AuthenticationError):
        af.open_row_payload(v[:-1]+bytes([v[-1]^1]),ctx,tok,index.metadata)


def test_retry_rebuilds_payload_with_final_seed_and_bound(monkeypatch):
    h,ctx,entries=fixture(('A','B'))
    original=af._peel
    calls={'n':0}
    def once_fail(edges,size):
        calls['n']+=1
        return [] if calls['n']==1 else original(edges,size)
    monkeypatch.setattr(af,'_peel',once_fail)
    m=AFMetrics()
    index=af.ProtectedPayloadAF().build(entries,header=h,ctx_af=ctx,metrics=m,
                                         seed_source=deterministic_bytes(b'retry'),
                                         slot_source=deterministic_bytes(b'slot'))
    assert (m.attempts,m.peel_failures)==(2,1)
    for e in entries:
        assert af.ProtectedPayloadAF().query(index,e.token,header=h,ctx_af=ctx).rows==e.rows
    monkeypatch.setattr(af,'_peel',lambda edges,size: [])
    m=AFMetrics(); source=deterministic_bytes(b'fail')
    with pytest.raises(AFBuildError,match='32'):
        af.ProtectedPayloadAF().build(entries,header=h,ctx_af=ctx,metrics=m,seed_source=source)
    assert (m.attempts,m.peel_failures,m.build_success)==(32,32,False)


def test_published_state_contains_only_metadata_and_slots():
    _,_,_,index,_=build()
    assert tuple(index.__dataclass_fields__) == ('slots','metadata')
    assert set(index.metadata.__dataclass_fields__) == {
        'profile_id','encoding_profile_id','sys_id','ell','u','c_max',
        'segment_length','m_af','seed_af','slot_payload_bytes'}
    def walk(value):
        if dataclasses.is_dataclass(value):
            for field in dataclasses.fields(value):
                assert field.name not in {'token_to_rows','token_to_positions','member_map','locator','pstore',
                                          'edges','adjacency','peeling_stack','row_keys','plaintext_payloads'}
                walk(getattr(value,field.name))
        elif type(value) in (tuple,list):
            for part in value: walk(part)
        else:
            assert type(value) not in (dict,set)
    walk(index)


def test_metadata_validation():
    h,ctx,entries,index,_=build()
    m=index.metadata
    for field,value in [('u',0),('ell',0),('c_max',0),('m_af',m.m_af+1),
                        ('segment_length',m.segment_length+1),('slot_payload_bytes',0),('seed_af',b'bad')]:
        with pytest.raises(ContractError):
            dataclasses.replace(m,**{field:value})
