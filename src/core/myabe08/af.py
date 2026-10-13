"""Authenticated fixed-row segmented XOR retrieval, without retained member maps.

Peeling/random-slot assignment audited from historical 05.3; FusePos is a
new explicit V1 closure, not the historical three-independent-hash rule.
"""
from collections import deque
import hashlib
import secrets
from typing import Optional, Tuple

from .crypto import AES256GCMSIV, derive_row_key, derive_af_nonce
from .encoding import (encode, StructuredRecord, UInt32, UInt64, require_bytes,
                       require_uint, encode_fixed_rows, decode_fixed_rows)
from .errors import ContractError, AuthenticationError, AFBuildError
from .metrics import AFMetrics
from .profile import MYABE08_ENCODING_V1
from .types import (AFHeader, AFMetadata, AFParameters, AFQueryResult,
                    ProtectedAnonymousFilter, TokenRows)

AF_PROFILE = 'MYABE05.3-SEGMENTED-XOR-V1'
FUSE_DOMAIN = 'MYABE08-FUSEPOS-V1'
SEED_BYTES = 16
MAX_ATTEMPTS = 32


def fuse_positions(seed_af, token, segment_length):
    require_bytes(seed_af, 'seed', SEED_BYTES)
    require_bytes(token, 'token', 32)
    require_uint(segment_length, 64, 'segment length')
    if segment_length < 4:
        raise ContractError('segment length must be >=4')
    limit = (1 << 64) - ((1 << 64) % segment_length)
    for counter in range(256):
        block = hashlib.sha256(encode((FUSE_DOMAIN, seed_af, token,
                                      UInt64(segment_length), UInt32(counter)))).digest()
        lanes = tuple(int.from_bytes(block[i:i+8], 'big') for i in (0, 8, 16))
        if all(value < limit for value in lanes):
            return tuple(j * segment_length + value % segment_length
                         for j, value in enumerate(lanes))
    raise ContractError('FusePos reduction budget exhausted')


def validate_metadata(meta):
    if type(meta) is not AFMetadata:
        raise ContractError('AFMetadata required')
    if meta.profile_id != AF_PROFILE or meta.encoding_profile_id != MYABE08_ENCODING_V1:
        raise ContractError('unsupported AF profile')
    require_bytes(meta.sys_id, 'SysID')
    require_bytes(meta.seed_af, 'seed', SEED_BYTES)
    if not meta.sys_id:
        raise ContractError('empty SysID')
    for name in ('ell', 'u', 'c_max'):
        require_uint(getattr(meta, name), 32, name)
        if getattr(meta, name) == 0:
            raise ContractError('positive dimensions required')
    for name in ('segment_length', 'm_af', 'slot_payload_bytes'):
        require_uint(getattr(meta, name), 64, name)
    if (meta.u > meta.ell or meta.segment_length != max(4, (3*meta.u+5)//2)
            or meta.m_af != 3*meta.segment_length
            or meta.slot_payload_bytes != 4*(meta.c_max+1)+16):
        raise ContractError('inconsistent AF dimensions')
    if meta.slot_payload_bytes > 16*1024*1024:
        raise ContractError('AF payload exceeds V1 resource bound')


def metadata_record(meta):
    validate_metadata(meta)
    return StructuredRecord('MYABE08.AFMetadataV1', (
        ('profile_id', meta.profile_id), ('encoding_profile_id', meta.encoding_profile_id),
        ('sys_id', meta.sys_id), ('ell', UInt32(meta.ell)), ('u', UInt32(meta.u)),
        ('c_max', UInt32(meta.c_max)), ('segment_length', UInt64(meta.segment_length)),
        ('m_af', UInt64(meta.m_af)), ('seed_af', meta.seed_af),
        ('slot_payload_bytes', UInt64(meta.slot_payload_bytes))))


def encode_af_metadata(meta):
    return encode(metadata_record(meta))


def header_record(header):
    if type(header) is not AFHeader or type(header.parameters) is not AFParameters:
        raise ContractError('AFHeader and AFParameters required')
    require_bytes(header.sys_id, 'SysID')
    require_bytes(header.ctx_priv, 'ctx_priv', 32)
    require_bytes(header.matrix_digest, 'matrix digest', 32)
    if not header.sys_id or type(header.ell) is not int or type(header.distinct_tokens) is not int or not 1 <= header.distinct_tokens <= header.ell <= 0xffffffff:
        raise ContractError('invalid header dimensions')
    p = header.parameters
    if p != AFParameters(p.c_max):
        raise ContractError('unsupported AF parameters')
    params = StructuredRecord('MYABE08.AFParametersV1', (
        ('profile_id', p.profile_id), ('c_max', UInt32(p.c_max)),
        ('max_seed_attempts', UInt32(p.max_seed_attempts)),
        ('row_width_bytes', UInt32(p.row_width_bytes)), ('authenc_id', p.authenc_id),
        ('tag_bytes', UInt32(p.tag_bytes))))
    return StructuredRecord('MYABE08.AFHeaderV1', (
        ('sys_id', header.sys_id), ('ctx_priv', header.ctx_priv),
        ('matrix_digest', header.matrix_digest), ('ell', UInt32(header.ell)),
        ('u', UInt32(header.distinct_tokens)), ('parameters', params)))


def compute_ctx_af(header):
    return hashlib.sha256(encode(('AF', header_record(header)))).digest()


def token_context(token):
    require_bytes(token, 'token', 32)
    return hashlib.sha256(encode(('AF-TOKEN', token))).digest()


def build_af_row_ad(ctx_af, token, metadata):
    require_bytes(ctx_af, 'ctx_AF', 32)
    return encode(('AF-row', ctx_af, token_context(token), metadata_record(metadata)))


def protect_row_payload(rows, ctx_af, token, metadata):
    ad = build_af_row_ad(ctx_af, token, metadata)
    plaintext = encode_fixed_rows(rows, metadata.c_max, metadata.ell)
    result = AES256GCMSIV().encrypt(derive_row_key(ctx_af, token),
                                   derive_af_nonce(ctx_af, token), plaintext, ad)
    require_bytes(result, 'protected payload', metadata.slot_payload_bytes)
    return result


def open_row_payload(payload, ctx_af, token, metadata):
    ad = build_af_row_ad(ctx_af, token, metadata)
    require_bytes(payload, 'protected payload', metadata.slot_payload_bytes)
    raw = AES256GCMSIV().decrypt(derive_row_key(ctx_af, token),
                              derive_af_nonce(ctx_af, token), payload, ad)
    return decode_fixed_rows(raw, metadata.c_max, metadata.ell)


def xor_slots(slots):
    if not slots or any(type(s) is not bytes or len(s) != len(slots[0]) for s in slots):
        raise ContractError('unequal XOR widths')
    value = 0
    for slot in slots:
        value ^= int.from_bytes(slot, 'big')
    return value.to_bytes(len(slots[0]), 'big')


def _peel(edges, size):
    degree, edge_xor = [0]*size, [0]*size
    for edge_id, edge in enumerate(edges):
        for p in edge:
            degree[p] += 1
            edge_xor[p] ^= edge_id
    queue = deque(p for p in range(size) if degree[p] == 1)
    stack = []
    while queue:
        pivot = queue.popleft()
        if degree[pivot] != 1:
            continue
        edge_id = edge_xor[pivot]
        stack.append((edge_id, pivot))
        for p in edges[edge_id]:
            degree[p] -= 1
            edge_xor[p] ^= edge_id
            if degree[p] == 1:
                queue.append(p)
    return stack


class ProtectedPayloadAF:
    def build(self, entries: Tuple[TokenRows, ...], *, header: AFHeader,
              ctx_af: bytes, metrics: Optional[AFMetrics] = None,
              seed_source=None, slot_source=None) -> ProtectedAnonymousFilter:
        """Sources accept byte count; secure defaults, deterministic injection for tests.

        Payloads are generated only AFTER successful peeling with final metadata.
        All policy rows must occur exactly once across distinct token entries.
        """
        if compute_ctx_af(header) != ctx_af:
            raise ContractError('header/context mismatch')
        if type(entries) not in (tuple, list) or len(entries) != header.distinct_tokens:
            raise ContractError('entry count mismatch')
        seen, rows_seen = set(), set()
        for entry in entries:
            if type(entry) is not TokenRows:
                raise ContractError('TokenRows required')
            require_bytes(entry.token, 'token', 32)
            encode_fixed_rows(entry.rows, header.parameters.c_max, header.ell)
            if entry.token in seen or rows_seen.intersection(entry.rows):
                raise ContractError('duplicate token or row ownership')
            seen.add(entry.token)
            rows_seen.update(entry.rows)
        if len(rows_seen) != header.ell:
            raise ContractError('entries must partition complete policy rows')
        entries = tuple(sorted(entries, key=lambda entry: entry.token))
        seed_source = secrets.token_bytes if seed_source is None else seed_source
        slot_source = secrets.token_bytes if slot_source is None else slot_source
        u = len(entries)
        length = max(4, (3*u+5)//2)
        if metrics is not None:
            metrics.status = 'EXECUTED'
            metrics.u, metrics.segment_length, metrics.m_af = u, length, 3*length
            metrics.slot_payload_bytes = header.parameters.payload_bytes
            metrics.attempts = metrics.peel_failures = 0
            metrics.build_success = False
        for attempt in range(1, MAX_ATTEMPTS+1):
            seed = seed_source(SEED_BYTES)
            meta = AFMetadata(AF_PROFILE, MYABE08_ENCODING_V1, header.sys_id,
                              header.ell, u, header.parameters.c_max, length,
                              3*length, seed, header.parameters.payload_bytes)
            edges = [fuse_positions(seed, e.token, length) for e in entries]
            stack = _peel(edges, meta.m_af)
            if metrics is not None:
                metrics.attempts = metrics.seed_attempts = attempt
            if len(stack) != u:
                if metrics is not None:
                    metrics.peel_failures += 1
                continue
            values = [protect_row_payload(e.rows, ctx_af, e.token, meta) for e in entries]
            slots = [slot_source(meta.slot_payload_bytes) for _ in range(meta.m_af)]
            for slot in slots:
                require_bytes(slot, 'slot randomness', meta.slot_payload_bytes)
            for edge_id, pivot in reversed(stack):
                slots[pivot] = xor_slots([values[edge_id]] +
                                         [slots[p] for p in edges[edge_id] if p != pivot])
            for edge, value in zip(edges, values):
                if xor_slots([slots[p] for p in edge]) != value:
                    raise AFBuildError('member equation verification failed')
            if metrics is not None:
                metrics.build_success = True
                metrics.slot_bytes = meta.m_af*meta.slot_payload_bytes
                metrics.metadata_bytes = len(encode_af_metadata(meta))
            return ProtectedAnonymousFilter(tuple(slots), meta)
        raise AFBuildError('32 peeling attempts exhausted')

    def query(self, index: ProtectedAnonymousFilter, token: bytes, *,
              header: AFHeader, ctx_af: bytes,
              metrics: Optional[AFMetrics] = None) -> AFQueryResult:
        if metrics is not None:
            metrics.status = 'EXECUTED'
            metrics.queries += 1
        try:
            if type(index) is not ProtectedAnonymousFilter:
                raise ContractError('filter required')
            meta = index.metadata
            validate_metadata(meta)
            if (compute_ctx_af(header) != ctx_af or meta.sys_id != header.sys_id
                    or meta.ell != header.ell or meta.u != header.distinct_tokens
                    or meta.c_max != header.parameters.c_max):
                raise ContractError('AF binding mismatch')
            if type(index.slots) is not tuple or len(index.slots) != meta.m_af:
                raise ContractError('wrong slot count')
            for slot in index.slots:
                require_bytes(slot, 'slot', meta.slot_payload_bytes)
            positions = fuse_positions(meta.seed_af, token, meta.segment_length)
            payload = xor_slots([index.slots[p] for p in positions])
            rows = open_row_payload(payload, ctx_af, token, meta)
        except (ContractError, AuthenticationError) as exc:
            if metrics is not None:
                metrics.misses += 1
                if isinstance(exc, AuthenticationError):
                    metrics.auth_failures += 1
                else:
                    metrics.parse_failures += 1
            return AFQueryResult(False, ())
        if metrics is not None:
            metrics.hits += 1
            metrics.decoded_payloads = (metrics.decoded_payloads or 0)+1
        return AFQueryResult(True, rows)
