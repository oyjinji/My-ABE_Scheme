"""Strict MYABE08_ENCODING_V1; explicit values only, no object serializer."""

from dataclasses import dataclass
import struct
from typing import Tuple, Union

from .errors import ContractError
from .profile import MYABE08_ENCODING_V1, ROW_KDF_DOMAIN, AF_NONCE_DOMAIN

MAX_ENCODING_BYTES = 16 * 1024 * 1024
MAX_NESTING = 64
BYTES, STRING, UINT32, UINT64, SCALAR32, LIST, TUPLE, RECORD = range(1, 9)


def require_bytes(value, name, length=None):
    if type(value) is not bytes or (length is not None and len(value) != length):
        raise ContractError("%s must be exact bytes%s" %
                            (name, "" if length is None else " of length %d" % length))


def require_uint(value, bits, name):
    if type(value) is not int or not 0 <= value < (1 << bits):
        raise ContractError("%s must be uint%d (no coercion)" % (name, bits))


@dataclass(frozen=True)
class UInt32:
    value: int

    def __post_init__(self):
        require_uint(self.value, 32, "UInt32")


@dataclass(frozen=True)
class UInt64:
    value: int

    def __post_init__(self):
        require_uint(self.value, 64, "UInt64")


@dataclass(frozen=True)
class FixedScalarBytes:
    """32-byte framing only; scalar FIELD RANGE is validated by the backend."""
    value: bytes

    def __post_init__(self):
        require_bytes(self.value, "fixed scalar", 32)


@dataclass(frozen=True)
class StructuredRecord:
    """Named schema, explicit ordered fields; not a dict/dataclass serializer."""
    schema: str
    fields: Tuple[Tuple[str, "CanonicalValue"], ...]

    def __post_init__(self):
        if type(self.schema) is not str or not self.schema:
            raise ContractError("record schema must be a nonempty string")
        if type(self.fields) is not tuple:
            raise ContractError("record fields must be an ordered tuple")
        names = []
        for item in self.fields:
            if (type(item) is not tuple or len(item) != 2
                    or type(item[0]) is not str or not item[0]):
                raise ContractError("record field must be a named (name, value) tuple")
            names.append(item[0])
        if len(names) != len(set(names)):
            raise ContractError("duplicate record field name")


CanonicalValue = Union[bytes, str, UInt32, UInt64, FixedScalarBytes,
                       list, tuple, StructuredRecord]


def _frame(tag, payload):
    if len(payload) + 5 > MAX_ENCODING_BYTES:
        raise ContractError("encoding exceeds V1 size limit")
    return bytes([tag]) + struct.pack(">I", len(payload)) + payload


def _encode(value, depth):
    if depth > MAX_NESTING:
        raise ContractError("encoding exceeds V1 nesting limit")
    t = type(value)
    if t is bytes:
        return _frame(BYTES, value)
    if t is str:
        try:
            return _frame(STRING, value.encode("utf-8", errors="strict"))
        except UnicodeError as exc:
            raise ContractError("invalid UTF-8 string") from exc
    if t is UInt32:
        return _frame(UINT32, struct.pack(">I", value.value))
    if t is UInt64:
        return _frame(UINT64, struct.pack(">Q", value.value))
    if t is FixedScalarBytes:
        return _frame(SCALAR32, value.value)
    if t in (list, tuple):
        tag, children = (LIST if t is list else TUPLE), value
        prefix = struct.pack(">I", len(value))
    elif t is StructuredRecord:
        tag = RECORD
        children = [value.schema]
        for name, child in value.fields:
            children.extend((name, child))
        prefix = struct.pack(">I", len(value.fields))
    else:
        raise ContractError("unsupported V1 type; explicit typed value required")
    parts, length = [prefix], len(prefix)
    for child in children:
        part = _encode(child, depth + 1)
        length += len(part)
        if length + 5 > MAX_ENCODING_BYTES:
            raise ContractError("encoding exceeds V1 size limit")
        parts.append(part)
    return _frame(tag, b"".join(parts))


def encode(value: CanonicalValue) -> bytes:
    return _encode(value, 0)


def decode(data: bytes) -> CanonicalValue:
    require_bytes(data, "encoded input")
    if len(data) > MAX_ENCODING_BYTES:
        raise ContractError("encoding exceeds V1 size limit")

    def parse(offset, limit, depth):
        if depth > MAX_NESTING or offset + 5 > limit:
            raise ContractError("truncated frame or excessive nesting")
        tag = data[offset]
        size = int.from_bytes(data[offset + 1:offset + 5], "big")
        start, end = offset + 5, offset + 5 + size
        if end > limit:
            raise ContractError("truncated frame payload")
        if tag == BYTES:
            return data[start:end], end
        if tag == STRING:
            try:
                return data[start:end].decode("utf-8", errors="strict"), end
            except UnicodeError as exc:
                raise ContractError("invalid UTF-8") from exc
        if tag in (UINT32, UINT64, SCALAR32):
            width = {UINT32: 4, UINT64: 8, SCALAR32: 32}[tag]
            if size != width:
                raise ContractError("non-canonical fixed-width integer/scalar")
            raw = data[start:end]
            result = (FixedScalarBytes(raw) if tag == SCALAR32 else
                      (UInt32 if tag == UINT32 else UInt64)(int.from_bytes(raw, "big")))
            return result, end
        if tag not in (LIST, TUPLE, RECORD):
            raise ContractError("invalid type tag")
        if size < 4:
            raise ContractError("missing element count")
        count = int.from_bytes(data[start:start + 4], "big")
        offset = start + 4
        minimum_frames = count if tag != RECORD else 1 + 2 * count
        if minimum_frames > (end - offset) // 5:
            raise ContractError("element count exceeds payload")
        if tag == RECORD:
            schema, offset = parse(offset, end, depth + 1)
            fields = []
            for _ in range(count):
                name, offset = parse(offset, end, depth + 1)
                child, offset = parse(offset, end, depth + 1)
                fields.append((name, child))
            result = StructuredRecord(schema, tuple(fields))
        else:
            result = []
            for _ in range(count):
                child, offset = parse(offset, end, depth + 1)
                result.append(child)
            if tag == TUPLE:
                result = tuple(result)
        if offset != end:
            raise ContractError("extra bytes inside composite frame")
        return result, end

    value, end = parse(0, len(data), 0)
    if end != len(data):
        raise ContractError("extra trailing bytes")
    return value


def _row_bounds(c_max, ell):
    require_uint(c_max, 32, "c_max")
    require_uint(ell, 32, "ell")
    if c_max == 0 or ell == 0:
        raise ContractError("c_max and ell must be positive")
    if 4 * (c_max + 1) > MAX_ENCODING_BYTES:
        raise ContractError("fixed payload exceeds V1 allocation limit")


def encode_fixed_rows(rows: Tuple[int, ...], c_max: int, ell: int) -> bytes:
    _row_bounds(c_max, ell)
    if type(rows) not in (list, tuple) or not 1 <= len(rows) <= c_max:
        raise ContractError("invalid row list length/type")
    previous = 0
    for row in rows:
        require_uint(row, 32, "row")
        if not previous < row <= ell:
            raise ContractError("rows must be strictly increasing and within 1..ell")
        previous = row
    values = (len(rows),) + tuple(rows) + (0,) * (c_max - len(rows))
    return struct.pack(">%dI" % (c_max + 1), *values)


def decode_fixed_rows(data: bytes, c_max: int, ell: int) -> Tuple[int, ...]:
    _row_bounds(c_max, ell)
    require_bytes(data, "fixed rows", 4 * (c_max + 1))
    values = struct.unpack(">%dI" % (c_max + 1), data)
    h = values[0]
    if not 1 <= h <= c_max or any(values[h + 1:]):
        raise ContractError("invalid length or nonzero bottom padding")
    rows = values[1:h + 1]
    if encode_fixed_rows(rows, c_max, ell) != data:
        raise ContractError("non-canonical row payload")
    return rows


def encode_attribute(namespace: str, name: str, value: str) -> bytes:
    if any(type(x) is not str for x in (namespace, name, value)):
        raise ContractError("attribute fields must be strings")
    return encode(StructuredRecord("MYABE08.AttributeV1", (
        ("namespace", namespace), ("name", name), ("value", value))))


def validate_attribute(data: bytes) -> None:
    value = decode(data)
    if (type(value) is not StructuredRecord or value.schema != "MYABE08.AttributeV1"
            or tuple(n for n, _ in value.fields) != ("namespace", "name", "value")
            or any(type(v) is not str for _, v in value.fields)):
        raise ContractError("expected canonical AttributeV1 record")


def encode_priv_context(sys_id: bytes, policy_context_id: bytes, policy_version: int) -> bytes:
    require_bytes(sys_id, "SysID")
    require_bytes(policy_context_id, "PolicyContextID")
    if not sys_id or len(policy_context_id) < 32:
        raise ContractError("empty SysID or PolicyContextID shorter than 256 bits")
    return encode(("PRIV", sys_id, policy_context_id, UInt64(policy_version)))


def encode_token_input(sys_id: bytes, ctx_priv: bytes, canonical_attribute: bytes) -> bytes:
    require_bytes(sys_id, "SysID")
    require_bytes(ctx_priv, "ctx_priv", 32)
    if not sys_id:
        raise ContractError("empty SysID")
    validate_attribute(canonical_attribute)
    return encode(("MYABE-TOK", sys_id, ctx_priv, canonical_attribute))


def encode_row_kdf_input(ctx_af: bytes, token: bytes) -> bytes:
    require_bytes(ctx_af, "ctx_AF", 32)
    require_bytes(token, "token", 32)
    return encode((ROW_KDF_DOMAIN, ctx_af, token))


def encode_af_nonce_input(ctx_af: bytes, token: bytes) -> bytes:
    require_bytes(ctx_af, "ctx_AF", 32)
    require_bytes(token, "token", 32)
    return encode((AF_NONCE_DOMAIN, ctx_af, token))


def encode_dem_ad(ctx_ct: bytes) -> bytes:
    require_bytes(ctx_ct, "ctx_CT", 32)
    return encode(("DEM", ctx_ct))
