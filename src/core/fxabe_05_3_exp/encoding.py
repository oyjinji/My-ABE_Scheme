"""Canonical encodings used by the 05.3 experiment profile."""

import struct


def _frame(tag, payload):
    return tag + struct.pack(">I", len(payload)) + payload


def encode(value):
    if value is None:
        return _frame(b"N", b"")
    if isinstance(value, bool):
        return _frame(b"B", b"\1" if value else b"\0")
    if isinstance(value, int):
        sign = b"\1" if value < 0 else b"\0"
        n = abs(value)
        body = b"\0" if n == 0 else n.to_bytes((n.bit_length() + 7) // 8, "big")
        return _frame(b"I", sign + body)
    if isinstance(value, float):
        return _frame(b"F", struct.pack(">d", value))
    if isinstance(value, str):
        return _frame(b"S", value.encode("utf-8"))
    if isinstance(value, (bytes, bytearray)):
        return _frame(b"Y", bytes(value))
    if isinstance(value, (list, tuple)):
        return _frame(b"L", b"".join(encode(x) for x in value))
    if isinstance(value, dict):
        pairs = sorted((encode(k), encode(v)) for k, v in value.items())
        return _frame(b"D", b"".join(k + v for k, v in pairs))
    raise TypeError("unsupported canonical type: %s" % type(value).__name__)


def encode_group(group, element):
    return _frame(b"G", group.serialize(element))


def encode_posting(rows):
    rows = tuple(rows)
    if not rows or rows != tuple(sorted(rows)) or len(rows) != len(set(rows)):
        raise ValueError("posting list must be nonempty, strict and sorted")
    if any(not isinstance(row, int) or row < 1 or row > 0xFFFFFFFF for row in rows):
        raise ValueError("posting row is outside uint32")
    return struct.pack(">I", len(rows)) + b"".join(struct.pack(">I", r) for r in rows)


def decode_posting(data, ell):
    if not isinstance(data, bytes) or len(data) < 8:
        raise ValueError("truncated posting list")
    count = struct.unpack(">I", data[:4])[0]
    if count < 1 or len(data) != 4 + 4 * count:
        raise ValueError("non-canonical posting length")
    rows = tuple(struct.unpack(">I", data[4 + 4*i:8 + 4*i])[0]
                 for i in range(count))
    if rows != tuple(sorted(rows)) or len(rows) != len(set(rows)):
        raise ValueError("posting list is not strict")
    if any(row < 1 or row > int(ell) for row in rows):
        raise ValueError("posting row outside ciphertext")
    return rows


def canonical_attribute(attribute, privacy_epoch, version="05.3"):
    return encode([
        "FXABE05.3/ATTRIBUTE", str(version), str(privacy_epoch),
        {"namespace": "default", "name": "attribute", "value": str(attribute)},
    ])
