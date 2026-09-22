"""Canonical, length-prefixed encodings used by FXDACP.

The encoder is deliberately small and self-contained.  It never relies on
``repr`` or delimiter concatenation for cryptographic inputs.
"""

import struct


def _frame(tag, payload):
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    return tag + struct.pack(">I", len(payload)) + payload


def encode(value):
    """Encode the supported Python value subset canonically."""
    if value is None:
        return _frame(b"N", b"")
    if isinstance(value, bool):
        return _frame(b"B", b"\x01" if value else b"\x00")
    if isinstance(value, int):
        sign = b"\x01" if value < 0 else b"\x00"
        magnitude = abs(value)
        body = b"\x00" if magnitude == 0 else magnitude.to_bytes(
            (magnitude.bit_length() + 7) // 8, "big"
        )
        return _frame(b"I", sign + body)
    if isinstance(value, float):
        return _frame(b"F", struct.pack(">d", value))
    if isinstance(value, str):
        return _frame(b"S", value.encode("utf-8"))
    if isinstance(value, (bytes, bytearray)):
        return _frame(b"Y", bytes(value))
    if isinstance(value, (list, tuple)):
        return _frame(b"L", b"".join(encode(item) for item in value))
    if isinstance(value, dict):
        pairs = []
        for key, item in value.items():
            encoded_key = encode(key)
            pairs.append((encoded_key, encode(item)))
        pairs.sort(key=lambda pair: pair[0])
        return _frame(b"D", b"".join(k + v for k, v in pairs))
    raise TypeError("unsupported canonical type: {0}".format(type(value).__name__))


def encode_group(group, element):
    return _frame(b"G", group.serialize(element))


def canonical_attribute(attribute, epoch, version="1", system="FXDACP", namespace="default"):
    """Bind every attribute to version, domain, namespace, name/value and epoch.

    String attributes use the explicit name ``attribute`` and the string as
    their value.  A mapping may override ``namespace``, ``name`` and ``value``.
    """
    if isinstance(attribute, dict):
        attr_namespace = str(attribute.get("namespace", namespace))
        if "name" not in attribute or "value" not in attribute:
            raise ValueError("attribute mappings require name and value")
        name = str(attribute["name"])
        value = str(attribute["value"])
    else:
        attr_namespace = str(namespace)
        name = "attribute"
        value = str(attribute)
    return encode({
        "version": str(version),
        "system": str(system),
        "namespace": attr_namespace,
        "name": name,
        "value": value,
        "epoch": str(epoch),
    })


def encode_posting_list(rows):
    rows = list(rows)
    if rows != sorted(rows) or len(rows) != len(set(rows)):
        raise ValueError("posting list must be strictly increasing")
    if any(not isinstance(row, int) or row < 1 for row in rows):
        raise ValueError("posting row ids must be positive integers")
    return struct.pack(">I", len(rows)) + b"".join(struct.pack(">I", row) for row in rows)


def decode_posting_list(data, ell):
    if not isinstance(data, bytes) or len(data) < 4:
        raise ValueError("truncated posting list")
    count = struct.unpack(">I", data[:4])[0]
    if len(data) != 4 + 4 * count:
        raise ValueError("non-canonical posting list length")
    rows = [struct.unpack(">I", data[4 + 4*i:8 + 4*i])[0] for i in range(count)]
    if rows != sorted(rows) or len(rows) != len(set(rows)):
        raise ValueError("posting list is not strictly increasing")
    if any(row < 1 or row > ell for row in rows):
        raise ValueError("posting row id outside ciphertext range")
    return rows
