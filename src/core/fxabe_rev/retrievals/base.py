"""Common contract, value encoding and canonical binary serialization."""

import abc
import hashlib
import hmac
import json
import math
import random
import struct
from dataclasses import dataclass, field

from ..encoding import encode


MAGIC = b"FXRET1\0"
FORMAT_VERSION = 1
CHECK_DOMAIN = "FX-Retrieval-Check-v1"


@dataclass
class RetrievalResult:
    hit: bool
    value: bytes = b""
    reason: str = "miss"
    metrics: dict = field(default_factory=dict)


class BuildFailure(RuntimeError):
    def __init__(self, message, stats):
        super().__init__(message)
        self.stats = dict(stats)


def sha256_domain(domain, *parts):
    """The one SHA-256/canonical-encoding helper used by every retrieval."""
    return hashlib.sha256(encode([domain] + list(parts))).digest()


def identifier_bits(u):
    return max(1, math.ceil(math.log2(u))) if u > 1 else 1


def value_width_bytes(b_j, delta):
    return (int(b_j) + 7) // 8 + (int(delta) + 7) // 8


def make_value(token, identifier, b_j, delta=64):
    """Encode_bj(j) || delta-bit check, padded only to whole bytes."""
    b_j = int(b_j)
    delta = int(delta)
    identifier = int(identifier)
    if identifier < 0 or identifier >= (1 << b_j):
        raise ValueError("identifier does not fit b_j")
    identifier_bytes = identifier.to_bytes((b_j + 7) // 8, "big")
    check_width = (delta + 7) // 8
    check = sha256_domain(
        CHECK_DOMAIN, token, b_j, delta, identifier_bytes
    )[:check_width]
    if delta % 8:
        check = bytes([check[0] & ((1 << (delta % 8)) - 1)]) + check[1:]
    return identifier_bytes + check


def validate_value(token, value, b_j, delta):
    width = value_width_bytes(b_j, delta)
    if not isinstance(value, bytes) or len(value) != width:
        return False
    identifier_width = (b_j + 7) // 8
    identifier_bytes = value[:identifier_width]
    identifier = int.from_bytes(identifier_bytes, "big")
    if identifier >= (1 << b_j):
        return False
    expected = make_value(token, identifier, b_j, delta)[identifier_width:]
    return hmac.compare_digest(value[identifier_width:], expected)


def xor_bytes(left, right):
    return bytes(a ^ b for a, b in zip(left, right))


def random_bytes(rng, width):
    return bytes(rng.getrandbits(8) for _ in range(width))


class StaticRetrieval(abc.ABC):
    """Static token-to-fixed-width-value retrieval without an exact locator."""

    name = "abstract"
    type_id = "abstract"

    def __init__(self, delta=64, **options):
        self.delta = int(delta)
        self.options = dict(options)
        self.u = 0
        self.b_j = 0
        self.value_width = 0
        self._stats = {}

    @abc.abstractmethod
    def build(self, mapping, rng=None):
        raise NotImplementedError

    @abc.abstractmethod
    def query(self, token):
        raise NotImplementedError

    @abc.abstractmethod
    def _structure_bytes(self):
        raise NotImplementedError

    @abc.abstractmethod
    def _load_structure_bytes(self, metadata, body):
        raise NotImplementedError

    def stats(self):
        return dict(self._stats)

    def _functional_metadata(self):
        return {
            "format_version": FORMAT_VERSION,
            "name": self.name,
            "type_id": self.type_id,
            "u": self.u,
            "b_j": self.b_j,
            "delta": self.delta,
            "value_width": self.value_width,
        }

    def serialize(self):
        metadata = json.dumps(
            self._functional_metadata(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        body = self._structure_bytes()
        return MAGIC + struct.pack(">I", len(metadata)) + metadata + body

    def serialized_size_bytes(self):
        return len(self.serialize())

    def size_breakdown(self):
        metadata = json.dumps(
            self._functional_metadata(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        body = self._structure_bytes()
        return {
            "structure_bytes": len(body),
            "metadata_bytes": len(MAGIC) + 4 + len(metadata),
            "serialized_bytes": len(MAGIC) + 4 + len(metadata) + len(body),
        }

    @classmethod
    def _from_serialized_parts(cls, metadata, body):
        obj = cls(delta=int(metadata["delta"]))
        obj.u = int(metadata["u"])
        obj.b_j = int(metadata["b_j"])
        obj.value_width = int(metadata["value_width"])
        obj._load_structure_bytes(metadata, body)
        obj._stats = {
            "deserialized": True,
            "success": True,
            "final_capacity": int(metadata["capacity"]),
        }
        return obj

    def _validate_mapping(self, mapping):
        if not isinstance(mapping, dict) or not mapping:
            raise ValueError("retrieval build requires a nonempty mapping")
        u = len(mapping)
        b_j = identifier_bits(u)
        width = value_width_bytes(b_j, self.delta)
        items = []
        for token, value in mapping.items():
            if not isinstance(token, bytes):
                raise TypeError("tokens must be bytes")
            if not isinstance(value, bytes) or len(value) != width:
                raise ValueError("all values must use the common fixed width")
            if not validate_value(token, value, b_j, self.delta):
                raise ValueError("value does not contain the common token check")
            items.append((token, value))
        return tuple(items), u, b_j, width

    @staticmethod
    def _rng(rng):
        return rng if rng is not None else random.SystemRandom()


def parse_serialized(data):
    if not isinstance(data, bytes) or not data.startswith(MAGIC):
        raise ValueError("invalid retrieval serialization magic")
    offset = len(MAGIC)
    if len(data) < offset + 4:
        raise ValueError("truncated retrieval metadata length")
    length = struct.unpack(">I", data[offset:offset + 4])[0]
    offset += 4
    if len(data) < offset + length:
        raise ValueError("truncated retrieval metadata")
    metadata = json.loads(data[offset:offset + length].decode("utf-8"))
    if int(metadata["format_version"]) != FORMAT_VERSION:
        raise ValueError("unsupported retrieval format")
    return metadata, data[offset + length:]
