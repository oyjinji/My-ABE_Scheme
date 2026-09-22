"""Functionally equivalent fixed-width static retrieval structures."""

from .base import (
    BuildFailure, RetrievalResult, StaticRetrieval, make_value,
    parse_serialized,
)
from .bloomier import BloomierRetrieval
from .cuckoo_payload import CuckooPayloadRetrieval
from .fxabf_retrieval import FXABFRetrieval
from .legacy_abf import LegacyABFRetrieval
from .plain_xor import PlainXorRetrieval


RETRIEVALS = {
    "Legacy ABF retrieval": LegacyABFRetrieval,
    "Bloomier retrieval": BloomierRetrieval,
    "Cuckoo payload table": CuckooPayloadRetrieval,
    "Plain XOR retrieval": PlainXorRetrieval,
    "FX-ABF retrieval": FXABFRetrieval,
}
TYPE_REGISTRY = {cls.type_id: cls for cls in RETRIEVALS.values()}


def create_retrieval(name, **options):
    try:
        return RETRIEVALS[name](**options)
    except KeyError as exc:
        raise ValueError("unknown retrieval %r" % name) from exc


def deserialize_retrieval(data):
    metadata, body = parse_serialized(data)
    try:
        cls = TYPE_REGISTRY[metadata["type_id"]]
    except KeyError as exc:
        raise ValueError("unknown serialized retrieval type") from exc
    return cls._from_serialized_parts(metadata, body)


__all__ = [
    "BuildFailure", "RetrievalResult", "StaticRetrieval", "make_value",
    "create_retrieval", "deserialize_retrieval", "RETRIEVALS",
    "LegacyABFRetrieval", "BloomierRetrieval", "CuckooPayloadRetrieval",
    "PlainXorRetrieval", "FXABFRetrieval",
]
