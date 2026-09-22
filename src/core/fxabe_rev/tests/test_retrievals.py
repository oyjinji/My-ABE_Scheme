import hashlib
import inspect
import random

from core.fxabe_rev.retrievals import (
    BloomierRetrieval, CuckooPayloadRetrieval, FXABFRetrieval,
    LegacyABFRetrieval, PlainXorRetrieval, RETRIEVALS, create_retrieval,
    deserialize_retrieval, make_value,
)


def _mapping(u=32):
    b_j = max(1, (u - 1).bit_length())
    tokens = [
        hashlib.sha256(("retrieval-token-%d" % i).encode()).digest()
        for i in range(u)
    ]
    return {
        token: make_value(token, identifier, b_j, 64)
        for identifier, token in enumerate(tokens)
    }


def _contains_token_key(value, tokens, seen=None):
    seen = set() if seen is None else seen
    marker = id(value)
    if marker in seen:
        return False
    seen.add(marker)
    if isinstance(value, dict):
        if any(key in tokens for key in value if isinstance(key, bytes)):
            return True
        return any(
            _contains_token_key(item, tokens, seen) for item in value.values()
        )
    if isinstance(value, (list, tuple)):
        return any(_contains_token_key(item, tokens, seen) for item in value)
    return False


def test_all_retrievals_return_same_value_and_survive_serialization():
    mapping = _mapping()
    for offset, name in enumerate(RETRIEVALS):
        retrieval = create_retrieval(name).build(
            mapping, random.Random(9000 + offset)
        )
        for token, expected in mapping.items():
            result = retrieval.query(token)
            assert result.hit and result.value == expected
        restored = deserialize_retrieval(retrieval.serialize())
        for token, expected in mapping.items():
            result = restored.query(token)
            assert result.hit and result.value == expected


def test_build_does_not_retain_token_mapping_and_query_has_no_dict_get():
    mapping = _mapping()
    tokens = set(mapping)
    for offset, cls in enumerate(RETRIEVALS.values()):
        retrieval = cls().build(mapping, random.Random(12000 + offset))
        assert not _contains_token_key(retrieval.__dict__, tokens)
        assert ".get(" not in inspect.getsource(cls.query)


def test_nonmembers_are_rejected_by_structure_check():
    mapping = _mapping()
    for offset, name in enumerate(RETRIEVALS):
        retrieval = create_retrieval(name).build(
            mapping, random.Random(15000 + offset)
        )
        for i in range(2000):
            token = hashlib.sha256(
                ("retrieval-nonmember-%s-%d" % (name, i)).encode()
            ).digest()
            assert not retrieval.query(token).hit


def test_payload_width_and_construction_identity():
    mapping = _mapping(64)
    plain = PlainXorRetrieval().build(mapping, random.Random(1))
    fx = FXABFRetrieval().build(mapping, random.Random(2))
    cuckoo = CuckooPayloadRetrieval().build(mapping, random.Random(3))
    bloomier = BloomierRetrieval().build(mapping, random.Random(4))
    legacy = LegacyABFRetrieval().build(mapping, random.Random(5))
    assert plain.value_width == fx.value_width
    assert plain.b_j + plain.delta == fx.b_j + fx.delta
    assert cuckoo.fingerprint_bits > 0
    assert all(
        record is None or len(record) == (
            cuckoo.fingerprint_width + cuckoo.value_width
        )
        for bucket in cuckoo.buckets for record in bucket
    )
    assert not hasattr(cuckoo, "locator")
    assert bloomier.query_hashes == 4
    assert bloomier.type_id != "plain-xor-v1"
    assert not hasattr(bloomier, "bits")
    assert not hasattr(bloomier, "locator")
    assert not hasattr(legacy, "locator")
