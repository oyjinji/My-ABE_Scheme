from core.fxabe_rev.serialization import dumps, loads, serialized_size


def test_group_and_byte_serialization_roundtrip(prepared):
    scheme, pp, _ = prepared
    value = {"g1": pp["g1"], "raw": b"abc", "items": (1, "x")}
    encoded = dumps(value, scheme.group)
    decoded = loads(encoded, scheme.group)
    assert decoded["g1"] == pp["g1"]
    assert decoded["raw"] == b"abc" and decoded["items"] == (1, "x")
    assert serialized_size(value, scheme.group) == len(encoded)
