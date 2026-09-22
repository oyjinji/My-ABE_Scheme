from Code.fxabe_rev import FXABERev
from Rev_Exp.src.revocation import measured_rev_key_upt, serialize_ku


def test_ku_size_is_canonical_wire_size(group):
    scheme = FXABERev(group, user_capacity=8, scheme_seed=101)
    pp, _ = scheme.setup()
    for index in range(8):
        scheme.state["tree"].register("user-%d" % index)
    scheme.state["tree"].revoke("user-3", 1)
    ku, metrics = measured_rev_key_upt(scheme, pp, 1)
    wire, metadata = serialize_ku(ku, group)
    assert len(wire) == metrics.ku_serialized_bytes
    assert metadata == metrics.ku_metadata_bytes
    assert metrics.ku_g2_elements == 2 * metrics.cover_size
    assert len(wire) > metadata
