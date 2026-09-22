from Code.fxabe_rev import TransformMetrics
from Code.fxabe_rev.revocation import KUNodes


def test_cover_boundaries_and_intersections(prepared):
    scheme, pp, msk = prepared
    keys = {}
    for user in ("a", "b", "c", "d"):
        keys[user] = scheme.keygen(pp, msk, user, ["A"], 1)
    tree = scheme.state["tree"]
    assert KUNodes(tree, 1) == (1,)
    scheme.rev("b", 2)
    cover = set(KUNodes(tree, 2))
    for user in ("a", "c", "d"):
        assert len(set(tree.path(user)) & cover) == 1
    assert not (set(tree.path("b")) & cover)
    scheme.rev("a", 3)
    scheme.rev("c", 3)
    scheme.rev("d", 3)
    assert KUNodes(tree, 3) == ()


def test_revoked_transform_fails_before_row_pairing(prepared):
    scheme, pp, msk = prepared
    static, private, _ = scheme.keygen(pp, msk, "alice", ["A"], 1)
    scheme.rev("alice", 1)
    ku = scheme.rev_key_upt(pp, 1)
    ct = scheme.encrypt(pp, msk, b"x", "A", 1, 1, filter_seed=3)
    metrics = TransformMetrics()
    assert scheme.transform(pp, ct, static, private, ku, metrics) is None
    assert metrics.row_pairing_ns == 0 and metrics.pairing_count == 0


def test_old_ku_rejects_new_epoch_ciphertext(prepared):
    scheme, pp, msk = prepared
    static, private, _ = scheme.keygen(pp, msk, "alice", ["A"], 1)
    old_ku = scheme.rev_key_upt(pp, 1)
    scheme.rev_key_upt(pp, 2)
    ct = scheme.encrypt(pp, msk, b"x", "A", 1, 2, filter_seed=4)
    metrics = TransformMetrics()
    assert scheme.transform(pp, ct, static, private, old_ku, metrics) is None
    assert metrics.pairing_count == 0
