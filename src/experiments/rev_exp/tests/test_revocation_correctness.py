from core.fxabe_rev import FXABERev, TransformMetrics
from experiments.rev_exp.src.revocation import measured_rev_key_upt


def _scheme(group, capacity=8, seed=19):
    scheme = FXABERev(group, user_capacity=capacity, scheme_seed=seed)
    pp, msk = scheme.setup()
    return scheme, pp, msk


def test_c4_satisfied_and_unrevoked_transform_finaldec(group):
    scheme, pp, msk = _scheme(group)
    static, private, recovery = scheme.keygen(pp, msk, "alice", ["A", "B"], 1)
    ku, _ = measured_rev_key_upt(scheme, pp, 1)
    ct = scheme.encrypt(pp, msk, b"message", "(A and B)", 1, 1, filter_seed=1)
    metrics = TransformMetrics()
    transformed = scheme.transform(pp, ct, static, private, ku, metrics)
    assert scheme.final_dec(pp, transformed, recovery) == b"message"
    assert metrics.pairing_count == 2 + 2 * metrics.r == 6


def test_c5_satisfied_but_revoked_transform_fails(group):
    scheme, pp, msk = _scheme(group)
    static, private, _ = scheme.keygen(pp, msk, "alice", ["A"], 1)
    scheme.rev("alice", 1)
    ku, _ = measured_rev_key_upt(scheme, pp, 1)
    ct = scheme.encrypt(pp, msk, b"message", "A", 1, 1, filter_seed=2)
    metrics = TransformMetrics()
    assert scheme.transform(pp, ct, static, private, ku, metrics) is None
    assert metrics.status == "revoked-or-invalid-path"
    assert metrics.pairing_count == 0


def test_c6_unrevoked_but_policy_unsatisfied(group):
    scheme, pp, msk = _scheme(group)
    static, private, recovery = scheme.keygen(pp, msk, "alice", ["A"], 1)
    ku, _ = measured_rev_key_upt(scheme, pp, 1)
    ct = scheme.encrypt(pp, msk, b"message", "(A and B)", 1, 1, filter_seed=3)
    assert scheme.final_dec(pp, scheme.transform(pp, ct, static, private, ku), recovery) is None


def test_c7_c8_old_or_mismatched_ku_fails_closed(group):
    scheme, pp, msk = _scheme(group)
    static, private, recovery = scheme.keygen(pp, msk, "alice", ["A"], 1)
    ku1, _ = measured_rev_key_upt(scheme, pp, 1)
    ku2, _ = measured_rev_key_upt(scheme, pp, 2)
    ct2 = scheme.encrypt(pp, msk, b"message", "A", 1, 2, filter_seed=4)
    # C8: the honest old KU carries epoch 1 and is rejected before pairing.
    metrics = TransformMetrics()
    assert scheme.transform(pp, ct2, static, private, ku1, metrics) is None
    assert metrics.status == "metadata-failure" and metrics.pairing_count == 0
    # C7: even relabelling old algebraic components cannot decrypt an epoch-2
    # ciphertext; the residual h_1/h_2 term causes KEM-DEM authentication failure.
    relabelled_old = dict(ku1)
    relabelled_old["epoch"] = 2
    transformed = scheme.transform(pp, ct2, static, private, relabelled_old)
    assert transformed is not None
    assert scheme.final_dec(pp, transformed, recovery) is None
    # An arbitrary mismatched label also fails closed.
    bad = dict(ku2)
    bad["epoch"] = 999
    assert scheme.transform(pp, ct2, static, private, bad) is None


def test_c9_published_epoch_is_frozen(group):
    scheme, pp, msk = _scheme(group)
    scheme.keygen(pp, msk, "alice", ["A"], 1)
    measured_rev_key_upt(scheme, pp, 1)
    try:
        scheme.rev("alice", 1)
        assert False, "frozen epoch accepted a late revocation"
    except ValueError:
        pass
    scheme.rev("alice", 2)
    assert scheme.state["tree"].revoked_from["alice"] == 2


def test_c12_forward_not_backward_revocation(group):
    scheme, pp, msk = _scheme(group)
    static, private, recovery = scheme.keygen(pp, msk, "alice", ["A"], 1)
    ku1, _ = measured_rev_key_upt(scheme, pp, 1)
    ct1 = scheme.encrypt(pp, msk, b"old", "A", 1, 1, filter_seed=5)
    assert scheme.final_dec(pp, scheme.transform(pp, ct1, static, private, ku1), recovery) == b"old"
    scheme.rev("alice", 2)
    ku2, _ = measured_rev_key_upt(scheme, pp, 2)
    ct2 = scheme.encrypt(pp, msk, b"new", "A", 1, 2, filter_seed=6)
    assert scheme.transform(pp, ct2, static, private, ku2) is None
    assert scheme.final_dec(pp, scheme.transform(pp, ct1, static, private, ku1), recovery) == b"old"
