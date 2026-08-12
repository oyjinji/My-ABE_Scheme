from Code.fxabe_rev import TransformMetrics


def _roundtrip(prepared, attrs, policy):
    scheme, pp, msk = prepared
    static, private, recovery = scheme.keygen(pp, msk, "alice", attrs, 7)
    ku = scheme.rev_key_upt(pp, 9)
    ciphertext = scheme.encrypt(pp, msk, b"message", policy, 7, 9, filter_seed=1)
    metrics = TransformMetrics()
    transformed = scheme.transform(pp, ciphertext, static, private, ku, metrics)
    return scheme.final_dec(pp, transformed, recovery), metrics


def test_satisfied_unrevoked_decrypts(prepared):
    plaintext, metrics = _roundtrip(prepared, ["A", "B"], "(A and B)")
    assert plaintext == b"message"
    assert metrics.pairing_count == 2 + 2 * metrics.r == 6


def test_unsatisfied_finaldec_fails(prepared):
    plaintext, metrics = _roundtrip(prepared, ["A"], "(A and B)")
    assert plaintext is None
    assert metrics.r == 1


def test_mixed_user_transform_and_recovery_keys_fail(prepared):
    scheme, pp, msk = prepared
    a_static, a_private, a_rk = scheme.keygen(pp, msk, "alice", ["A"], 1)
    _, _, b_rk = scheme.keygen(pp, msk, "bob", ["A"], 1)
    ku = scheme.rev_key_upt(pp, 1)
    ct = scheme.encrypt(pp, msk, b"bound", "A", 1, 1, filter_seed=2)
    transformed = scheme.transform(pp, ct, a_static, a_private, ku)
    assert scheme.final_dec(pp, transformed, a_rk) == b"bound"
    assert scheme.final_dec(pp, transformed, b_rk) is None
