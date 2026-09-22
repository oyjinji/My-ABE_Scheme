import copy

import pytest
from charm.toolbox.pairinggroup import GT

from core.fabeo22cp import FABEO22CPABE
from core.fxabe_05_3_exp import FXABE053, NoOccurrenceFXABE, TransformMetrics
from core.fxabe_05_3_exp.lsss import policy_rows


def threshold_policy(n, k):
    return {"A": [[pow(x, power) for power in range(k)]
                  for x in range(1, n + 1)],
            "rho": ["T%d" % x for x in range(1, n + 1)]}


def and_policy(group, n, labels=None):
    text = "(" + " and ".join("X%d" % i for i in range(n)) + ")"
    matrix, rho = policy_rows(group, text)
    return {"A": matrix, "rho": labels or rho}


def roundtrip(group, policy, user_attrs, c_max=8, cls=FXABE053, seed=11):
    scheme = cls(group, user_capacity=16, c_max=c_max, seed=seed)
    pp, msk = scheme.setup()
    static, private, recovery = scheme.keygen(pp, msk, "alice", user_attrs, "p1")
    ku = scheme.rev_key_upt(pp, 1)
    sid = scheme.open_policy_session("owner", "p1", len(policy["rho"]))
    ct = scheme.encrypt(pp, msk, b"frozen-05.3", policy, "p1", ku, sid,
                        fx_seed=seed + 100)
    metrics = TransformMetrics()
    transformed = scheme.transform(pp, ct, static, private, ku, metrics)
    return scheme, pp, msk, static, private, recovery, ku, ct, transformed, metrics


@pytest.mark.parametrize("policy,attrs", [
    ({"A": [[1], [1], [1]], "rho": ["A", "B", "C"]}, ["B"]),
])
def test_or(group, policy, attrs):
    scheme, pp, _, _, _, rk, _, _, tr, metrics = roundtrip(group, policy, attrs)
    assert scheme.final_dec(pp, tr, rk) == b"frozen-05.3"
    assert (metrics.k, metrics.t_I, metrics.pair_count) == (1, 1, 4)


def test_and(group):
    policy = and_policy(group, 3)
    result = roundtrip(group, policy, policy["rho"])
    scheme, pp, _, _, _, rk, _, _, tr, metrics = result
    assert scheme.final_dec(pp, tr, rk) == b"frozen-05.3"
    assert metrics.k == 3 and metrics.pair_count == 3 + metrics.t_I


def test_threshold(group):
    policy = threshold_policy(5, 3)
    result = roundtrip(group, policy, ["T1", "T3", "T5"])
    scheme, pp, _, _, _, rk, _, _, tr, metrics = result
    assert scheme.final_dec(pp, tr, rk) == b"frozen-05.3"
    assert metrics.k == 3 and metrics.pair_count == 3 + metrics.t_I


def test_duplicate_and_later_occurrence(group):
    # Row 1 is a zero share for A. Reconstruction must use row 3, which is
    # A's authenticated second posting and therefore occurrence rank two.
    policy = {"A": [[0, 0], [1, 1], [0, -1]], "rho": ["A", "B", "A"]}
    result = roundtrip(group, policy, ["A", "B"], c_max=2)
    scheme, pp, _, _, _, rk, _, _, tr, metrics = result
    assert scheme.final_dec(pp, tr, rk) == b"frozen-05.3"
    assert metrics.k == 2 and metrics.t_I == 2 and metrics.pair_count == 5


def test_ti_greater_than_one(group):
    policy = and_policy(group, 4, ["D", "D", "D", "D"])
    result = roundtrip(group, policy, ["D"], c_max=4)
    scheme, pp, _, _, _, rk, _, _, tr, metrics = result
    assert scheme.final_dec(pp, tr, rk) == b"frozen-05.3"
    assert metrics.t_I == 4 and metrics.pair_count == 7


def test_privacy_epoch_and_revocation_gates(group):
    policy = {"A": [[1]], "rho": ["A"]}
    scheme = FXABE053(group, user_capacity=8, c_max=1, seed=31)
    pp, msk = scheme.setup()
    st_a, pr_a, rk_a = scheme.keygen(pp, msk, "alice", ["A"], "p1")
    scheme.keygen(pp, msk, "bob", ["A"], "p1")
    ku1 = scheme.rev_key_upt(pp, 1)
    sid = scheme.open_policy_session("owner", "p1", 1)
    ct1 = scheme.encrypt(pp, msk, b"epoch", policy, "p1", ku1, sid, fx_seed=4)
    assert scheme.final_dec(pp, scheme.transform(pp, ct1, st_a, pr_a, ku1), rk_a) == b"epoch"
    pr_wrong = scheme.privacy_key_upt(pp, msk, "alice", "p2")
    assert scheme.transform(pp, ct1, st_a, pr_wrong, ku1) is None
    scheme.rev("alice", 2)
    ku2 = scheme.rev_key_upt(pp, 2)
    assert scheme.transform(pp, ct1, st_a, pr_a, ku2) is None
    sid2 = scheme.open_policy_session("owner", "p1", 1)
    ct2 = scheme.encrypt(pp, msk, b"revoked", policy, "p1", ku2, sid2, fx_seed=5)
    assert scheme.transform(pp, ct2, st_a, pr_a, ku2) is None


def test_fx_hit_miss_tamper_and_no_locator(group):
    policy = {"A": [[1], [1]], "rho": ["A", "B"]}
    result = roundtrip(group, policy, ["A"], c_max=1)
    _, _, _, _, private, _, _, ct, _, _ = result
    token = private["items"][0]["token_bytes"]
    assert ct["index"].query(token, ct["ctx_fx"]).posting_list == (1,)
    assert not ct["index"].query(b"not-a-member", ct["ctx_fx"]).hit
    assert not ct["index"].has_exact_locator()
    original = ct["index"].slots[0]
    ct["index"].slots = (bytes([original[0] ^ 1]) + original[1:],) + ct["index"].slots[1:]
    # A changed slot may not be on this token's path, so tamper the matching
    # PStore record as the deterministic authenticated check.
    hit = ct["index"].query(token, ct["ctx_fx"])
    if hit.hit:
        records = list(ct["index"].pstore)
        rec = dict(records[0])
        rec["ciphertext"] = rec["ciphertext"][:-1] + bytes([rec["ciphertext"][-1] ^ 1])
        records[0] = rec
        ct["index"].pstore = tuple(records)
        assert not ct["index"].query(token, ct["ctx_fx"]).hit


def test_fresh_d_and_nooccurrence(group):
    policy = {"A": [[1], [1], [1]], "rho": ["A", "B", "C"]}
    first = roundtrip(group, policy, ["A"], c_max=4, seed=71)
    scheme, pp, msk, *_rest = first
    ku = first[6]
    sid = scheme.open_policy_session("owner", "p1", 3)
    ct2 = scheme.encrypt(pp, msk, b"second", policy, "p1", ku, sid, fx_seed=999)
    assert tuple(group.serialize(x) for x in first[7]["D"]) != tuple(group.serialize(x) for x in ct2["D"])
    noocc = roundtrip(group, policy, ["A"], c_max=4, cls=NoOccurrenceFXABE, seed=72)
    assert len(noocc[7]["D"]) == 3
    assert noocc[0].final_dec(noocc[1], noocc[8], noocc[5]) == b"frozen-05.3"


def test_unauthorized_and_policy_issuance_boundary(group):
    policy = threshold_policy(4, 3)
    result = roundtrip(group, policy, ["T1", "T2"], seed=91)
    assert result[8] is None and result[9].status == "unauthorized"
    scheme, _, msk = result[:3]
    with pytest.raises(PermissionError):
        scheme.policy_token_issuance(msk, ["T1"], "p1", "missing")


def test_blind_oprf_matches_token_algebra(group):
    scheme = FXABE053(group, user_capacity=2, c_max=1, seed=101)
    pp, msk = scheme.setup()
    scheme.state["tree"].register("u")
    sid = scheme.open_policy_session("owner", "p1", 1)
    issued = scheme.policy_token_issuance(msk, ["SECRET"], "p1", sid)["SECRET"]
    direct = scheme.oprf.direct("SECRET", "p1", msk["kappa"])
    assert issued == direct


def test_fabeo_official_roundtrip(group):
    scheme = FABEO22CPABE(group)
    pk, msk = scheme.setup()
    sk = scheme.keygen(pk, msk, ["A", "B"])
    message = group.random(GT)
    ct = scheme.encrypt(pk, message, "(A and B)")
    assert scheme.decrypt(pk, ct, sk) == message
