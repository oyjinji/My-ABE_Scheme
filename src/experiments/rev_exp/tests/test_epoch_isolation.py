from core.fxabe_rev import FXABERev
from experiments.rev_exp.src.revocation import measured_rev_key_upt


def _prepared(group):
    scheme = FXABERev(group, user_capacity=4, scheme_seed=73)
    pp, msk = scheme.setup()
    static, private, recovery = scheme.keygen(pp, msk, "alice", ["A", "B"], 1)
    ku1, _ = measured_rev_key_upt(scheme, pp, 1)
    ct = scheme.encrypt(pp, msk, b"x", "(A and B)", 1, 1, filter_seed=8)
    return scheme, pp, msk, static, private, recovery, ku1, ct


def test_c10_revocation_epoch_update_preserves_privacy_side(group):
    scheme, pp, _, static, private, recovery, ku1, ct = _prepared(group)
    tokens = tuple(item["token_bytes"] for item in private["items"])
    fx = ct["index"]
    pstore = fx.state["pstore"]
    builds = scheme.fx_build_count
    ku2, _ = measured_rev_key_upt(scheme, pp, 2)
    assert tuple(item["token_bytes"] for item in private["items"]) == tokens
    assert ct["index"] is fx and fx.state["pstore"] is pstore
    assert scheme.fx_build_count == builds
    assert scheme.state["user_state"]["alice"]["tk_static"] is static
    assert scheme.state["user_state"]["alice"]["rk"] is recovery
    assert ku2 is not ku1


def test_c11_privacy_epoch_changes_only_token_and_tk_priv(group):
    scheme, pp, msk, static, private, recovery, ku, _ = _prepared(group)
    tree = scheme.state["tree"]
    leaf = tree.user_leaf["alice"]
    path = tree.path("alice")
    node_secrets = dict(scheme.state["node_secret"])
    user = scheme.state["user_state"]["alice"]
    eta, z = user["eta"], user["z"]
    updated = scheme.privacy_key_upt(pp, msk, "alice", 2)
    assert [x["token_bytes"] for x in private["items"]] != [x["token_bytes"] for x in updated["items"]]
    assert [x["K_x"] for x in private["items"]] != [x["K_x"] for x in updated["items"]]
    assert scheme.state["tree"] is tree and tree.user_leaf["alice"] == leaf
    assert tree.path("alice") == path and scheme.state["node_secret"] == node_secrets
    assert user["tk_static"] is static and user["rk"] is recovery
    assert user["eta"] == eta and user["z"] == z
    assert scheme.state["ku"][1] is ku

