def test_revocation_epoch_update_does_not_rebuild_privacy_material(prepared):
    scheme, pp, msk = prepared
    static, private, recovery = scheme.keygen(pp, msk, "alice", ["A"], 5)
    ku1 = scheme.rev_key_upt(pp, 1)
    ct = scheme.encrypt(pp, msk, b"x", "A", 5, 1, filter_seed=8)
    builds = scheme.fx_build_count
    token = private["items"][0]["token_bytes"]
    index_identity = id(ct["index"])
    ku2 = scheme.rev_key_upt(pp, 2)
    assert scheme.fx_build_count == builds
    assert private["items"][0]["token_bytes"] == token
    assert id(ct["index"]) == index_identity
    assert ku1 is not ku2 and static is scheme.state["user_state"]["alice"]["tk_static"]
    assert recovery is scheme.state["user_state"]["alice"]["rk"]


def test_privacy_epoch_changes_only_private_key(prepared):
    scheme, pp, msk = prepared
    static, private1, recovery = scheme.keygen(pp, msk, "alice", ["A"], 1)
    ku = scheme.rev_key_upt(pp, 1)
    tree = scheme.state["tree"]
    node_secrets = dict(scheme.state["node_secret"])
    private2 = scheme.privacy_key_upt(pp, msk, "alice", 2)
    assert private1["items"][0]["token_bytes"] != private2["items"][0]["token_bytes"]
    assert private1["items"][0]["K_x"] != private2["items"][0]["K_x"]
    assert static is scheme.state["user_state"]["alice"]["tk_static"]
    assert recovery is scheme.state["user_state"]["alice"]["rk"]
    assert tree is scheme.state["tree"] and node_secrets == scheme.state["node_secret"]
    assert ku is scheme.state["ku"][1]
