"""Workload identity: all schemes consume the same policy, matrix, rho,
user set and message for every experimental point (requirement 5.1/5.2)."""

from Code.fxabe_rev.lsss import policy_rows

from Global_Exp.src.common import derive_seed, fingerprint
from Global_Exp.src.workloads import (
    build_workload, or_policy, policy_matrix, policy_rho, user_set_for,
)

MS = 20260812


def _workload(l, S):
    return build_workload(MS, "test", derive_seed(MS, "test", l, S), l, S, 0.5)


def test_or_policy_maps_to_l_rows(group):
    """OR policy over l attrs -> exactly l unit LSSS rows for every scheme."""
    for l in (4, 8, 16):
        workload = _workload(l, l)
        rows, rho = policy_rows(group, workload.policy)
        assert len(rows) == l
        assert rho == workload.rho
        assert rows == policy_matrix(l)
        assert all(len(row) == 1 for row in rows)
        assert workload.policy == or_policy(l)


def test_workload_deterministic():
    first = _workload(8, 8)
    second = _workload(8, 8)
    assert first.fingerprints == second.fingerprints
    assert first.user_set == second.user_set
    assert first.message_bytes == second.message_bytes


def test_satisfaction_ratio_exact_for_even_l():
    for l in (8, 16, 32, 64):
        workload = _workload(l, l)
        assert workload.satisfaction_ratio == 0.5
        assert workload.satisfied_rows == l // 2
        assert workload.policy_cols == 1


def test_user_set_structure():
    workload = _workload(8, 10)
    satisfying = workload.user_set[:workload.satisfied_rows]
    extras = workload.user_set[workload.satisfied_rows:]
    assert all(attr.startswith("P") for attr in satisfying)
    assert all(attr.startswith("U") for attr in extras)
    assert len(set(workload.user_set)) == len(workload.user_set)
    assert workload.universe_size == 8 + len(extras)


def test_fingerprints_distinguish_points():
    a = _workload(8, 8)
    b = _workload(16, 8)
    assert a.fingerprints["policy_hash"] != b.fingerprints["policy_hash"]
    assert fingerprint(a.user_set) != fingerprint(b.user_set)


def test_shared_workload_cross_scheme(group):
    """The same workload object drives every scheme end-to-end.

    Each adapter receives the *same* object; this test pins that invariant so
    a future refactor cannot split the workloads into per-scheme variants.
    All three must encrypt and decrypt the identical message.
    """
    from charm.toolbox.pairinggroup import GT

    from Global_Exp.src.adapters import create_adapter
    workload = _workload(8, 8)
    hashes = [workload.fingerprints[k] for k in (
        "policy_hash", "matrix_hash", "rho_hash", "user_set_hash",
        "message_hash")]
    assert len(set(hashes)) == len(hashes)  # distinct field families
    for scheme_name in ("FABEO22", "FXABE-Base", "FXABE-Full"):
        adapter = create_adapter(scheme_name, group)
        scheme = adapter.new_scheme(derive_seed(MS, "test", "scheme", 1))
        setup = adapter.setup(scheme, 1)
        prov = adapter.provision(scheme, setup["pk"], setup["msk"], workload,
                                 "user-0", "privacy-1")
        if scheme_name != "FABEO22":
            # publish a revocation epoch so a ciphertext can be created
            scheme.state["tree"].register("user-1")
            scheme.rev("user-1", 1)
            scheme.rev_key_upt(setup["pk"], 1)
        enc = adapter.encrypt(scheme, setup["pk"], setup["msk"], workload,
                              "privacy-1", 1,
                              seed=derive_seed(MS, "test", "filter", 1))
        if scheme_name == "FABEO22":
            out = adapter.decrypt(scheme, setup["pk"], enc["ct"], prov["keys"])
            assert out["msg"] == group.init(GT, workload.message_gt_int)
        else:
            tr = adapter.transform(scheme, setup["pk"], enc["ct"],
                                   prov["keys"], scheme.state["ku"][1])
            assert tr["status"] == "ok"
            out = adapter.final_dec(scheme, setup["pk"], tr["transformed"],
                                    prov["keys"])
            assert out["msg"] == workload.message_bytes
