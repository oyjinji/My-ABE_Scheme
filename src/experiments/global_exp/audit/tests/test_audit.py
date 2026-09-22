"""Read-only assertions for the performance-complexity audit.

These verify the audit's central claims against the real code (no scheme
modification): the OR-policy LSSS has a minimum authorized subset of 1,
FXABE's transform pairs every matched row (Case A), FABEO's prune selects
exactly one node, and the reconstruction uses a single nonzero coefficient.
"""

import itertools
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

import pytest
from charm.toolbox.pairinggroup import PairingGroup, ZR

from experiments.global_exp.src.adapters import create_adapter
from experiments.global_exp.src.workloads import build_workload
from core.fxabe_rev.lsss import solve_reconstruction


@pytest.fixture(scope="module")
def group():
    return PairingGroup("MNT224", secparam=512)


def _workload(l, group, satisfaction=0.5):
    return build_workload(20260813, "audit-test", 1, l, user_attrs=l,
                          satisfaction_ratio=satisfaction)


def _matched(w):
    user = set(map(str, w.user_set))
    return [i + 1 for i, a in enumerate(w.rho) if str(a) in user]


def _nonzero(coeffs):
    return {k: v for k, v in coeffs.items() if int(v) != 0}


def test_or_policy_minimum_authorized_subset_is_one(group):
    w = _workload(8, group)
    # every single unit row alone reconstructs the target [1]
    for row_id in range(1, 9):
        coeffs = solve_reconstruction(group, w.matrix, [row_id])
        assert coeffs is not None
        assert {int(v) for v in coeffs.values()} == {1}


def test_or_policy_reconstruction_over_matched_uses_one_row(group):
    w = _workload(8, group)
    m = _matched(w)
    assert len(m) == 4
    nz = _nonzero(solve_reconstruction(group, w.matrix, m))
    assert list(nz.keys()) == [1]  # only the first matched row gets coeff 1


def test_fxabe_transform_pair_count_equals_2_plus_2_matched(group):
    adapter = create_adapter("FXABE-Base", group, capacity=64)
    scheme = adapter.new_scheme(111)
    pp, msk = scheme.setup()
    w = _workload(8, group)
    prov = adapter.provision(scheme, pp, msk, w, "user-0", 1)
    scheme.rev_key_upt(pp, 1)
    ct = adapter.encrypt(scheme, pp, msk, w, 1, 1, seed=2)
    tr = adapter.transform(scheme, pp, ct["ct"], prov["keys"],
                           scheme.state["ku"][1])
    assert tr["pair_count"] == 2 + 2 * len(_matched(w))


def test_fabeo_prune_selects_single_node(group):
    from core.fabeo22cp import FABEO22CPABE
    scheme = FABEO22CPABE(group)
    pk, msk = scheme.setup()
    w = _workload(8, group)
    key = scheme.keygen(pk, msk, list(w.user_set))
    nodes = scheme.util.prune(scheme.util.createPolicy(w.policy),
                              key["attr_list"])
    assert nodes is not None and len(nodes) == 1


def test_solve_reconstruction_returned_zeros_not_filtered_in_charm(group):
    # Charm 0.63: ZR(0) != 0 is True, so solve_reconstruction's own
    # ``if coeff != 0`` filter does not drop zero coefficients.
    z = group.init(ZR, 0)
    assert z != 0


def test_transform_rows_sent_to_pairable_dict_equals_matched(group):
    adapter = create_adapter("FXABE-Base", group, capacity=64)
    scheme = adapter.new_scheme(222)
    pp, msk = scheme.setup()
    w = _workload(8, group)
    prov = adapter.provision(scheme, pp, msk, w, "user-0", 1)
    scheme.rev_key_upt(pp, 1)
    ct = adapter.encrypt(scheme, pp, msk, w, 1, 1, seed=3)
    tr = adapter.transform(scheme, pp, ct["ct"], prov["keys"],
                           scheme.state["ku"][1])
    assert len(tr["transformed"]["transformed_rows"]) == len(_matched(w))
