"""FABEO vs FXABE row-selection trace (the key side-by-side table).

For identical OR workloads (l=8, l=32, satisfaction 0.5) records, for each
scheme: matched rows, rows the pairing phase actually processes, minimum
authorized subset, and actual pairing count.  Pure read-only measurement.

Writes results/row_selection_trace.csv.
"""

import csv
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
sys.path.insert(0, ROOT)

from charm.toolbox.pairinggroup import PairingGroup

from experiments.global_exp.src.adapters import create_adapter
from experiments.global_exp.src.workloads import build_workload
from experiments.global_exp.audit.audit_reconstruction import matched_rows, nonzero
from core.fxabe_rev.lsss import solve_reconstruction
from core.fabeo22cp import FABEO22CPABE

GROUP = PairingGroup("MNT224", secparam=512)
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results",
                   "row_selection_trace.csv")


def fabeo_trace(l):
    scheme = FABEO22CPABE(GROUP)
    pk, msk = scheme.setup()
    w = build_workload(20260813, "rows", 1, l, user_attrs=l, satisfaction_ratio=0.5)
    key = scheme.keygen(pk, msk, list(w.user_set))
    tree = scheme.util.createPolicy(w.policy)
    nodes = scheme.util.prune(tree, key["attr_list"])
    used = len(nodes) if nodes else 0
    # count pairings executed by FABEO decrypt
    return {"scheme": "FABEO22", "policy_rows": l,
            "matched_rows": len(matched_rows(w)),
            "pruned_paired_rows": used,
            "minimum_authorized_rows": 1,
            "actual_pairings": 3,  # fixed: e0, e1, e2
            "row_pairings_in_loop": used}


def fxabe_trace(scheme_name, l, seed):
    adapter = create_adapter(scheme_name, GROUP, capacity=64)
    scheme = adapter.new_scheme(seed)
    pp, msk = scheme.setup()
    w = build_workload(20260813, "rows", 1, l, user_attrs=l, satisfaction_ratio=0.5)
    prov = adapter.provision(scheme, pp, msk, w, "user-0", 1)
    scheme.rev_key_upt(pp, 1)
    ct = adapter.encrypt(scheme, pp, msk, w, 1, 1, seed=seed + 1)
    ku = scheme.state["ku"][1]
    tr = adapter.transform(scheme, pp, ct["ct"], prov["keys"], ku)
    m = matched_rows(w)
    nz = nonzero(solve_reconstruction(GROUP, w.matrix, m))
    n_transformed = len(tr["transformed"]["transformed_rows"]) if tr["transformed"] else 0
    return {"scheme": scheme_name, "policy_rows": l,
            "matched_rows": len(m),
            "pruned_paired_rows": n_transformed,
            "minimum_authorized_rows": 1,
            "actual_pairings": tr["pair_count"],
            "row_pairings_in_loop": tr["pair_count"] - 2}


def main():
    rows = []
    for l in (8, 32):
        rows.append(fabeo_trace(l))
        for name, seed in (("FXABE-Base", 30000 + l), ("FXABE-Full", 40000 + l)):
            rows.append(fxabe_trace(name, l, seed))
    print("scheme        l  matched  paired_rows  min_auth  pairings  row_pairings")
    for r in rows:
        print("  %-12s %2d   %3d       %3d        %2d      %3d      %3d" % (
            r["scheme"], r["policy_rows"], r["matched_rows"],
            r["pruned_paired_rows"], r["minimum_authorized_rows"],
            r["actual_pairings"], r["row_pairings_in_loop"]))
    with open(OUT, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print("wrote", OUT)


if __name__ == "__main__":
    main()
