"""Audit A: OR-policy reconstruction — matched vs authorized vs used rows.

Answers, with real code execution (no guesses):

* what the OR-policy LSSS matrix / rho / user set actually look like
* which rows FABEO's ``prune`` selects (Charm policytree)
* which rows FXABE's Transform pairs (Case A: all matched rows?)
* how many of those rows ``final_dec`` actually uses (nonzero coefficients)
* the *minimum* authorized subset size (brute force for small l)
* actual pair_count vs policy_rows / matched_rows / reconstruction_rows

No scheme equations are modified.  This is a read-only diagnostic.
"""

import csv
import itertools
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, ROOT)

from charm.toolbox.pairinggroup import PairingGroup

from Global_Exp.src.adapters import create_adapter
from Global_Exp.src.workloads import build_workload
from Code.fxabe_rev.lsss import solve_reconstruction

GROUP = PairingGroup("MNT224", secparam=512)
OUT_DIR = os.path.dirname(os.path.abspath(__file__))


def workload(l, master_seed=20260813):
    # user_attrs = l so satisfied = ceil(l*0.5); the extra U attrs fill out.
    return build_workload(master_seed, "audit", 1, l, user_attrs=l,
                          satisfaction_ratio=0.5)


def matched_rows(workload):
    """Rows whose rho attribute is in the user set."""
    user = set(map(str, workload.user_set))
    return [i + 1 for i, attr in enumerate(workload.rho) if str(attr) in user]


def nonzero(coeffs):
    """Count coefficients that are genuinely non-zero (int-converted)."""
    return {k: v for k, v in coeffs.items() if int(v) != 0}


def reconstructs_target(matrix, row_ids, coeffs):
    """Verify sum(coeff_i * row_i) == [1, 0, ..., 0] after padding."""
    width = max(len(row) for row in matrix)
    padded = [list(row) + [0] * (width - len(row)) for row in matrix]
    vec = [0] * width
    for row_id, coeff in coeffs.items():
        c = int(coeff)
        if c == 0:
            continue
        row = padded[row_id - 1]
        for j in range(width):
            vec[j] += c * row[j]
    target = [1] + [0] * (width - 1)
    return vec == target


def min_authorized_subset_bruteforce(matrix, row_ids):
    """Smallest subset of row_ids that reconstructs target vector [1,0,...].

    A subset is authorized iff there is a coefficient assignment (from
    solve_reconstruction) that is genuinely nonzero somewhere AND reconstructs
    the target.  (Charm 0.63 returns ``{i: ZR(0)}`` for degenerate subsets, so
    we verify the actual linear combination, not just a non-None return.)
    """
    for size in range(1, len(row_ids) + 1):
        for combo in itertools.combinations(row_ids, size):
            coeffs = solve_reconstruction(GROUP, matrix, list(combo))
            if coeffs is not None and nonzero(coeffs) \
                    and reconstructs_target(matrix, list(combo), coeffs):
                return size, list(combo)
    return None, None


def trace_or_policy(l):
    w = workload(l)
    print("\n" + "=" * 78)
    print(f"OR-policy trace  l={l}")
    print("=" * 78)
    print("policy :", w.policy)
    print("matrix :", w.matrix)
    print("rho    :", w.rho)
    print("user_set:", w.user_set)
    m = matched_rows(w)
    print("matched_rows:", m, f"(len={len(m)})")
    # Solve reconstruction over the matched rows (what final_dec would do).
    coeffs = solve_reconstruction(GROUP, w.matrix, m)
    print("solve_reconstruction(matched):", coeffs)
    nz = nonzero(coeffs) if coeffs else {}
    print("nonzero-coefficient rows:", nz)
    rec_rows = sorted(nz.keys())
    print("reconstruction_rows actually used by final_dec (nonzero):", rec_rows)
    min_size, min_subset = min_authorized_subset_bruteforce(w.matrix, m)
    print(f"minimum_authorized_subset: size={min_size} e.g. {min_subset}")
    return w, m, coeffs, rec_rows, min_size, min_subset


def trace_fabeo(l):
    """What FABEO22 decrypt actually uses (prune -> node list -> 3 pairings)."""
    from Code.fabeo22cp import FABEO22CPABE
    scheme = FABEO22CPABE(GROUP)
    pk, msk = scheme.setup()
    w = workload(l)
    key = scheme.keygen(pk, msk, list(w.user_set))
    tree = scheme.util.createPolicy(w.policy)
    nodes = scheme.util.prune(tree, key["attr_list"])
    used = [n.getAttributeAndIndex() for n in nodes] if nodes else []
    print("\n[FABEO22] prune of OR policy with user_set:")
    print("  pruned nodes:", used)
    return used


def run_dynamic_paircount(l):
    """Real FXABE-Base transform: matched rows, pair_count, rec rows."""
    adapter = create_adapter("FXABE-Base", GROUP, capacity=64)
    scheme = adapter.new_scheme(20260813 + l)
    pp, msk = scheme.setup()
    w = workload(l)
    prov = adapter.provision(scheme, pp, msk, w, "user-0", 1)
    # publish one revocation epoch so encrypt/transform are valid
    scheme.rev_key_upt(pp, 1)
    ct = adapter.encrypt(scheme, pp, msk, w, 1, 1, seed=20260813 + l)
    ku = scheme.state["ku"][1]
    tr = adapter.transform(scheme, pp, ct["ct"], prov["keys"], ku)
    m = matched_rows(w)
    coeffs = solve_reconstruction(GROUP, w.matrix, m)
    nz = nonzero(coeffs) if coeffs else {}
    # OR: any single unit row is a legal authorized subset (brute-verified l=8)
    min_size, _ = min_authorized_subset_bruteforce(w.matrix, m)
    return {
        "policy_rows": l,
        "matched_rows": len(m),
        "reconstruction_rows": len(nz),  # rows final_dec actually consumes
        "minimum_reconstruction_rows": min_size or 1,
        "actual_pair_count": tr["pair_count"],
        "transform_ms": tr["transform_ms"],
        "transform_status": tr["status"],
    }


def main():
    rows = []
    # --- detailed small trace ---
    w, m, coeffs, rec_rows, min_size, min_subset = trace_or_policy(8)
    trace_fabeo(8)
    print("\n[FXABE-Base] transform at l=8 (dynamic):")
    r = run_dynamic_paircount(8)
    print("  ", r)
    rows.append(r)

    # --- threshold contrast: 2-of-3 ---
    print("\n[CONTRAST] 2-of-3 threshold policy (not OR):")
    th_policy = "(P0000 and P0001) or (P0000 and P0002) or (P0001 and P0002)"
    from Code.fxabe_rev.lsss import policy_rows
    t_matrix, t_rho = policy_rows(GROUP, th_policy)
    print("  matrix:", t_matrix, "rho:", t_rho)
    t_ids = list(range(1, len(t_matrix) + 1))
    ts, tsb = min_authorized_subset_bruteforce(t_matrix, t_ids)
    print(f"  minimum_authorized_subset over all rows: size={ts} e.g. {tsb}")

    # --- pair_count vs reconstruction size table ---
    print("\n" + "=" * 78)
    print("pair_count vs policy_rows / matched / reconstruction rows (dynamic)")
    print("=" * 78)
    for l in (8, 16, 32, 64):
        rows.append(run_dynamic_paircount(l))
    for r in rows:
        print("  l=%3d matched=%3d rec_rows=%3d min_rec=1  pair_count=%3d  "
              "transform_ms=%.1f  status=%s" % (
                  r["policy_rows"], r["matched_rows"], r["reconstruction_rows"],
                  r["actual_pair_count"], r["transform_ms"], r["transform_status"]))

    out = os.path.join(OUT_DIR, "results", "reconstruction_trace.csv")
    with open(out, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print("\nwrote", out)


if __name__ == "__main__":
    main()
