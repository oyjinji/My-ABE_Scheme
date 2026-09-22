"""Diagnostic: fixed policy (l=32), vary the number of matched rows m.

Same OR policy (l=32), three user attribute sets with m = 1, 8, 16 matched
rows.  Theory: OR policy min authorized subset = 1, so Transform should only
need 2 revocation + 2 row pairings regardless of m.  Measures what the real
scheme does: matched rows, pair_count, Transform time.  Diagnostic only —
does not overwrite any Global_Exp result.
"""

import csv
import os
import sys
from time import perf_counter_ns

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
sys.path.insert(0, ROOT)

from charm.toolbox.pairinggroup import PairingGroup

from experiments.global_exp.src.adapters import create_adapter

GROUP = PairingGroup("MNT224", secparam=512)
# GLOBAL_EXP_AUDIT_OUT redirects the output directory, so this can be run
# without rewriting the committed CSV; unset, it writes where it always has.
OUT = os.path.join(os.environ.get("GLOBAL_EXP_AUDIT_OUT")
                   or os.path.join(os.path.dirname(os.path.abspath(__file__)), "results"),
                   "diagnostic_m_sweep.csv")

L = 32


def user_set_for_m(m):
    return ["P%04d" % i for i in range(m)] + ["U%04d" % i for i in range(32 - m)]


def run(scheme_name, m, seed):
    adapter = create_adapter(scheme_name, GROUP, capacity=64)
    scheme = adapter.new_scheme(seed)
    pp, msk = scheme.setup()
    w = type("W", (), {"policy": "(P0000 or P0001 or P0002 or P0003 or P0004 or P0005 or P0006 or P0007 or P0008 or P0009 or P0010 or P0011 or P0012 or P0013 or P0014 or P0015 or P0016 or P0017 or P0018 or P0019 or P0020 or P0021 or P0022 or P0023 or P0024 or P0025 or P0026 or P0027 or P0028 or P0029 or P0030 or P0031)",
                       "user_set": user_set_for_m(m),
                       "message_bytes": b"x" * 32})()
    prov = adapter.provision(scheme, pp, msk, w, "user-0", 1)
    scheme.rev_key_upt(pp, 1)
    ct = adapter.encrypt(scheme, pp, msk, w, 1, 1, seed=seed + 1)
    ku = scheme.state["ku"][1]
    # warm
    adapter.transform(scheme, pp, ct["ct"], prov["keys"], ku)
    best = None
    for _ in range(5):
        t = perf_counter_ns()
        tr = adapter.transform(scheme, pp, ct["ct"], prov["keys"], ku)
        ms = (perf_counter_ns() - t) / 1e6
        best = ms if best is None else min(best, ms)
    return {
        "scheme": scheme_name,
        "policy_rows": L,
        "matched_rows": m,
        "actual_pair_count": tr["pair_count"],
        "transform_ms": round(best, 3),
        "status": tr["status"],
    }


def main():
    rows = []
    for scheme_name in ("FXABE-Base", "FXABE-Full"):
        for m in (1, 8, 16):
            seed = 40000 + m + (0 if scheme_name.endswith("Base") else 100)
            rows.append(run(scheme_name, m, seed))
    print("scheme        l  m  pair_count  transform_ms")
    for r in rows:
        print("  %-12s %2d %2d  %3d       %8.2f" % (
            r["scheme"], r["policy_rows"], r["matched_rows"],
            r["actual_pair_count"], r["transform_ms"]))
    with open(OUT, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print("wrote", OUT)


if __name__ == "__main__":
    main()
