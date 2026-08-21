"""Encryption scaling: FABEO22 / FXABE-Base / FXABE-Full at l=16..128.

Small run (3 warm-ups, 5 reps) to distinguish fixed vs per-row encryption
cost.  Also micro-benchmarks the raw group operations (pair, G1/G2/GT exp,
hash-to-group) that feed the operation ledger.

No Global_Exp result is touched; output goes to Global_Exp/audit/results/.
"""

import csv
import os
import sys
from time import perf_counter_ns

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, ROOT)

from charm.toolbox.pairinggroup import PairingGroup, G1, G2, GT, ZR, pair

from Global_Exp.src.adapters import create_adapter
from Global_Exp.src.workloads import build_workload

GROUP = PairingGroup("MNT224", secparam=512)
OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")


def micro_benchmark():
    g1, g2 = GROUP.random(G1), GROUP.random(G2)
    gt = GROUP.random(GT)
    z = GROUP.random(ZR)
    items = []

    def bench(label, fn, n=150):
        for _ in range(5):
            fn()
        t = perf_counter_ns()
        for _ in range(n):
            fn()
        items.append((label, (perf_counter_ns() - t) / n / 1e6))

    bench("pair(g1,g2)", lambda: pair(g1, g2))
    bench("g1 ** z", lambda: g1 ** z)
    bench("g2 ** z", lambda: g2 ** z)
    bench("gt ** z", lambda: gt ** z)
    bench("hash->G1", lambda: GROUP.hash("a", G1))
    bench("hash->G2", lambda: GROUP.hash("a", G2))
    bench("hash->ZR", lambda: GROUP.hash("a", ZR))
    bench("g1*g1", lambda: g1 * g1)
    bench("g2*g2", lambda: g2 * g2)
    bench("zr*zr", lambda: z * z)
    with open(os.path.join(OUT_DIR, "operation_costs.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["operation", "ms_per_op"])
        for label, ms in items:
            w.writerow([label, round(ms, 4)])
    print("operation_costs.csv written")
    for label, ms in items:
        print("  %-10s %8.4f ms" % (label, ms))


def run_encrypt(scheme_name, l, seed, warmups=3, reps=5):
    adapter = create_adapter(scheme_name, GROUP, capacity=64)
    scheme = adapter.new_scheme(seed)
    pp, msk = scheme.setup()
    w = build_workload(20260813, "encrypt-scaling", 1, l, user_attrs=l,
                       satisfaction_ratio=0.5)
    if scheme_name != "FABEO22":
        scheme.rev_key_upt(pp, 1)
    # warm-ups (fresh ciphertext each, no caching)
    for _ in range(warmups):
        adapter.encrypt(scheme, pp, msk, w, 1, 1, seed=seed)
    times = []
    for _ in range(reps):
        t = perf_counter_ns()
        adapter.encrypt(scheme, pp, msk, w, 1, 1, seed=seed)
        times.append((perf_counter_ns() - t) / 1e6)
    times.sort()
    return times[len(times) // 2]  # median


def main():
    micro_benchmark()
    rows = []
    for l in (16, 32, 64, 128):
        for scheme_name in ("FABEO22", "FXABE-Base", "FXABE-Full"):
            seed = 70000 + l + (0 if scheme_name == "FABEO22" else
                                1000 if scheme_name == "FXABE-Base" else 2000)
            med = run_encrypt(scheme_name, l, seed)
            rows.append({
                "scheme": scheme_name, "policy_rows": l, "encrypt_median_ms": med,
                "ms_per_policy_row": round(med / l, 4),
            })
            print("  %-12s l=%3d  encrypt=%8.2f ms  (%.3f ms/row)" % (
                scheme_name, l, med, med / l))
    with open(os.path.join(OUT_DIR, "encrypt_operation_scaling.csv"),
              "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print("wrote encrypt_operation_scaling.csv")


if __name__ == "__main__":
    main()
