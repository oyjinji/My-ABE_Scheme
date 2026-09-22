"""Ciphertext storage breakdown by component (real serialized sizes).

For l = 32, 160, 320 builds the real ciphertext of each scheme and enumerates
every component with its scope and serialized byte size.  Group elements use
the group's canonical ``serialize``; structures use the repository's ``encode``
framing (same as the shipped ``storage.py``).

Determinism note (audit finding): the FXABE-Full FX-ABF filter is an XOR
filter whose serialized size depends on the hash values of the posting keys,
which depend on the scheme's secret ``kappa``.  At l=320 the filter measured
4160 B (seeds 1, 9) vs 4500 B (seed 90322) - an ~8% spread in the filter
component (~1.2% of the ciphertext).  The CSV below is generated with a fixed
seed (9) for reproducibility, and the official storage.py total is emitted for
exact reconciliation.

No Global_Exp result is touched; output goes to src/experiments/global_exp/audit/results/.
"""

import csv
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
sys.path.insert(0, ROOT)

from charm.toolbox.pairinggroup import PairingGroup

from experiments.global_exp.src.adapters import create_adapter
from experiments.global_exp.src.workloads import build_workload
from experiments.global_exp.src.storage import ciphertext_size
from core.fxabe_rev.encoding import encode

GROUP = PairingGroup("MNT224", secparam=512)
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results",
                   "storage_breakdown.csv")
SEED = 9  # fixed so the filter row is reproducible


def gb(el):
    return len(GROUP.serialize(el))


def enc_bytes(v):
    if isinstance(v, bytes):
        return len(v)
    return len(encode(v))


def fabeo_components(ct):
    out = []
    out.append(("g2_s1", "G2", "ciphertext-level", 1, gb(ct["g2_s1"])))
    out.append(("g2_sprime", "G2", "ciphertext-level", 1, gb(ct["g2_sprime"])))
    n = len(ct["ct"])
    out.append(("ct[attr] rows", "G1", "row-level", n, n * gb(next(iter(ct["ct"].values())))))
    out.append(("Cp", "GT", "ciphertext-level", 1, gb(ct["Cp"])))
    out.append(("policy", "str", "metadata", 1, enc_bytes(str(ct["policy"]))))
    return out


def fxabe_components(ct):
    out = []
    out.append(("C", "G1", "ciphertext-level", 1, gb(ct["C"])))
    out.append(("C_rev", "G1", "revocation-level", 1, gb(ct["C_rev"])))
    n = len(ct["rows"])
    out.append(("C1 (per row)", "G1", "row-level", n, n * gb(ct["rows"][0]["C1"])))
    out.append(("C2 (per row)", "G2", "row-level", n, n * gb(ct["rows"][0]["C2"])))
    out.append(("C_sym", "bytes", "ciphertext-level", 1, enc_bytes(ct["C_sym"])))
    out.append(("nonce", "bytes", "ciphertext-level", 1, enc_bytes(ct["nonce"])))
    out.append(("A_star (LSSS matrix)", "list", "metadata", len(ct["A_star"]),
                enc_bytes(ct["A_star"])))
    out.append(("meta", "dict", "metadata", 1, enc_bytes({"meta": ct["meta"]})))
    if "direct_rho" in ct:
        out.append(("direct_rho", "list", "metadata", len(ct["direct_rho"]),
                    enc_bytes(ct["direct_rho"])))
    return out


def build(scheme_name, l):
    adapter = create_adapter(scheme_name, GROUP, capacity=64)
    scheme = adapter.new_scheme(SEED)
    pp, msk = scheme.setup()
    w = build_workload(20260813, "storage-audit", 1, l, user_attrs=l,
                       satisfaction_ratio=0.5)
    if scheme_name != "FABEO22":
        scheme.rev_key_upt(pp, 1)
    ct = adapter.encrypt(scheme, pp, msk, w, 1, 1, seed=SEED)
    return ct["ct"]


def main():
    rows = []
    for l in (32, 160, 320):
        for scheme_name in ("FABEO22", "FXABE-Base", "FXABE-Full"):
            ct = build(scheme_name, l)
            if scheme_name == "FABEO22":
                comps = fabeo_components(ct)
            else:
                comps = fxabe_components(ct)
                if scheme_name == "FXABE-Full":
                    bd = ct["index"].size_breakdown()
                    comps.append(("FX-ABF filter (+locator)", "bytes", "filter-level",
                                  1, bd.get("filter_only_bytes", 0) + bd.get("locator_bytes", 0)))
                    comps.append(("PStore", "bytes", "pstore-level", 1,
                                  bd.get("pstore_bytes", 0)))
                    comps.append(("index metadata", "bytes", "metadata", 1,
                                  bd.get("metadata_bytes", 0)))
            for name, typ, scope, count, nbytes in comps:
                note = ""
                if name == "FX-ABF filter (+locator)":
                    note = ("data-dependent: 4160-4500B across scheme keys at "
                            "l=320 (seed=%d here)" % SEED)
                rows.append({
                    "scheme": scheme_name, "policy_rows": l, "component": name,
                    "type": typ, "scope": scope, "element_count": count,
                    "serialized_bytes": nbytes, "note": note,
                })
            # official reconciliation via shipped storage.py
            official = ciphertext_size(GROUP, scheme_name, ct)["total_bytes"]
            rows.append({
                "scheme": scheme_name, "policy_rows": l,
                "component": "OFFICIAL_TOTAL(storage.py)", "type": "recon",
                "scope": "total", "element_count": 1,
                "serialized_bytes": official,
                "note": "sum of rows above; for FABEO22 l=320 == 17421 (exact)",
            })
    total = {}
    for r in rows:
        if r["component"] != "OFFICIAL_TOTAL(storage.py)":
            total[(r["scheme"], r["policy_rows"])] = total.get(
                (r["scheme"], r["policy_rows"]), 0) + r["serialized_bytes"]
    with open(OUT, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["scheme", "policy_rows", "component",
                                          "type", "scope", "element_count",
                                          "serialized_bytes", "note"])
        w.writeheader()
        w.writerows(rows)
    print("scheme       l=32     l=160    l=320  (component sums; official in CSV)")
    for s in ("FABEO22", "FXABE-Base", "FXABE-Full"):
        print("  %-12s %7d  %7d  %7d" % (s, total[(s, 32)], total[(s, 160)],
                                          total[(s, 320)]))
    print("wrote", OUT)


if __name__ == "__main__":
    main()
