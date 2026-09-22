"""cProfile attribution for representative workloads (l=160).

Profiles FABEO22 Encrypt, FXABE-Base Encrypt, FXABE-Full Encrypt, and
FXABE-Base/FXABE-Full Transform.  Profiler numbers are for *attribution only*,
never a replacement for the formal benchmark.  Outputs pstats files and a
top-30 cumulative-time listing per profile in src/experiments/global_exp/audit/profiles/.
"""

import cProfile
import io
import os
import pstats
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
sys.path.insert(0, ROOT)

from charm.toolbox.pairinggroup import PairingGroup

from experiments.global_exp.src.adapters import create_adapter
from experiments.global_exp.src.workloads import build_workload

GROUP = PairingGroup("MNT224", secparam=512)
PROF_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "profiles")
L = 160


def profile(label, fn):
    pr = cProfile.Profile()
    pr.enable()
    fn()
    pr.disable()
    out = os.path.join(PROF_DIR, label + ".stats")
    pr.dump_stats(out)
    s = io.StringIO()
    ps = pstats.Stats(pr, stream=s).sort_stats("cumulative")
    ps.print_stats(30)
    with open(os.path.join(PROF_DIR, label + ".txt"), "w") as f:
        f.write(s.getvalue())
    print("profiled %-22s -> %s.txt (%d calls)" % (
        label, label, ps.total_calls))


def make_state(scheme_name, seed):
    adapter = create_adapter(scheme_name, GROUP, capacity=64)
    scheme = adapter.new_scheme(seed)
    pp, msk = scheme.setup()
    w = build_workload(20260813, "profile", 1, L, user_attrs=L,
                       satisfaction_ratio=0.5)
    return adapter, scheme, pp, msk, w


def main():
    os.makedirs(PROF_DIR, exist_ok=True)

    for name in ("FABEO22", "FXABE-Base", "FXABE-Full"):
        adapter, scheme, pp, msk, w = make_state(name, 10000 + L)
        if name != "FABEO22":
            scheme.rev_key_upt(pp, 1)
        profile("encrypt_" + name, lambda: adapter.encrypt(
            scheme, pp, msk, w, 1, 1, seed=20260813))

    for name in ("FXABE-Base", "FXABE-Full"):
        adapter, scheme, pp, msk, w = make_state(name, 20000 + L)
        prov = adapter.provision(scheme, pp, msk, w, "user-0", 1)
        scheme.rev_key_upt(pp, 1)  # publish AFTER user-0 is registered
        ct = adapter.encrypt(scheme, pp, msk, w, 1, 1, seed=20260813)
        ku = scheme.state["ku"][1]
        profile("transform_" + name, lambda: adapter.transform(
            scheme, pp, ct["ct"], prov["keys"], ku))
    print("done.")


if __name__ == "__main__":
    main()
