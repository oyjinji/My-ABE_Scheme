#!/usr/bin/env python3
"""Produce a conservative data-backed Full runtime estimate before execution."""

import argparse
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from Perf_Exp_05_3.scripts.common import read_csv  # noqa: E402


def main():
    parser = argparse.ArgumentParser(); parser.add_argument("standard_run")
    args = parser.parse_args(); standard = Path(args.standard_run).resolve()
    exp01 = read_csv(standard / "raw/exp01_encrypt.csv")
    def med(scheme, phase, ell):
        vals = [int(r["time_ns"]) for r in exp01 if r["scheme"] == scheme and r["phase"] == phase and int(r["ell"]) == ell]
        return statistics.median(vals) / 1e9
    # EXP-01 estimate models each real encrypt invocation. NoOccurrence's
    # unreported index-build portion is conservatively added from FX Full-Core.
    measured = [20, 40, 80, 160, 320, 640]
    fx = [med("FXABE-05.3 Full", "Full Encrypt", x) for x in measured]
    no_core = [med("FXABE-NoOccurrence Core", "Encrypt Core", x) for x in measured]
    overhead = [med("FXABE-05.3 Full", "Full Encrypt", x) - med("FXABE-05.3 Core", "Encrypt Core", x) for x in measured]
    fab = [med("FABEO", "Encrypt Core", x) for x in measured]
    exp01_seconds = 55 * (sum(fx) + 2 * fx[-1] + sum(a + b for a, b in zip(no_core, overhead)) +
                          2 * (no_core[-1] + overhead[-1]) + sum(fab) + 2 * fab[-1])
    estimates = [
        ("EXP-01 Encrypt Core", 7 * 3 * 55, exp01_seconds * 1.15, "linear endpoint extrapolation; 15% margin"),
        ("EXP-02 Storage", 7 * 3, 30, "deterministic canonical recomputation"),
        ("EXP-03 Transform vs J", 7 * 55, 180, "timed Transform plus one preparation per J"),
        ("EXP-04 Transform vs t_I", 4 * 55, 120, "timed Transform plus preparation"),
        ("EXP-06 FX Build", 7 * 55, 90, "real peeling/AEAD builds"),
        ("EXP-07 FX Query", 7 * 50, 45, "batched all-hit query"),
        ("EXP-08/09 E2E", 5 * 55, 360, "three OR sizes plus AND/threshold lifecycle"),
        ("EXP-10 Critical Revocation", 1595, 1200, "n=2048 endpoint and 50-repeat update loops"),
        ("EXP-11 FABEO Core", 4 * 3 * 55, exp01_seconds * .90, "fresh lifecycle objects at four core sizes"),
    ]
    total = sum(x[2] for x in estimates)
    lines = ["# Full Runtime Estimate", "",
             "Generated before Full from retained Standard medians and the frozen `full.yaml`. "
             "It is a planning estimate, not a change to repeats or workload.", "",
             "| experiment | estimated runs/invocations | estimated runtime | basis |",
             "|---|---:|---:|---|"]
    for name, runs, seconds, basis in estimates:
        lines.append(f"| {name} | {runs} | {seconds / 60:.1f} min | {basis} |")
    lines += ["", f"Total estimated wall time: **{total / 3600:.2f} hours**.", "",
              "EXP-00 and EXP-05 reuse their validated Standard mechanism results; EXP-12 remains a "
              "20-repeat Standard supplemental experiment. Storage is recomputed on Full workloads "
              "without artificial 50-fold deterministic duplication. No Full repeat was reduced."]
    (ROOT / "Perf_Exp_05_3/docs/FULL_RUNTIME_ESTIMATE.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"FULL_RUNTIME_ESTIMATE {total / 3600:.3f} hours")


if __name__ == "__main__": main()
