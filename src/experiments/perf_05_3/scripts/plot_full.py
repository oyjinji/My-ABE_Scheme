#!/usr/bin/env python3
"""Create the non-duplicative Full paper plot set with IQR uncertainty."""

import argparse
import csv
import shutil
import statistics
import sys
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "src"))
from experiments.perf_05_3.scripts.common import read_csv  # noqa: E402
from experiments.perf_05_3.scripts.standard_final_audit import (bootstrap_median_ci, cleanup_plots,
                                                        percentile, storage_audit, write_rows)  # noqa: E402

COLORS = {"FXABE-05.3 Core": "#1b9e77", "FXABE-NoOccurrence Core": "#d95f02", "FABEO": "#7570b3"}


def samples(rows, x, series, phase, value="time_ns", predicate=lambda r: True):
    out = defaultdict(list)
    for r in rows:
        if r["phase"] == phase and predicate(r) and r.get(x) and r.get(value):
            out[(r[series], int(float(r[x])))].append(float(r[value]))
    return out


def error_lines(ax, grouped, scale=1e-6):
    for name in sorted({k[0] for k in grouped}):
        xs = sorted(k[1] for k in grouped if k[0] == name)
        vals = [grouped[(name, x)] for x in xs]
        med = [statistics.median(v) * scale for v in vals]
        p25 = [percentile(v, .25) * scale for v in vals]
        p75 = [percentile(v, .75) * scale for v in vals]
        ax.plot(xs, med, marker="o", label=name, color=COLORS.get(name))
        ax.fill_between(xs, p25, p75, alpha=.18, color=COLORS.get(name))
    ax.grid(alpha=.25); ax.legend(fontsize=8)


def full_statistics(run, rows):
    output = []
    for ell in (40, 80, 160, 320, 640, 1280):
        data = {}
        for scheme in ("FXABE-05.3 Core", "FABEO"):
            vals = [float(r["time_ns"]) / 1e6 for r in rows if r["scheme"] == scheme and
                    r["phase"] == "Encrypt Core" and int(r["ell"]) == ell]
            lo, hi = bootstrap_median_ci(vals, 54000 + ell + len(scheme))
            data[scheme] = (vals, lo, hi)
        fv, flo, fhi = data["FXABE-05.3 Core"]; bv, blo, bhi = data["FABEO"]
        output.append({"ell": ell, "n_per_scheme": len(fv), "fxabe_median_ms": statistics.median(fv),
                       "fxabe_p25_ms": percentile(fv, .25), "fxabe_p75_ms": percentile(fv, .75),
                       "fxabe_median_ci_low_ms": flo, "fxabe_median_ci_high_ms": fhi,
                       "fabeo_median_ms": statistics.median(bv), "fabeo_p25_ms": percentile(bv, .25),
                       "fabeo_p75_ms": percentile(bv, .75), "fabeo_median_ci_low_ms": blo,
                       "fabeo_median_ci_high_ms": bhi,
                       "fxabe_over_fabeo": statistics.median(fv) / statistics.median(bv),
                       "median_ci_overlap": max(flo, blo) <= min(fhi, bhi)})
    write_rows(run / "fabeo_core_statistics.csv", output)


def main():
    parser = argparse.ArgumentParser(); parser.add_argument("run_dir"); parser.add_argument("--standard-run", required=True); parser.add_argument("--exp12-run", required=True)
    args = parser.parse_args(); run = Path(args.run_dir).resolve(); standard = Path(args.standard_run).resolve(); exp12 = Path(args.exp12_run).resolve()
    plots = run / "plots"; plots.mkdir(exist_ok=True)
    exp01 = read_csv(run / "raw/exp01_encrypt.csv")
    fig, ax = plt.subplots(figsize=(7.5, 4.7)); error_lines(ax, samples(exp01, "ell", "scheme", "Encrypt Core"))
    ax.set(xlabel="Policy rows ell", ylabel="Time (ms), median and IQR", title="Encrypt Core vs ell")
    fig.tight_layout(); fig.savefig(plots / "01_encrypt_core.png", dpi=190); plt.close(fig)
    cleanup_plots(run)
    storage_audit(run)
    exp03 = read_csv(run / "raw/exp03_transform_vs_J.csv")
    fig, ax = plt.subplots(figsize=(7.5, 4.7)); error_lines(ax, samples(exp03, "J", "phase", "Transform Total"))
    # Add separately named components (the helper's phase filter is exact).
    for phase in ("FX Query", "AuthorizedSubset", "Transform Attribute", "Transform Revocation"):
        grouped = defaultdict(list)
        for r in exp03:
            if r["phase"] == phase: grouped[(phase, int(r["J"]))].append(float(r["time_ns"]))
        error_lines(ax, grouped)
    ax.set(xlabel="|J|", ylabel="Time (ms), median and IQR", title="Transform Decomposition vs |J|")
    fig.tight_layout(); fig.savefig(plots / "05_transform_decomposition_vs_J.png", dpi=190); plt.close(fig)
    exp04 = read_csv(run / "raw/exp04_transform_vs_tI.csv")
    grouped = samples(exp04, "t_I", "scheme", "Transform Total")
    fig, ax = plt.subplots(figsize=(7.2, 4.5)); error_lines(ax, grouped)
    ax.set(xlabel="t_I", ylabel="Transform time (ms)", title="Transform vs t_I")
    ax2 = ax.twinx(); pair = sorted({(int(r["t_I"]), int(r["pair_count"])) for r in exp04})
    ax2.plot([x for x, _ in pair], [y for _, y in pair], "k--s", label="pair count"); ax2.set_ylabel("Pairings")
    fig.tight_layout(); fig.savefig(plots / "06_transform_vs_tI.png", dpi=190); plt.close(fig)
    exp06 = read_csv(run / "raw/exp06_fx_build.csv")
    fig, ax = plt.subplots(figsize=(7.2, 4.5)); error_lines(ax, samples(exp06, "u", "phase", "FX+PStore Build"))
    ax.set(xlabel="Distinct tokens u", ylabel="Time (ms)", title="Real FX/PStore Build")
    fig.tight_layout(); fig.savefig(plots / "07_real_fx_build.png", dpi=190); plt.close(fig)
    exp07 = read_csv(run / "raw/exp07_fx_query.csv")
    fig, ax = plt.subplots(figsize=(7.2, 4.5)); error_lines(ax, samples(exp07, "N", "phase", "Query Total"))
    ax.set(xlabel="Query tokens N", ylabel="Time (ms)", title="Real FX Query")
    fig.tight_layout(); fig.savefig(plots / "08_real_fx_query.png", dpi=190); plt.close(fig)
    shutil.copy2(exp12 / "plots/12a_policy_oprf_vs_u.png", plots / "09_policy_oprf_vs_u.png")
    exp10 = read_csv(run / "raw/exp10_revocation.csv")
    dual = []
    for phase in ("Dual-Epoch", "Coupled-Epoch"):
        vals = [float(r["time_ns"]) / 1e6 for r in exp10 if r["phase"] == phase]
        dual.append({"model": phase, "n": len(vals), "median_ms": statistics.median(vals),
                     "p25_ms": percentile(vals, .25), "p75_ms": percentile(vals, .75)})
    ratio = dual[1]["median_ms"] / dual[0]["median_ms"]
    for row in dual: row["coupled_over_dual_median_ratio"] = ratio
    write_rows(run / "dual_epoch_ablation.csv", dual)
    fig, ax = plt.subplots(figsize=(5.5, 4.2)); ax.bar([r["model"] for r in dual], [r["median_ms"] for r in dual], color=["#1b9e77", "#d95f02"])
    ax.set(ylabel="Median update lifecycle time (ms)", title=f"Dual vs Coupled Epoch ({ratio:.2f}x)")
    fig.tight_layout(); fig.savefig(plots / "10_dual_vs_coupled.png", dpi=190); plt.close(fig)
    grouped = samples(exp10, "n_users", "phase", "RevKeyUpt vs n")
    fig, ax = plt.subplots(figsize=(7.2, 4.5)); error_lines(ax, grouped)
    ax.set(xlabel="Registered users n", ylabel="Time (ms)", title="RevKeyUpt Scaling")
    fig.tight_layout(); fig.savefig(plots / "S1_revkeyupt_scaling.png", dpi=190); plt.close(fig)
    shutil.copy2(standard / "plots/06_cmax_ablation.png", plots / "S2_cmax_standard_ablation.png")
    full_statistics(run, exp01)
    print("FULL_PLOTS_PASS")


if __name__ == "__main__": main()
