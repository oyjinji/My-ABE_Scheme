#!/usr/bin/env python3
"""Render the six paper-style figures exclusively from aggregated CSV."""

import argparse
import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))
os.environ.setdefault("MPLCONFIGDIR", str(ROOT / "src/experiments/rev_exp" / ".mplconfig"))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from experiments.rev_exp.src.common import read_csv, results_paths


FILES = {
    "exp01": "exp01_revkeyupt_vs_users_aggregated.csv",
    "exp02": "exp02_revkeyupt_vs_revoked_aggregated.csv",
    "exp03": "exp03_cover_ku_vs_revoked_aggregated.csv",
    "exp04": "exp04_transform_vs_revoked_aggregated.csv",
    "exp05": "exp05_dual_vs_coupled_epoch_aggregated.csv",
    "exp06": "exp06_privacykeyupt_vs_attributes_aggregated.csv",
}

# Kept explicit and tested: analytical views must not silently change metrics.
FIGURE_METRICS = {
    "exp01": "revkeyupt_time_ms",
    "exp05_direct": "total_epoch_update_ns",
    "exp05_scalability": "dual_epoch_total_ms",
}


def _style():
    plt.rcParams.update({
        "figure.facecolor": "white", "axes.facecolor": "white",
        "font.size": 9, "axes.labelsize": 10, "legend.fontsize": 9,
        "lines.linewidth": 1.5, "lines.markersize": 4,
        "pdf.fonttype": 42, "ps.fonttype": 42,
    })


def _metric(rows, name):
    return [row for row in rows if row["metric"] == name]


def _series(rows, xkey, scale=1.0):
    rows = sorted(rows, key=lambda row: float(row[xkey]))
    x = [float(row[xkey]) for row in rows]
    y = [float(row["mean"]) / scale for row in rows]
    lo = [float(row["ci95_low"]) / scale for row in rows]
    hi = [float(row["ci95_high"]) / scale for row in rows]
    return x, y, lo, hi


def _line(ax, rows, xkey, label=None, scale=1.0, marker="o"):
    x, y, lo, hi = _series(rows, xkey, scale)
    line = ax.plot(x, y, marker=marker, label=label)[0]
    ax.fill_between(x, lo, hi, color=line.get_color(), alpha=0.16, linewidth=0)


def _finish(fig, stem, output_dir):
    fig.tight_layout()
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_dir / (stem + ".png"), dpi=300, bbox_inches="tight")
    fig.savefig(output_dir / (stem + ".pdf"), bbox_inches="tight")
    plt.close(fig)


def plot_exp01(rows, out):
    fig, ax = plt.subplots(figsize=(5.2, 3.3))
    timing = _metric(rows, FIGURE_METRICS["exp01"])
    for ratio in sorted({float(row["revocation_ratio"]) for row in timing}):
        subset = [row for row in timing if float(row["revocation_ratio"]) == ratio]
        _line(ax, subset, "n", "%g%%" % (ratio * 100))
    ax.set_xscale("log", base=2)
    ax.set_xlabel("Number of Users n")
    ax.set_ylabel("RevKeyUpt Time (ms)")
    ax.grid(True, alpha=.22)
    ax.legend(title="Revoked")
    _finish(fig, "exp01_revkeyupt_vs_users", out)


def plot_exp02(rows, out):
    fig, ax = plt.subplots(figsize=(5.2, 3.3))
    _line(ax, _metric(rows, "total_ns"), "r_v", scale=1e6)
    ax.set_xscale("log", base=2)
    ax.set_xlabel("Number of Revoked Users r_v")
    ax.set_ylabel("RevKeyUpt Time (ms)")
    ax.grid(True, alpha=.22)
    _finish(fig, "exp02_revkeyupt_vs_revoked", out)


def plot_exp03(rows, out):
    fig, axes = plt.subplots(2, 1, figsize=(5.2, 5.4), sharex=True)
    _line(axes[0], _metric(rows, "cover_size"), "r_v")
    _line(axes[1], _metric(rows, "ku_serialized_bytes"), "r_v", scale=1024.0)
    axes[0].set_ylabel("Cover Size (nodes)")
    axes[1].set_ylabel("KU Size (KiB)")
    axes[1].set_xlabel("Number of Revoked Users r_v")
    axes[1].set_xscale("log", base=2)
    for ax in axes:
        ax.grid(True, alpha=.22)
    _finish(fig, "exp03_cover_ku_vs_revoked", out)


def plot_exp04(rows, out):
    fig, ax = plt.subplots(figsize=(5.2, 4.8))
    _line(ax, _metric(rows, "transform_total_ns"), "r_v", scale=1e6)
    ax.set_xscale("log", base=2)
    ax.set_ylim(63, 85)
    ax.set_xlabel("Number of Revoked Users r_v")
    ax.set_ylabel("Transform Time (ms)")
    ax.grid(True, alpha=.22)
    _finish(fig, "exp04_transform_vs_revoked", out)


def plot_exp05(rows, out):
    fig, axes = plt.subplots(1, 2, figsize=(9.2, 3.5))
    direct_timing = _metric(rows, FIGURE_METRICS["exp05_direct"])
    direct = [row for row in direct_timing
              if row["experiment_domain"] == "direct_comparison"]
    for mode, marker in (("Dual-Epoch", "o"), ("Coupled-Epoch Ablation", "s")):
        _line(axes[0], [row for row in direct if row["epoch_model"] == mode],
              "n", mode, 1e6, marker)
    scalability_timing = _metric(rows, FIGURE_METRICS["exp05_scalability"])
    scalability = [row for row in scalability_timing
                   if row["experiment_domain"] == "dual_scalability" and
                   row["epoch_model"] == "Dual-Epoch"]
    _line(axes[1], scalability, "n", "Dual-Epoch", 1.0, "o")
    for ax in axes:
        ax.set_xscale("log", base=2)
        ax.set_yscale("log")
        ax.set_xlabel("Number of Users n")
        ax.grid(True, which="both", alpha=.22)
        ax.legend()
    axes[0].set_ylabel("Epoch Update Time (ms)")
    axes[0].set_title("(a) Direct real-operation comparison")
    axes[1].set_title("(b) Dual-Epoch scalability")
    _finish(fig, "exp05_dual_vs_coupled_epoch", out)


def plot_exp06(rows, out):
    fig, ax = plt.subplots(figsize=(5.2, 3.3))
    _line(ax, _metric(rows, "privacykeyupt_ns"), "S", scale=1e6)
    ax.set_xscale("log", base=2)
    ax.set_xlabel("Number of User Attributes S")
    ax.set_ylabel("PrivacyKeyUpt Time (ms)")
    ax.grid(True, alpha=.22)
    _finish(fig, "exp06_privacykeyupt_vs_attributes", out)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--results-dir", required=True,
                        help="run directory containing aggregated/ and figures/")
    args = parser.parse_args(argv)
    paths = results_paths(args.results_dir)
    _style()
    readers = {name: read_csv(paths["aggregated"] / filename)
               for name, filename in FILES.items()}
    plot_exp01(readers["exp01"], paths["figures"])
    plot_exp02(readers["exp02"], paths["figures"])
    plot_exp03(readers["exp03"], paths["figures"])
    plot_exp04(readers["exp04"], paths["figures"])
    plot_exp05(readers["exp05"], paths["figures"])
    plot_exp06(readers["exp06"], paths["figures"])


if __name__ == "__main__":
    main()
