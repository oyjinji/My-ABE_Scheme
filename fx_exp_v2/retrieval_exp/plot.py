"""Four paper-style plots for the retrieval-only experiment."""

from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


STYLES = {
    "Legacy ABF retrieval": ("#7f7f7f", "D", "--"),
    "Bloomier retrieval": ("#9467bd", "s", "-"),
    "Cuckoo payload table": ("#2ca02c", "v", "-."),
    "Plain XOR retrieval": ("#1f77b4", "^", "-"),
    "FX-ABF retrieval": ("#d62728", "o", "-"),
}


def _metric(data, metric):
    return data[data["metric"] == metric].copy()


def _line(ax, group, label):
    color, marker, style = STYLES[label]
    group = group.sort_values("u")
    yerr = [
        group["median"] - group["ci95_low"],
        group["ci95_high"] - group["median"],
    ]
    ax.errorbar(
        group["u"], group["median"], yerr=yerr, label=label,
        color=color, marker=marker, linestyle=style, capsize=3,
    )


def _finish(fig, axes, path):
    for ax in axes:
        ax.grid(True, alpha=0.25)
        ax.set_xscale("log", base=2)
    fig.tight_layout()
    fig.savefig(str(path) + ".png", dpi=300, bbox_inches="tight")
    fig.savefig(str(path) + ".pdf", bbox_inches="tight")
    plt.close(fig)


def plot_all(run_dir):
    run_dir = Path(run_dir)
    figures = run_dir / "figures"
    data = pd.read_csv(run_dir / "summary" / "retrieval_summary.csv")

    build = _metric(data, "build_total_ms")
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.2))
    for name, group in build.groupby("retrieval_name"):
        _line(axes[0], group, name)
        if name != "Legacy ABF retrieval":
            _line(axes[1], group, name)
    axes[0].set_yscale("log")
    axes[0].set_title("All Structures (log-y)")
    axes[1].set_title("Modern Structures (linear-y)")
    for ax in axes:
        ax.set_xlabel("Number of Keys")
        ax.set_ylabel("Median Build Time (ms)")
    axes[0].legend(fontsize=8)
    fig.suptitle("Retrieval Structure Build Time vs Keys")
    _finish(fig, axes, figures / "r1_retrieval_build_time")

    query = _metric(data, "mixed_query_ns")
    fig, ax = plt.subplots(figsize=(6.8, 4.5))
    for name, group in query.groupby("retrieval_name"):
        _line(ax, group, name)
    ax.set_xlabel("Number of Keys")
    ax.set_ylabel("Median Query Time (ns/query)")
    ax.set_title("Retrieval Query Time vs Keys (50% Members)")
    ax.legend(fontsize=8)
    _finish(fig, [ax], figures / "r2_retrieval_query_time")

    space = _metric(data, "bytes_per_key")
    fig, ax = plt.subplots(figsize=(6.8, 4.5))
    for name, group in space.groupby("retrieval_name"):
        _line(ax, group, name)
    ax.set_xlabel("Number of Keys")
    ax.set_ylabel("Serialized Bytes per Key")
    ax.set_title("Serialized Bytes per Key")
    ax.legend(fontsize=8)
    _finish(fig, [ax], figures / "r3_retrieval_space")

    success = _metric(data, "success_rate")
    attempts = _metric(data, "attempt_count")
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.2))
    for name, group in success.groupby("retrieval_name"):
        _line(axes[0], group, name)
    for name, group in attempts.groupby("retrieval_name"):
        _line(axes[1], group, name)
    axes[0].set_xlabel("Number of Keys")
    axes[0].set_ylabel("Build Success Rate")
    axes[0].set_ylim(-0.02, 1.05)
    axes[1].set_xlabel("Number of Keys")
    axes[1].set_ylabel("Median Attempt Count")
    axes[1].set_yscale("log")
    axes[0].set_title("Success Rate")
    axes[1].set_title("Retry / Attempt Count (log-y)")
    axes[0].legend(fontsize=8)
    fig.suptitle("Build Success Rate / Retry Count vs Keys")
    _finish(fig, axes, figures / "r4_retrieval_build_stability")
