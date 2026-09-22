"""Shared paper figure styling and summary helpers."""

import os
from pathlib import Path

os.environ.setdefault("MPLCONFIGDIR", "/tmp/fxabe-matplotlib")

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd


STYLES = {
    "Legacy ABF": {"color": "#1f77b4", "marker": "o", "linestyle": "-"},
    "Bloom+Locator": {"color": "#ff7f0e", "marker": "P", "linestyle": "--"},
    "Cuckoo+Locator": {"color": "#d62728", "marker": "s", "linestyle": "--"},
    "Xor+Locator": {"color": "#2ca02c", "marker": "^", "linestyle": "-."},
    "FX-ABF": {"color": "#9467bd", "marker": "D", "linestyle": "-"},
}


def load_summary(run_dir, name):
    return pd.read_csv(Path(run_dir) / "summary" / (name + "_summary.csv"))


def new_figure():
    plt.rcParams.update({
        "font.size": 9, "axes.titlesize": 11, "axes.labelsize": 10,
        "legend.fontsize": 8, "figure.dpi": 120, "savefig.dpi": 300,
        "axes.grid": True, "grid.alpha": 0.25,
    })
    return plt.subplots(figsize=(6.4, 4.1), constrained_layout=True)


def plot_metric(ax, frame, x_column, filters):
    for filter_name in filters:
        data = frame[frame["filter_name"] == filter_name].sort_values(x_column)
        style = STYLES[filter_name]
        lower = data["median"] - data["ci95_low"]
        upper = data["ci95_high"] - data["median"]
        ax.errorbar(
            data[x_column], data["median"], yerr=[lower, upper],
            label=filter_name, capsize=3, linewidth=1.5, markersize=5,
            **style,
        )


def save_both(fig, run_dir, stem):
    figure_dir = Path(run_dir) / "figures"
    png = figure_dir / (stem + ".png")
    pdf = figure_dir / (stem + ".pdf")
    png.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(png, dpi=300)
    fig.savefig(pdf)
    plt.close(fig)
