#!/usr/bin/env python3
"""Produce all Global ABE experiment figures from the aggregated summaries.

Median is the point estimator; the p25-p75 IQR is the error band (requirement
18).  Outliers are never removed; p95 is reported in the summary CSVs and in
the figure captions.  FABEO22 has no outsourced Transform, so exp04 shows
Base/Full only.  Exp05 compares FABEO's full Decrypt against Base/Full
FinalDec -- the figures carry an explicit phase-difference caveat.
"""

import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from Global_Exp.src.common import results_paths  # noqa: E402

SCHEME_COLORS = {
    "FABEO22": "#1f77b4",
    "FXABE-Base": "#ff7f0e",
    "FXABE-Full": "#2ca02c",
}
SCHEME_MARKERS = {
    "FABEO22": "o",
    "FXABE-Base": "s",
    "FXABE-Full": "^",
}


def _load_summary(run_dir, experiment):
    path = Path(run_dir) / "summary" / ("%s_summary.csv" % experiment)
    if not path.exists():
        return []
    import csv
    with open(path, newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _series(rows, metric, scheme):
    points = {}
    for row in rows:
        if row["scheme"] != scheme or row["metric"] != metric:
            continue
        key = int(row["policy_rows"]) if row["policy_rows"] else int(row.get(
            "user_attrs", 0))
        points[key] = row
    return {k: points[k] for k in sorted(points)}


def _plot_line(ax, series, color, marker, label, y_unit):
    xs = list(series)
    medians = [float(series[x]["median"]) for x in xs]
    lows = [float(series[x]["p25"]) for x in xs]
    highs = [float(series[x]["p75"]) for x in xs]
    ax.plot(xs, medians, color=color, marker=marker, label=label,
            linewidth=1.6, markersize=5)
    ax.fill_between(xs, lows, highs, color=color, alpha=0.15)
    ax.set_xscale("log", base=2)
    ax.set_yscale("log", base=10)
    ax.grid(True, which="both", alpha=0.25)
    ax.set_xlabel("policy rows (l)")
    ax.set_ylabel(y_unit)


def _save(fig, path, caption):
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print("  wrote %s" % path, flush=True)


def plot_exp01(run_dir):
    rows = _load_summary(run_dir, "exp01")
    if not rows:
        return
    schemes = [r["scheme"] for r in rows if r["metric"] == "setup_ms"]
    schemes = list(dict.fromkeys(schemes))
    medians = []
    lows = []
    highs = []
    for scheme in schemes:
        row = next(r for r in rows
                   if r["scheme"] == scheme and r["metric"] == "setup_ms")
        medians.append(float(row["median"]))
        lows.append(float(row["p25"]))
        highs.append(float(row["p75"]))
    fig, ax = plt.subplots(figsize=(7, 4.6))
    positions = np.arange(len(schemes))
    bars = ax.bar(positions, medians, width=0.55, alpha=0.85,
                  color=[SCHEME_COLORS[s] for s in schemes])
    ax.errorbar(positions, medians,
                yerr=[[m - lo for m, lo in zip(medians, lows)],
                      [hi - m for m, hi in zip(medians, highs)]],
                fmt="none", ecolor="black", capsize=3)
    for bar, value in zip(bars, medians):
        ax.text(bar.get_x() + bar.get_width() / 2, value * 1.03,
                "%.0f ms" % value, ha="center", va="bottom", fontsize=9)
    ax.set_xticks(positions)
    ax.set_xticklabels(schemes)
    ax.set_ylabel("Setup time (ms)")
    ax.set_title("System Setup Cost by Scheme (universe-independent)")
    ax.grid(True, axis="y", alpha=0.25)
    ax.set_ylim(0, max(medians) * 1.18)
    _save(fig, Path(run_dir) / "plots" / "exp01_setup.png",
          "Setup time by scheme; Setup is universe-independent.")


def _plot_scaling(run_dir, experiment, filename, metric, ylabel, title,
                  schemes=None, x_field="policy_rows"):
    rows = _load_summary(run_dir, experiment)
    if not rows:
        return
    schemes = schemes or [s for s in SCHEME_COLORS if
                          _series(rows, metric, s)]
    fig, ax = plt.subplots(figsize=(7, 4.8))
    for scheme in schemes:
        series = _series(rows, metric, scheme)
        if not series:
            continue
        _plot_line(ax, series, SCHEME_COLORS[scheme], SCHEME_MARKERS[scheme],
                   scheme, ylabel)
    ax.legend(frameon=False, fontsize=9)
    ax.set_title(title)
    _save(fig, Path(run_dir) / "plots" / filename, title)


def plot_exp02(run_dir):
    """User provisioning vs |S| (fixed small policy)."""
    rows = _load_summary(run_dir, "exp02")
    if not rows:
        return
    fig, ax = plt.subplots(figsize=(7, 4.8))
    for scheme in SCHEME_COLORS:
        points = {}
        for row in rows:
            if row["scheme"] != scheme or row["metric"] != "provisioning_total_ms":
                continue
            points[int(row["user_attrs"])] = row
        if not points:
            continue
        xs = sorted(points)
        ax.plot(xs, [float(points[x]["median"]) for x in xs],
                color=SCHEME_COLORS[scheme], marker=SCHEME_MARKERS[scheme],
                label=scheme, linewidth=1.6, markersize=5)
        ax.fill_between(xs, [float(points[x]["p25"]) for x in xs],
                        [float(points[x]["p75"]) for x in xs],
                        color=SCHEME_COLORS[scheme], alpha=0.15)
    ax.set_xscale("log", base=2)
    ax.set_yscale("log", base=10)
    ax.grid(True, which="both", alpha=0.25)
    ax.set_xlabel("user attributes (|S|)")
    ax.set_ylabel("Provisioning time (ms)")
    ax.set_title("User Provisioning Cost vs |S| (fixed policy l=4)")
    ax.legend(frameon=False, fontsize=9)
    _save(fig, Path(run_dir) / "plots" / "exp02_user_provisioning.png",
          "KeyGen cost vs |S|.")


def plot_exp08(run_dir):
    rows = _load_summary(run_dir, "exp08")
    if not rows:
        return
    schemes = list(dict.fromkeys(r["scheme"] for r in rows))
    # --- encryption breakdown ---
    fig, ax = plt.subplots(figsize=(8, 4.8))
    segments_enc = [("oprf_ms", "OPRF"), ("filter_build_ms", "FX-ABF"),
                    ("pstore_build_ms", "PStore"), ("abe_crypto_ms", "ABE rows"),
                    ("breakdown_other_ms", "other")]
    _stacked_bar(ax, rows, schemes, segments_enc, "median",
                 "End-to-End Encryption Breakdown (median ms)")
    ax.set_ylabel("ms")
    _save(fig, Path(run_dir) / "plots" / "exp08_encrypt_breakdown.png",
          "Encryption cost stacked by phase.")
    # --- decryption breakdown ---
    fig, ax = plt.subplots(figsize=(8, 4.8))
    segments_dec = [("user_oprf_ms", "user OPRF"),
                    ("direct_lookup_ms", "direct lookup"),
                    ("index_query_ms", "index query"),
                    ("transform_ms", "Transform"), ("finaldec_ms", "FinalDec")]
    _stacked_bar(ax, rows, schemes, segments_dec, "median",
                 "Decryption Cost Breakdown (median ms)")
    ax.set_ylabel("ms")
    _save(fig, Path(run_dir) / "plots" / "exp08_decrypt_breakdown.png",
          "Decryption cost stacked by phase; FABEO22 is the full Decrypt.")


def _stacked_bar(ax, rows, schemes, segments, stat, title):
    values = []
    for scheme in schemes:
        scheme_values = []
        for metric, _ in segments:
            row = next((r for r in rows
                        if r["scheme"] == scheme and r["metric"] == metric),
                       None)
            if row is None or not row.get(stat):
                scheme_values.append(0.0)
            else:
                scheme_values.append(float(row[stat]))
        values.append(scheme_values)
    bottom = np.zeros(len(schemes))
    positions = np.arange(len(schemes))
    for index, (_, label) in enumerate(segments):
        segment = np.array([v[index] for v in values])
        ax.bar(positions, segment, bottom=bottom, width=0.55, alpha=0.9,
               label=label)
        bottom += segment
    for position, scheme_values in zip(positions, values):
        ax.text(position, sum(scheme_values) * 1.02,
                "%.1f" % sum(scheme_values), ha="center", va="bottom",
                fontsize=9)
    ax.set_xticks(positions)
    ax.set_xticklabels(schemes)
    ax.legend(frameon=False, fontsize=8, ncol=3, loc="upper left")
    ax.grid(True, axis="y", alpha=0.25)
    ax.set_title(title)


def plot_all(run_dir):
    run_dir = Path(run_dir)
    print("plotting exp01..exp08", flush=True)
    plot_exp01(run_dir)
    plot_exp02(run_dir)
    _plot_scaling(run_dir, "exp03", "exp03_encrypt.png",
                  "encrypt_total_ms", "Encryption time (ms)",
                  "End-to-End Encryption vs Policy Rows (median, IQR band)")
    _plot_scaling(run_dir, "exp04", "exp04_transform.png",
                  "transform_ms", "Transform time (ms)",
                  "CSP Transform vs Policy Rows (median, IQR band)",
                  schemes=["FXABE-Base", "FXABE-Full"])
    _plot_scaling(run_dir, "exp05", "exp05_client_decrypt.png",
                  "finaldec_ms", "Client decryption time (ms)",
                  "Client-Side Decryption vs Policy Rows (FABEO full Decrypt;\n"
                  "FXABE FinalDec after outsourced Transform)")
    _plot_scaling(run_dir, "exp06", "exp06_e2e_decrypt.png",
                  "end_to_end_decrypt_ms", "End-to-end decrypt time (ms)",
                  "End-to-End Decryption Latency vs Policy Rows\n"
                  "(tokenize + Transform + FinalDec for FXABE)")
    _plot_scaling(run_dir, "exp07", "exp07_storage.png",
                  "total_bytes", "Ciphertext-side bytes",
                  "Ciphertext-Side Storage vs Policy Rows (serialized bytes)")
    plot_exp08(run_dir)
    plot_exp09(run_dir)


def plot_exp09(run_dir):
    """Supplementary: normalized end-to-end decryption overhead vs FABEO22."""
    rows = _load_summary(run_dir, "exp06")
    if not rows:
        return
    base = _series(rows, "end_to_end_decrypt_ms", "FABEO22")
    if not base:
        return
    fig, ax = plt.subplots(figsize=(7, 4.6))
    for scheme in ("FXABE-Base", "FXABE-Full"):
        series = _series(rows, "end_to_end_decrypt_ms", scheme)
        if not series:
            continue
        xs = sorted(x for x in series if x in base)
        ratios = [float(series[x]["median"]) / max(float(base[x]["median"]),
                                                   1e-9) for x in xs]
        ax.plot(xs, ratios, color=SCHEME_COLORS[scheme],
                marker=SCHEME_MARKERS[scheme], label=scheme, linewidth=1.6,
                markersize=5)
    ax.axhline(1.0, color="grey", linestyle="--", linewidth=1)
    ax.set_xscale("log", base=2)
    ax.grid(True, which="both", alpha=0.25)
    ax.set_xlabel("policy rows (l)")
    ax.set_ylabel("ratio vs FABEO22")
    ax.set_title("End-to-End Decryption Overhead vs FABEO22 (median ratio)\n"
                 "(supplementary; includes per-query user OPRF)")
    ax.legend(frameon=False, fontsize=9)
    _save(fig, Path(run_dir) / "plots" / "exp09_normalized_overhead.png",
          "Normalized overhead, supplementary.")


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    args = parser.parse_args()
    plot_all(args.run_dir)


if __name__ == "__main__":
    main()
