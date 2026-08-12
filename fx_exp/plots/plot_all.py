"""Render every available experiment as publication-ready PNG and PDF."""

import argparse
import csv
import json
import os
import statistics
from pathlib import Path

os.environ.setdefault("MPLCONFIGDIR", "/tmp/fx_exp_matplotlib")
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


STYLES = {
    "Linear Scan": ("#7f7f7f", "o", "--"),
    "Exact Hash": ("#2ca02c", "s", "-"),
    "Bloom+Exact-PStore": ("#bcbd22", "P", "-."),
    "Attribute-BF (greedy)": ("#9467bd", "X", ":"),
    "Original-ABF": ("#d62728", "D", "-"),
    "as-ACF/Cuckoo": ("#ff7f0e", "v", "--"),
    "XOR-Retrieval": ("#17becf", "^", "-."),
    "FX-ABF": ("#1f77b4", "*", "-"),
}


def load_rows(run_dir, experiment):
    path = Path(run_dir) / "raw" / (experiment + ".jsonl")
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle
                if line.strip() and json.loads(line).get("status") == "ok"]


def aggregate(rows, x, series, metric):
    grouped = {}
    for row in rows:
        if x not in row or metric not in row:
            continue
        key = (row[x], str(row.get(series, "all")))
        grouped.setdefault(key, []).append(float(row[metric]))
    return [{x: key[0], series: key[1], metric: statistics.mean(values), "samples": len(values)}
            for key, values in sorted(grouped.items(), key=lambda item: (float(item[0][0]), item[0][1]))]


def line_plot(run_dir, filename, rows, x, series, metric, title, xlabel, ylabel):
    data = aggregate(rows, x, series, metric)
    if not data:
        return
    plot_data = Path(run_dir) / "plot_data" / (filename + ".csv")
    with plot_data.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, [x, series, metric, "samples"])
        writer.writeheader()
        writer.writerows(data)
    figure, axis = plt.subplots(figsize=(6.4, 4.2))
    labels = sorted({row[series] for row in data})
    for ordinal, label in enumerate(labels):
        selected = sorted((row for row in data if row[series] == label), key=lambda row: float(row[x]))
        color, marker, linestyle = STYLES.get(label, (
            "C{0}".format(ordinal % 10), ["o", "s", "^", "D", "v"][ordinal % 5], "-",
        ))
        axis.plot([row[x] for row in selected], [row[metric] for row in selected],
                  label=label, color=color, marker=marker, linestyle=linestyle, linewidth=1.5)
    axis.set_title(title)
    axis.set_xlabel(xlabel)
    axis.set_ylabel(ylabel)
    axis.grid(True, alpha=0.3)
    if len(labels) > 1:
        axis.legend(loc="best", fontsize=8)
    figure.tight_layout()
    for extension in ("png", "pdf"):
        figure.savefig(Path(run_dir) / "plots" / (filename + "." + extension), dpi=300)
    plt.close(figure)


def plot_run(run_dir):
    run_dir = Path(run_dir)
    (run_dir / "plots").mkdir(parents=True, exist_ok=True)
    (run_dir / "plot_data").mkdir(parents=True, exist_ok=True)
    build = load_rows(run_dir, "exp01_03_build")
    line_plot(run_dir, "exp01_first_success", build, "u", "c_fx", "first_attempt_success",
              "FX-ABF First-Attempt Build Success", "Distinct tokens (u)", "Success rate")
    line_plot(run_dir, "exp01_build_time", build, "u", "c_fx", "build_ns",
              "FX-ABF Build Time", "Distinct tokens (u)", "Time (ns)")
    line_plot(run_dir, "exp02_retries", build, "u", "c_fx", "retries",
              "FX-ABF Seed Retries", "Distinct tokens (u)", "Retries")
    line_plot(run_dir, "exp03_expansions", build, "u", "c_fx", "expansions",
              "FX-ABF Expansion Count", "Distinct tokens (u)", "Expansions")
    line_plot(run_dir, "exp03_final_load", build, "u", "c_fx", "final_m_per_u",
              "FX-ABF Final Slot Ratio", "Distinct tokens (u)", "Final m/u")

    query = load_rows(run_dir, "exp04_query")
    line_plot(run_dir, "exp04_query_latency", query, "u", "hit_ratio", "mean_query_ns",
              "FX-ABF Query Latency", "Distinct tokens (u)", "Mean latency (ns)")
    line_plot(run_dir, "exp04_aead_attempts", query, "hit_ratio", "u", "aead_attempts",
              "AEAD Attempts by Hit Ratio", "Hit ratio", "AEAD attempts")

    storage = load_rows(run_dir, "exp05_storage")
    line_plot(run_dir, "exp05_filter_bytes_per_token", storage, "u", "delta", "bytes_per_token",
              "FX-ABF Storage per Token", "Distinct tokens (u)", "Filter bytes/token")
    line_plot(run_dir, "exp05_total_index_bytes", storage, "u", "delta", "total_index_bytes",
              "Complete Index Size", "Distinct tokens (u)", "Bytes")

    pstore = load_rows(run_dir, "exp06_pstore")
    line_plot(run_dir, "exp06_pstore_size", pstore, "ell", "distribution", "pstore_bytes",
              "PStore Size by Posting Distribution", "Policy rows (ell)", "PStore bytes")
    line_plot(run_dir, "exp06_nonce_tag_share", pstore, "u", "distribution", "tag_bytes",
              "PStore Authentication Tag Cost", "Distinct tokens (u)", "Tag bytes")

    filters = load_rows(run_dir, "exp07_filter_suite")
    for metric, label, suffix in (
        ("build_ns", "Build time (ns)", "build_time"),
        ("hit_query_ns", "Mean hit latency (ns)", "hit_query"),
        ("miss_query_ns", "Mean miss latency (ns)", "miss_query"),
        ("total_index_bytes", "Index bytes", "index_size"),
        ("mixed_throughput_qps", "Queries/second", "throughput"),
    ):
        line_plot(run_dir, "exp07_" + suffix, filters, "u", "backend", metric,
                  "Filter Comparison: " + label, "Distinct tokens (u)", label)

    segments = load_rows(run_dir, "exp08_segments")
    line_plot(run_dir, "exp08_segment_build", segments, "u", "segment_length", "build_ns",
              "Segment Layout Build Time", "Distinct tokens (u)", "Build time (ns)")
    line_plot(run_dir, "exp08_segment_query", segments, "u", "segment_length", "mean_query_ns",
              "Segment Layout Query Time", "Distinct tokens (u)", "Mean query time (ns)")

    transform = load_rows(run_dir, "exp09_transform")
    for metric, ylabel, suffix in (
        ("core_transform_ns", "Core Transform time (ns)", "core"),
        ("filter_query_ns", "Filter query time (ns)", "filter"),
        ("pairing_ns", "Pairing time (ns)", "pairing_time"),
        ("pairing_count", "Pairing count", "pairing_count"),
    ):
        line_plot(run_dir, "exp09_" + suffix, transform, "ell", "backend", metric,
                  "Transform Scaling: " + ylabel, "Policy rows (ell)", ylabel)

    rejection = load_rows(run_dir, "exp10_rejection")
    line_plot(run_dir, "exp10_false_accept", rejection, "delta", "u", "empirical_false_accept_rate",
              "Empirical Nonmember False-Accept Rate", "Short-check bits (delta)", "False-accept rate")

    sensitivity = load_rows(run_dir, "exp11_sensitivity")
    for row in sensitivity:
        row["rmax_gamma"] = "R={0}, gamma={1}".format(row["r_max"], row["gamma"])
    line_plot(run_dir, "exp11_retries", sensitivity, "c_fx", "rmax_gamma", "retries",
              "Joint Parameter Sensitivity", "Load coefficient (cFX)", "Retries")


def main():
    argument_parser = argparse.ArgumentParser(description=__doc__)
    argument_parser.add_argument("--run-dir", required=True)
    args = argument_parser.parse_args()
    plot_run(Path(args.run_dir).resolve())
    print(Path(args.run_dir).resolve() / "plots")


if __name__ == "__main__":
    main()
