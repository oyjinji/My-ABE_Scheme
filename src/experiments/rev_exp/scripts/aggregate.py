#!/usr/bin/env python3
"""Aggregate one run's raw CSV and produce revocation diagnostics."""

import argparse
import math
import statistics
import sys
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from experiments.rev_exp.src.common import RESULTS_ROOT, read_csv, results_paths, summary, write_csv


SPECS = {
    "exp01": {
        "file": "exp01_revkeyupt_vs_users_raw.csv",
        "groups": ["n", "r_v", "revocation_ratio"],
        "metrics": ["kunodes_ns", "ku_crypto_ns", "total_ns", "rev_time_ms",
                    "revkeyupt_time_ms", "dual_epoch_total_ms", "cover_size",
                    "ku_g2_elements", "ku_metadata_bytes", "ku_serialized_bytes"],
    },
    "exp02": {
        "file": "exp02_revkeyupt_vs_revoked_raw.csv",
        "groups": ["n", "r_v"],
        "metrics": ["kunodes_ns", "ku_crypto_ns", "total_ns", "cover_size",
                    "ku_g2_elements", "ku_metadata_bytes", "ku_serialized_bytes"],
    },
    "exp03": {
        "file": "exp03_cover_ku_vs_revoked_raw.csv",
        "groups": ["n", "r_v"],
        "metrics": ["cover_size", "ku_g2_elements", "ku_metadata_bytes",
                    "ku_serialized_bytes"],
    },
    "exp04": {
        "file": "exp04_transform_vs_revoked_raw.csv",
        "groups": ["n", "r_v", "N", "ell", "configured_r"],
        "metrics": ["path_cover_lookup_ns", "fx_query_ns", "pairing_ns",
                    "path_cover_lookup_ms", "fx_query_ms", "pairing_ms",
                    "transform_total_ms",
                    "integrated_index_query_ns", "revocation_pairing_ns",
                    "row_pairing_ns", "transform_total_ns", "cover_size",
                    "actual_hit_rows", "actual_pairing_count", "r", "pairing_count"],
    },
    "exp05": {
        "file": "exp05_dual_vs_coupled_epoch_raw.csv",
        "groups": ["experiment_domain", "n", "r_v", "revocation_ratio", "S",
                   "ell", "policy_unique_attributes", "epoch_model"],
        "metrics": ["rev_ns", "revkeyupt_ns", "kunodes_ns", "ku_crypto_ns",
                    "bulk_privacykeyupt_ns", "policy_token_refresh_ns",
                    "fx_build_ns", "pstore_rebuild_ns", "total_epoch_update_ns",
                    "dual_epoch_total_ms",
                    "cover_size", "fx_build_attempts", "fx_resize_count"],
    },
    "exp06": {
        "file": "exp06_privacykeyupt_vs_attributes_raw.csv",
        "groups": ["S"],
        "metrics": ["privacykeyupt_ns", "token_count"],
    },
}


STRUCTURAL = {
    "cover_size", "ku_g2_elements", "ku_metadata_bytes", "ku_serialized_bytes",
    "pairing_count", "r", "actual_pairing_count", "actual_hit_rows", "token_count",
}


def aggregate_one(name, raw_dir, output_dir):
    spec = SPECS[name]
    rows = read_csv(Path(raw_dir) / spec["file"])
    output = []
    for metric in spec["metrics"]:
        buckets = defaultdict(list)
        seen_structural = set()
        for row in rows:
            group = tuple(row[key] for key in spec["groups"])
            if metric in STRUCTURAL:
                marker = group + (row.get("placement_seed", ""),)
                if marker in seen_structural:
                    continue
                seen_structural.add(marker)
            buckets[group].append(float(row[metric]))
        for group, values in buckets.items():
            result = dict(zip(spec["groups"], group))
            result.update({"experiment": name, "metric": metric})
            result.update(summary(values))
            output.append(result)
    destination = Path(output_dir) / spec["file"].replace("_raw.csv", "_aggregated.csv")
    write_csv(destination, output)
    return destination


def _rank(values):
    ordered = sorted(enumerate(values), key=lambda item: item[1])
    ranks = [0.0] * len(values)
    index = 0
    while index < len(ordered):
        end = index + 1
        while end < len(ordered) and ordered[end][1] == ordered[index][1]:
            end += 1
        average = (index + 1 + end) / 2.0
        for original, _ in ordered[index:end]:
            ranks[original] = average
        index = end
    return ranks


def _pearson(left, right):
    if len(left) < 2:
        return float("nan")
    left_mean, right_mean = statistics.mean(left), statistics.mean(right)
    numerator = sum((x - left_mean) * (y - right_mean) for x, y in zip(left, right))
    denominator = math.sqrt(
        sum((x - left_mean) ** 2 for x in left) *
        sum((y - right_mean) ** 2 for y in right)
    )
    return numerator / denominator if denominator else float("nan")


def write_revocation_diagnostics(raw_dir, output_dir):
    combined = []
    by_experiment = {}
    for experiment in ("exp01", "exp02"):
        rows = read_csv(Path(raw_dir) / SPECS[experiment]["file"])
        by_experiment[experiment] = rows
        groups = defaultdict(list)
        for row in rows:
            key = (row["n"], row["r_v"], row.get("revocation_ratio", ""))
            groups[key].append(row)
        covers = [float(row["cover_size"]) for row in rows]
        crypto_ms = [float(row["ku_crypto_ns"]) / 1e6 for row in rows]
        pearson = _pearson(covers, crypto_ms)
        spearman = _pearson(_rank(covers), _rank(crypto_ms))
        for (n, r_v, ratio), values in groups.items():
            placement_cover = {}
            for row in values:
                placement_cover.setdefault(
                    row.get("placement_seed", ""), float(row["cover_size"])
                )
            cover_values = list(placement_cover.values())
            repeated_covers = [float(row["cover_size"]) for row in values]
            kunodes = [float(row["kunodes_ns"]) / 1e6 for row in values]
            crypto = [float(row["ku_crypto_ns"]) / 1e6 for row in values]
            total = [float(row["total_ns"]) / 1e6 for row in values]
            per_node = [c / cover for c, cover in zip(crypto, repeated_covers)
                        if cover > 0]
            fractions = [c / t for c, t in zip(crypto, total) if t > 0]
            combined.append({
                "experiment": experiment, "n": n, "r_v": r_v,
                "revocation_ratio": ratio,
                "cover_size_mean": statistics.mean(cover_values),
                "cover_size_std": statistics.stdev(cover_values) if len(cover_values) > 1 else 0,
                "kunodes_ms_mean": statistics.mean(kunodes),
                "ku_crypto_ms_mean": statistics.mean(crypto),
                "revkeyupt_ms_mean": statistics.mean(total),
                "ku_crypto_ms_per_cover_node_mean":
                    statistics.mean(per_node) if per_node else float("nan"),
                "ku_crypto_fraction": statistics.mean(fractions),
                "pearson_cover_vs_ku_crypto_ms": pearson,
                "spearman_cover_vs_ku_crypto_ms": spearman,
                "n_samples": len(values),
                "placement_samples": len(cover_values),
            })
    destination = Path(output_dir) / "revocation_cost_diagnostics.csv"
    write_csv(destination, combined)
    return destination


def write_transform_diagnostics(raw_dir, output_dir):
    rows = read_csv(Path(raw_dir) / SPECS["exp04"]["file"])
    point_times = defaultdict(list)
    for row in rows:
        point_times[int(row["r_v"])].append(float(row["transform_total_ns"]) / 1e6)
    points = sorted((r_v, statistics.mean(values))
                    for r_v, values in point_times.items())
    all_times = [value for values in point_times.values() for value in values]
    overall_mean = statistics.mean(all_times)
    point_means = [value for _, value in points]
    x = [value for value, _ in points]
    x_mean, y_mean = statistics.mean(x), statistics.mean(point_means)
    denominator = sum((value - x_mean) ** 2 for value in x)
    slope = (sum((a - x_mean) * (b - y_mean) for a, b in points) / denominator
             if denominator else float("nan"))
    result = [{
        "n": rows[0]["n"], "N": rows[0]["N"], "ell": rows[0]["ell"],
        "fixed_hit_rows_r": rows[0]["configured_r"],
        "expected_pairing_count": 2 + 2 * int(rows[0]["configured_r"]),
        "transform_ms_mean": overall_mean,
        "transform_ms_cv": ((statistics.stdev(all_times) if len(all_times) > 1 else 0.0)
                            / overall_mean),
        "relative_point_mean_max_min_range":
            (max(point_means) - min(point_means)) / statistics.mean(point_means),
        "linear_slope_ms_per_revoked_user": slope,
        "min_r_v": min(x), "max_r_v": max(x), "n_samples": len(all_times),
        "interpretation": "diagnostic only; no complexity fit or outlier removal",
    }]
    destination = Path(output_dir) / "transform_stability_diagnostics.csv"
    write_csv(destination, result)
    return destination


def aggregate_all(results_dir, selected=None):
    paths = results_paths(results_dir)
    names = list(selected or SPECS)
    outputs = [aggregate_one(name, paths["raw"], paths["aggregated"])
               for name in names]
    if not selected or {"exp01", "exp02"}.issubset(set(names)):
        outputs.append(write_revocation_diagnostics(paths["raw"], paths["aggregated"]))
    if not selected or "exp04" in names:
        outputs.append(write_transform_diagnostics(paths["raw"], paths["aggregated"]))
    return outputs


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--results-dir", required=True,
                        help="run directory containing raw/ and aggregated/")
    parser.add_argument("--experiments", nargs="*", choices=sorted(SPECS))
    args = parser.parse_args(argv)
    for destination in aggregate_all(args.results_dir, args.experiments):
        print(destination)


if __name__ == "__main__":
    main()
