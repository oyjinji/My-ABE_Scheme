#!/usr/bin/env python3
"""Aggregate raw per-repetition CSVs into median/IQR summaries (long form).

Output: for every experiment, ``summary/<experiment>_summary.csv`` with one row
per (scheme, policy_rows, user_attrs, metric).  Median is the point estimator;
p25/p75 is the error band; p95 captures the tail (outliers are never removed).
Blank / N/A metrics (e.g. FABEO22 transform) are skipped.
"""

import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from experiments.global_exp.src.common import results_paths  # noqa: E402
from experiments.global_exp.src.experiments import RAW_FILENAMES  # noqa: E402
from experiments.global_exp.src.statistics import summary  # noqa: E402

EXPERIMENT_METRICS = {
    "exp01": ["setup_ms", "crypto_setup_ms", "aux_setup_ms"],
    "exp02": ["keygen_ms", "provisioning_total_ms", "oprf_ms"],
    "exp03": ["oprf_ms", "filter_build_ms", "pstore_build_ms",
              "abe_encrypt_ms", "abe_crypto_ms", "encrypt_total_ms",
              "ct_bytes", "filter_bytes", "pstore_bytes", "metadata_bytes",
              "total_bytes"],
    "exp04": ["transform_ms", "index_query_ms", "filter_lookup_ms",
              "pstore_lookup_ms", "pair_count"],
    "exp05": ["finaldec_ms", "decrypt_total_ms"],
    "exp06": ["user_oprf_ms", "direct_lookup_ms", "index_query_ms",
              "transform_ms", "finaldec_ms", "end_to_end_decrypt_ms",
              "pair_count"],
    "exp07": ["ct_bytes", "filter_bytes", "pstore_bytes", "metadata_bytes",
              "total_bytes"],
    "exp08": ["oprf_ms", "filter_build_ms", "pstore_build_ms",
              "abe_crypto_ms", "encrypt_total_ms", "user_oprf_ms",
              "direct_lookup_ms", "index_query_ms", "transform_ms",
              "finaldec_ms", "end_to_end_decrypt_ms", "pair_count",
              "breakdown_other_ms", "total_bytes"],
}

SUMMARY_FIELDS = [
    "experiment", "scheme", "policy_rows", "policy_cols", "user_attrs",
    "satisfied_rows", "universe_size", "metric",
    "median", "p25", "p75", "p95", "mean", "iqr",
    "median_ci_low", "median_ci_high", "count",
]


def _numeric_groups(rows, metrics):
    groups = {}
    for row in rows:
        if row.get("status") not in (None, "", "ok"):
            continue
        key = (row.get("scheme"), row.get("policy_rows"), row.get("user_attrs"))
        for metric in metrics:
            raw = row.get(metric)
            if raw in (None, ""):
                continue
            try:
                value = float(raw)
            except (TypeError, ValueError):
                continue
            if value != value:  # NaN
                continue
            groups.setdefault((metric,) + key, []).append(value)
    return groups


def aggregate_run(run_dir):
    paths = results_paths(run_dir)
    results = {}
    for experiment, metrics in EXPERIMENT_METRICS.items():
        raw_path = paths["raw"] / RAW_FILENAMES[experiment]
        if not raw_path.exists():
            continue
        with open(raw_path, newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        groups = _numeric_groups(rows, metrics)
        output = []
        for (metric, scheme, l, S), values in sorted(groups.items()):
            stats = summary(values)
            output.append({
                "experiment": experiment,
                "scheme": scheme,
                "policy_rows": l, "user_attrs": S,
                "metric": metric,
                **stats,
            })
        summary_path = paths["summary"] / ("%s_summary.csv" % experiment)
        _write(summary_path, output)
        results[experiment] = len(output)
    return results


def _write(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=SUMMARY_FIELDS,
                                extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    args = parser.parse_args()
    results = aggregate_run(args.run_dir)
    paths = results_paths(args.run_dir)
    with open(paths["logs"] / "aggregation.json", "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2, sort_keys=True)
    print(json.dumps(results, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
