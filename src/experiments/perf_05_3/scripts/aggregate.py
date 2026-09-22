#!/usr/bin/env python3
"""Aggregate every raw CSV without discarding failures or outliers."""

import argparse
import math
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "src"))

from experiments.perf_05_3.scripts.common import read_csv, write_csv  # noqa: E402


def _number(value):
    try:
        return float(value) if value != "" else None
    except (TypeError, ValueError):
        return None


def summarize(values):
    values = sorted(values)
    if not values:
        return {key: "" for key in ("median", "mean", "std", "p25", "p75", "min", "max")}
    def percentile(q):
        pos = (len(values) - 1) * q
        lo, hi = int(math.floor(pos)), int(math.ceil(pos))
        return values[lo] if lo == hi else values[lo] + (values[hi] - values[lo]) * (pos - lo)
    return {
        "median": statistics.median(values), "mean": statistics.mean(values),
        "std": statistics.stdev(values) if len(values) > 1 else 0.0,
        "p25": percentile(0.25), "p75": percentile(0.75),
        "min": min(values), "max": max(values),
    }


def aggregate_file(source, target):
    rows = read_csv(source)
    excluded = {"run_id", "seed", "replicate", "time_ns", "serialized_bytes", "success", "notes"}
    keys = [key for key in rows[0] if key not in excluded]
    groups = {}
    for row in rows:
        key = tuple(row.get(field, "") for field in keys)
        groups.setdefault(key, []).append(row)
    output = []
    for key, members in groups.items():
        base = dict(zip(keys, key))
        times = [_number(x.get("time_ns")) for x in members]
        sizes = [_number(x.get("serialized_bytes")) for x in members]
        times = [x for x in times if x is not None]
        sizes = [x for x in sizes if x is not None]
        time_stats, size_stats = summarize(times), summarize(sizes)
        base.update({"sample_count": len(members), "success_count": sum(x.get("success") == "True" for x in members)})
        base.update({"time_ns_" + name: value for name, value in time_stats.items()})
        base.update({"serialized_bytes_" + name: value for name, value in size_stats.items()})
        output.append(base)
    write_csv(target, output)


def main():
    parser = argparse.ArgumentParser(); parser.add_argument("run_dir")
    args = parser.parse_args(); run = Path(args.run_dir)
    for source in sorted((run / "raw").glob("*.csv")):
        aggregate_file(source, run / "aggregated" / source.name.replace(".csv", "_aggregated.csv"))
    print("AGGREGATION_PASS")


if __name__ == "__main__": main()
