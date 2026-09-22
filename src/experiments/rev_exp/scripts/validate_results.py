#!/usr/bin/env python3
"""Fail on missing points, NaN/zero times, bad Transform counts, or bad cover data."""

import math
import argparse
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from experiments.rev_exp.src.common import read_csv, results_paths


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--results-dir", required=True)
    args = parser.parse_args(argv)
    files = sorted(results_paths(args.results_dir)["raw"].glob("*_raw.csv"))
    if len(files) != 6:
        raise SystemExit("expected 6 raw CSV files, found %d" % len(files))
    issues = []
    for path in files:
        rows = read_csv(path)
        if not rows:
            issues.append("empty: %s" % path.name)
        for line, row in enumerate(rows, 2):
            for key, value in row.items():
                if key.endswith("_ns"):
                    number = float(value)
                    if not math.isfinite(number) or number < 0:
                        issues.append("invalid %s:%d %s=%s" % (path.name, line, key, value))
            if path.name.startswith("exp04"):
                expected = 2 + 2 * int(row["actual_hit_rows"])
                if (row["status"] != "ok" or
                        int(row["actual_hit_rows"]) != int(row["configured_r"]) or
                        int(row["actual_pairing_count"]) != expected or
                        int(row["pairing_count"]) != expected):
                    issues.append("Transform count/status: %s:%d" % (path.name, line))
            if "cover_size" in row and int(row["cover_size"]) < 0:
                issues.append("negative cover: %s:%d" % (path.name, line))
            if "cover_invariant_valid" in row and row["cover_invariant_valid"] != "True":
                issues.append("cover invariant: %s:%d" % (path.name, line))
            for primary in ("total_ns", "transform_total_ns", "total_epoch_update_ns",
                            "privacykeyupt_ns"):
                if primary in row and float(row[primary]) <= 0:
                    issues.append("zero primary time: %s:%d %s" %
                                  (path.name, line, primary))
    if issues:
        raise SystemExit("\n".join(issues))
    print("validated %d files with no NaN, negative time, or count failure" % len(files))


if __name__ == "__main__":
    main()
