#!/usr/bin/env python3
"""Project the full-config runtime from a completed standard run.

Writes ``logs/runtime_projection.json`` inside the reference (standard) run
directory and prints a short report.  Used to decide, per requirement 30,
whether the full config is feasible -- if it is not, the projection plus the
exact full command is reported instead of a fabricated run.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import yaml  # noqa: E402

from Global_Exp.src.common import dump_json, load_config  # noqa: E402
from Global_Exp.src.planning import project  # noqa: E402


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference-dir", required=True,
                        help="completed standard run directory")
    parser.add_argument("--candidate-config",
                        default="Global_Exp/configs/full.yaml")
    parser.add_argument("--run-name", default="global_full_20260812_v1")
    args = parser.parse_args()

    reference_dir = Path(args.reference_dir)
    reference_cfg_path = reference_dir / "config_snapshot.yaml"
    if not reference_cfg_path.exists():
        raise SystemExit("reference run has no config_snapshot.yaml")
    with open(reference_cfg_path, encoding="utf-8") as handle:
        reference_config = yaml.safe_load(handle)
    candidate = load_config(args.candidate_config)

    result = project(candidate, reference_dir, reference_config)
    result["candidate_config"] = args.candidate_config
    result["candidate_run_name"] = args.run_name
    result["full_command"] = (
        "python3 Global_Exp/scripts/run_all.py --config %s --run-name %s"
        % (args.candidate_config, args.run_name)
    )
    dump_json(reference_dir / "logs" / "runtime_projection.json", result)

    print("=== Full-config runtime projection (from %s) ===" % reference_dir)
    for experiment, item in sorted(result["per_experiment"].items()):
        print("  %-6s ref=%6.1fs  projected=%7.1fs  scale=%5.2fx  points %d->%d"
              % (experiment, item["reference_seconds"],
                 item["candidate_seconds"], item["scale"],
                 item["reference_points"], item["candidate_points"]))
    print("projected_total_minutes: %.1f" % result["projected_total_minutes"])
    for warning in result["linearity_warnings"]:
        print("WARNING: %s" % warning)
    print("full command:\n  %s" % result["full_command"])
    print("wrote %s" % (reference_dir / "logs" / "runtime_projection.json"))


if __name__ == "__main__":
    main()
