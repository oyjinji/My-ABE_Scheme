#!/usr/bin/env python3
"""Run the Global ABE end-to-end performance experiments.

Usage:
    python3 Global_Exp/scripts/run_all.py --config Global_Exp/configs/smoke.yaml \
        --run-name global_smoke_20260812_v1
    python3 Global_Exp/scripts/run_all.py --config Global_Exp/configs/standard.yaml \
        --run-name global_standard_20260812_v1
    python3 Global_Exp/scripts/run_all.py --config Global_Exp/configs/full.yaml \
        --run-name global_full_20260812_v1 [--experiments exp03,exp06]

Writes the run directory ``Global_Exp/results/<run_name>/`` with metadata.json,
config_snapshot.yaml, environment.json, correctness.json, raw/, summary/,
plots/ and logs/.
"""

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from charm.toolbox.pairinggroup import PairingGroup  # noqa: E402

from Global_Exp.src.common import (  # noqa: E402
    dump_json, dump_yaml, environment_record, load_config,
    results_paths, set_single_cpu_affinity, create_results_dir,
)
from Global_Exp.src.experiments import (  # noqa: E402
    RUNNERS, run_correctness_check, run_experiments,
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--run-name", required=True)
    parser.add_argument("--experiments", default=None,
                        help="comma-separated subset of exp01..exp08")
    args = parser.parse_args()

    config = load_config(args.config)
    run_dir = create_results_dir(config["mode"], args.run_name)
    paths = results_paths(run_dir)

    affinity = set_single_cpu_affinity()
    print("cpu_affinity=%r" % affinity, flush=True)

    group = PairingGroup(config.get("pairing_group", "MNT224"),
                         secparam=int(config.get("secparam", 512)))

    env = environment_record(args.config, config, group, affinity, args.run_name)
    dump_json(paths["root"] / "environment.json", env)
    dump_yaml(paths["root"] / "config_snapshot.yaml", config)
    dump_yaml(paths["root"] / "config.yaml", config)

    selected = (args.experiments.split(",") if args.experiments else None)
    experiment_names = list(selected or RUNNERS)

    # Correctness spot-check (fresh, real, untimed) is part of every run.
    print("running correctness spot-check ...", flush=True)
    correctness = run_correctness_check(config, group)
    dump_json(paths["root"] / "correctness.json", correctness)
    print("  all_ok=%s" % correctness["all_ok"], flush=True)
    if not correctness["all_ok"]:
        raise SystemExit("correctness check failed; refusing to benchmark")

    timings = {}
    for name in experiment_names:
        started = time.perf_counter()
        run_experiments(config, group, args.run_name, paths["raw"],
                        selected=[name])
        timings[name] = time.perf_counter() - started
        print("  %s done in %.1fs" % (name, timings[name]), flush=True)

    dump_json(paths["logs"] / "timing.json", timings)
    metadata = {
        "run_name": args.run_name,
        "mode": config["mode"],
        "config_path": args.config,
        "schemes": list(config.get("schemes", ["FABEO22", "FXABE-Base",
                                               "FXABE-Full"])),
        "repetitions": int(config["repetitions"]),
        "warmups": int(config["warmups"]),
        "policy_rows": [int(x) for x in config["policy_rows"]],
        "user_attrs": [int(x) for x in config["user_attrs"]],
        "master_seed": int(config["master_seed"]),
        "experiments": experiment_names,
        "timing_seconds": timings,
    }
    dump_json(paths["root"] / "metadata.json", metadata)
    print("wrote results to %s" % run_dir, flush=True)


if __name__ == "__main__":
    main()
