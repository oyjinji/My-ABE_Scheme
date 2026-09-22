#!/usr/bin/env python3
"""Correctness gate, tiered benchmark suite, aggregation, validation and plots."""

import argparse
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
sys.dont_write_bytecode = True
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from experiments.rev_exp.scripts.aggregate import SPECS, aggregate_all
from experiments.rev_exp.scripts.plot_all import main as plot_main
from experiments.rev_exp.src.common import (
    create_results_dir, dump_json, environment_metadata, load_config, results_paths,
)
from experiments.rev_exp.src.experiments import run_selected
from experiments.rev_exp.src.planning import format_plan, plan_totals, workload_plan


def _correctness_gate():
    test_env = dict(os.environ)
    test_env["PYTHONDONTWRITEBYTECODE"] = "1"
    subprocess.run(
        [sys.executable, "-m", "pytest", "src/experiments/rev_exp/tests", "-q",
         "-p", "no:cacheprovider"],
        cwd=str(ROOT), check=True, env=test_env,
    )


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--run-name",
                        help="non-overwriting subdirectory under src/experiments/rev_exp/results")
    parser.add_argument("--dry-run", action="store_true",
                        help="print tiered workload only; execute no crypto")
    parser.add_argument("--skip-tests", action="store_true")
    parser.add_argument("--experiments", nargs="*",
                        choices=["exp01", "exp02", "exp04", "exp05", "exp06"])
    args = parser.parse_args(argv)
    config = load_config(args.config)

    if args.dry_run:
        print(format_plan(config))
        return 0

    if not args.skip_tests:
        _correctness_gate()
    run_dir = create_results_dir(config["mode"], args.run_name)
    group, output = run_selected(config, run_dir, args.experiments)
    metadata = environment_metadata(args.config, config, group)
    metadata.update({
        "run_name": run_dir.name,
        "results_dir": str(run_dir.resolve()),
        "row_counts": {name: len(rows) for name, rows in output.items()},
        "workload_plan": workload_plan(config),
        "workload_totals": plan_totals(config),
    })
    paths = results_paths(run_dir)
    dump_json(paths["metadata"] / "run.json", metadata)

    if args.experiments:
        names = list(args.experiments)
        if "exp02" in names:
            names.append("exp03")
    else:
        names = list(SPECS)
    aggregate_all(run_dir, names if args.experiments else None)
    if not args.experiments:
        subprocess.run(
            [sys.executable, "src/experiments/rev_exp/scripts/validate_results.py",
             "--results-dir", str(run_dir)],
            cwd=str(ROOT), check=True,
        )
        plot_main(["--results-dir", str(run_dir)])
    print("completed mode=%s run=%s rows=%d" %
          (config["mode"], run_dir.name,
           sum(len(rows) for rows in output.values())))
    return 0


if __name__ == "__main__":
    main()
