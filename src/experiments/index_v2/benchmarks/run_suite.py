"""Unified F1/F2/F3 suite runner."""

import argparse
import os
import sys
from pathlib import Path

from . import (
    benchmark_f1_build_space, benchmark_f2_transform_scaling,
    benchmark_f3_correctness,
)
from .common import (
    create_run_dir, dump_json, dump_yaml, environment_record, read_config,
    set_single_cpu_affinity,
)


def run_benchmarks(config, run_dir):
    run_dir = Path(run_dir)
    benchmark_f1_build_space.run(
        config, run_dir / "raw" / "f1_build_space.csv"
    )
    benchmark_f2_transform_scaling.run(
        config, run_dir / "raw" / "f2_transform_scaling.csv"
    )
    benchmark_f3_correctness.run(
        config, run_dir / "raw" / "f3_correctness.csv"
    )
    from fx_exp_v2.analysis.summarize_results import summarize_run
    summarize_run(run_dir)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--validate", action="store_true")
    parser.add_argument("--plot", action="store_true")
    parser.add_argument("--report", action="store_true")
    args = parser.parse_args(argv)
    config = read_config(args.config)
    run_id, run_dir = create_run_dir(config)
    dump_yaml(run_dir / "config_resolved.yaml", config)
    affinity = set_single_cpu_affinity()
    environment = environment_record(
        args.config, sys.argv, config.get("pairing_group", "MNT224"), affinity
    )
    dump_json(run_dir / "environment.json", environment)
    log_path = run_dir / "logs" / "suite.log"
    log_path.write_text(
        "run_id=%s\nmode=%s\naffinity=%s\n" %
        (run_id, config.get("mode"), affinity), encoding="utf-8"
    )
    print("run_id:", run_id, flush=True)
    print("run_dir:", run_dir, flush=True)
    run_benchmarks(config, run_dir)
    if args.validate:
        from fx_exp_v2.analysis.validate_results import validate
        errors, _ = validate(run_dir)
        if errors:
            for error in errors:
                print("ERROR:", error)
            raise SystemExit(1)
    if args.plot:
        from fx_exp_v2.plots.plot_all import plot_all
        plot_all(run_dir)
    if args.report:
        from fx_exp_v2.analysis.generate_report import generate
        generate(run_dir)
    print("completed:", run_id)


if __name__ == "__main__":
    main()
