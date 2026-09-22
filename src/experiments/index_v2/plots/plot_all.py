"""Generate all four PNG/PDF figures from summary CSV files."""

import argparse
from pathlib import Path

import yaml

from . import (
    plot_f1_build_time, plot_f1_space, plot_f2_core_transform,
    plot_f2_integrated_query, plot_f2_transform_scaling,
)


def plot_all(run_dir):
    with open(Path(run_dir) / "config_resolved.yaml", encoding="utf-8") as handle:
        filters = yaml.safe_load(handle)["filters"]
    plot_f1_build_time.plot(run_dir, filters)
    plot_f1_space.plot(run_dir, filters)
    plot_f2_integrated_query.plot(run_dir, filters)
    plot_f2_core_transform.plot(run_dir, filters)
    # Total Transform remains available as a supplemental pairing-dominated view.
    plot_f2_transform_scaling.plot(run_dir, filters)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    args = parser.parse_args(argv)
    plot_all(args.run_dir)
    print(Path(args.run_dir) / "figures")


if __name__ == "__main__":
    main()
