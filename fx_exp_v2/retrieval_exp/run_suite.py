"""CLI for the isolated functionally-equivalent retrieval suite."""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

from fx_exp_v2.benchmarks.common import (
    environment_record, set_single_cpu_affinity,
)
from .benchmark import run
from .plot import plot_all
from .report import generate
from .summarize import summarize
from .validate import validate


ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"


def _run_id(config):
    import hashlib
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    digest = hashlib.sha256(
        json.dumps(config, sort_keys=True).encode()
    ).hexdigest()[:8]
    return "%s-%s-%s" % (config["mode"], stamp, digest)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config", default=str(ROOT / "configs" / "smoke.yaml")
    )
    parser.add_argument("--validate", action="store_true")
    parser.add_argument("--plot", action="store_true")
    parser.add_argument("--report", action="store_true")
    args = parser.parse_args(argv)
    config_path = Path(args.config)
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    run_id = _run_id(config)
    run_dir = RESULTS / run_id
    for directory in ("raw", "summary", "figures", "report", "logs"):
        (run_dir / directory).mkdir(parents=True, exist_ok=False)
    affinity = set_single_cpu_affinity()
    environment = environment_record(
        config_path, sys.argv, "none (retrieval-only)", affinity
    )
    (run_dir / "environment.json").write_text(
        json.dumps(environment, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (run_dir / "config_resolved.yaml").write_text(
        yaml.safe_dump(config, sort_keys=False), encoding="utf-8"
    )
    run(config, run_dir / "raw" / "retrieval_results.csv")
    summarize(
        run_dir / "raw" / "retrieval_results.csv",
        run_dir / "summary" / "retrieval_summary.csv",
    )
    ok = True
    if args.validate:
        ok, _ = validate(run_dir, config)
    if args.plot:
        plot_all(run_dir)
    if args.report:
        generate(run_dir)
    print("run_id=%s" % run_id)
    print("run_dir=%s" % run_dir)
    if not ok:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
