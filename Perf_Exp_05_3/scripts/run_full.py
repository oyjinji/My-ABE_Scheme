#!/usr/bin/env python3
"""Explicit PRE_FULL-gated runner for the frozen Full scalability profile."""

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from time import perf_counter_ns

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from charm.toolbox.pairinggroup import PairingGroup  # noqa: E402
from Perf_Exp_05_3.scripts.common import dump_json, environment, load_yaml  # noqa: E402
from Perf_Exp_05_3.scripts.run_suite import (run_exp01, run_exp02, run_exp03, run_exp04,
                                             run_exp06, run_exp07, run_exp08_09,
                                             run_exp10, run_exp11, write_feature_table)  # noqa: E402


RUNNERS = (run_exp01, run_exp02, run_exp03, run_exp04, run_exp06, run_exp07,
           run_exp08_09, run_exp10, run_exp11)
OUTPUTS = {
    "run_exp01": ("exp01_encrypt.csv",), "run_exp02": ("exp02_storage.csv",),
    "run_exp03": ("exp03_transform_vs_J.csv",), "run_exp04": ("exp04_transform_vs_tI.csv",),
    "run_exp06": ("exp06_fx_build.csv",), "run_exp07": ("exp07_fx_query.csv",),
    "run_exp08_09": ("exp08_e2e_breakdown.csv", "exp09_anonymity_overhead.csv"),
    "run_exp10": ("exp10_revocation.csv",), "run_exp11": ("exp11_fabeo_core.csv",),
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True); parser.add_argument("--run-id", required=True)
    parser.add_argument("--standard-run", required=True); parser.add_argument("--resume", action="store_true")
    args = parser.parse_args(); config = load_yaml(args.config)
    if config.get("mode") != "full" or int(config["warmup"]) != 5 or int(config["repeats"]) != 50:
        raise SystemExit("refusing non-frozen Full timing profile")
    standard = Path(args.standard_run).resolve()
    gate = json.loads((standard / "PRE_FULL_GATE.json").read_text())
    if not gate.get("FULL_READY"):
        raise SystemExit("PRE_FULL gate is not ready")
    run_root = ROOT / "Perf_Exp_05_3/results" / args.run_id
    if run_root.exists() and not args.resume:
        raise SystemExit(f"result directory exists: {run_root}")
    for child in ("raw", "aggregated", "plots", "logs"):
        (run_root / child).mkdir(parents=True, exist_ok=args.resume)
    group = PairingGroup(config["curve"])
    if group.groupType() != "MNT224" or config["backend"] != "Charm-Crypto/PBC":
        raise SystemExit("COMMON_BENCHMARK_PROFILE mismatch")
    # FABEO's left-deep official policy tree at ell=1280 needs interpreter
    # stack headroom. This does not alter its algorithm, policy, or workload.
    sys.setrecursionlimit(max(sys.getrecursionlimit(), 10000))
    if not args.resume or not (run_root / "correctness.json").exists():
        dump_json(run_root / "environment.json", environment(group, args.config))
        shutil.copy2(args.config, run_root / "config_snapshot.yaml")
        test = subprocess.run([sys.executable, "-m", "pytest", "-q", "Perf_Exp_05_3/tests/test_correctness.py"],
                              cwd=str(ROOT), text=True, capture_output=True)
        dump_json(run_root / "correctness.json", {"success": test.returncode == 0,
                                                   "stdout": test.stdout, "stderr": test.stderr})
        if test.returncode:
            raise SystemExit("Full correctness gate failed")
    timing_path = run_root / "logs/timings.json"
    timings = json.loads(timing_path.read_text()) if args.resume and timing_path.exists() else {}
    for runner in RUNNERS:
        names = OUTPUTS[runner.__name__]
        if args.resume and all((run_root / "raw" / name).exists() for name in names):
            print(f"{runner.__name__} SKIP completed raw", flush=True)
            continue
        started = perf_counter_ns()
        runner(config, group, args.run_id, run_root / "raw")
        timings[runner.__name__] = perf_counter_ns() - started
        dump_json(timing_path, timings)
        print(f"{runner.__name__} PASS {timings[runner.__name__] / 1e9:.3f}s", flush=True)
    write_feature_table(run_root)
    dump_json(run_root / "metadata.json", {
        "run_id": args.run_id, "mode": "full", "full_run": True,
        "experiments": "EXP-01,02,03,04,06,07,08,09,10,11",
        "reused_verified_standard": ["EXP-00", "EXP-05"],
        "supplemental_standard": "EXP-12", "skip_supplemental_full": True,
        "pre_full_gate": str(standard / "PRE_FULL_GATE.json"),
    })
    print(f"FULL_RAW_COMPLETE {run_root}", flush=True)


if __name__ == "__main__":
    main()
