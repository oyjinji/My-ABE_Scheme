#!/usr/bin/env python3
"""Run, aggregate, validate, plot and analyze one non-Full profile."""

import argparse
import subprocess
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]


def call(*args):
    subprocess.run([sys.executable,*map(str,args)],cwd=str(ROOT),check=True)


def main():
    parser=argparse.ArgumentParser();parser.add_argument("--config",required=True);parser.add_argument("--run-id",required=True);parser.add_argument("--resume",action="store_true");args=parser.parse_args()
    run=ROOT/"Perf_Exp_05_3"/"results"/args.run_id
    runner_args=["Perf_Exp_05_3/scripts/run_suite.py","--config",args.config,"--run-id",args.run_id]
    if args.resume:runner_args.append("--resume")
    call(*runner_args)
    call("Perf_Exp_05_3/scripts/aggregate.py",run)
    call("Perf_Exp_05_3/scripts/validate_results.py",run)
    call("Perf_Exp_05_3/scripts/plot_all.py",run)
    call("Perf_Exp_05_3/scripts/validate_results.py",run,"--require-plots")
    call("Perf_Exp_05_3/scripts/generate_analysis.py",run)
    call("Perf_Exp_05_3/scripts/write_manifest.py",run)
    print("PIPELINE_PASS",run)


if __name__=="__main__":main()
