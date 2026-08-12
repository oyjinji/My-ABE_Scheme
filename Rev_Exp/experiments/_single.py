import argparse
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Rev_Exp.scripts.aggregate import aggregate_all
from Rev_Exp.src.common import create_results_dir, load_config
from Rev_Exp.src.experiments import run_selected


def run(name):
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--run-name")
    args = parser.parse_args()
    config = load_config(args.config)
    run_dir = create_results_dir(config["mode"], args.run_name)
    run_selected(config, run_dir, [name])
    names = [name]
    if name == "exp02":
        names.append("exp03")
    aggregate_all(run_dir, names)
    print(run_dir)
