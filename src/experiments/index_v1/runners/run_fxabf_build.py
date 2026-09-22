"""Experiments 1-3: first success, retries, build time and expansion."""

import random

from fx_exp.filters.fxabf_fuse import FXABFFuse
from fx_exp.generators import token_entries
from .common import ExperimentRun, configure, parser


def combination_count(config):
    grid = config["experiments"]["build"]
    return len(grid["u"]) * len(grid["c_fx"]) * int(grid["trials"])


def run(run_context):
    grid = run_context.config["experiments"]["build"]
    warm_seed = run_context.seed("build-warmup")
    FXABFFuse().build(token_entries(4, warm_seed), run_context.config["filter"], random.Random(warm_seed))
    completed = run_context.completed_keys("exp01_03_build")
    for u in grid["u"]:
        for c_fx in grid["c_fx"]:
            for trial in range(int(grid["trials"])):
                key = "u={0}|c={1}|trial={2}".format(u, c_fx, trial)
                if key in completed:
                    continue
                seed = run_context.seed("build", u, c_fx, trial)
                try:
                    entries = token_entries(int(u), seed)
                    config = dict(run_context.config["filter"])
                    config["c_fx"] = float(c_fx)
                    index = FXABFFuse().build(entries, config, random.Random(seed))
                    stats = index["build_stats"]
                    run_context.record("exp01_03_build", key, {
                        "u": int(u), "c_fx": float(c_fx), "trial": trial, "seed": seed,
                        "first_attempt_success": int(stats.first_attempt_success),
                        "retries": stats.retries, "initial_m": stats.initial_m,
                        "final_m": stats.final_m, "expansions": stats.expansions,
                        "success_before_expansion": int(stats.expansions == 0),
                        "failure_at_current_m": int(stats.expansions > 0),
                        "peeling_ns": stats.peeling_ns, "assignment_ns": stats.assignment_ns,
                        "pstore_encryption_ns": index["pstore"]["encryption_ns"],
                        "build_ns": index["build_ns"], "final_m_per_u": stats.final_m / float(u),
                    })
                except Exception as exc:
                    run_context.record_failure("exp01_03_build", key, {"u": u, "c_fx": c_fx}, seed, exc)
                if run_context.interrupted:
                    return


def main():
    args = parser(__doc__).parse_args()
    config = configure(args)
    if args.dry_run:
        print("exp01_03_build combinations: {0}".format(combination_count(config)))
        return
    context = ExperimentRun(config, args.run_id, args.resume)
    run(context)
    context.summarize()
    print(context.run_dir)


if __name__ == "__main__":
    main()
