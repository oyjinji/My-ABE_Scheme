"""Experiments 8 and 11: segment layout and joint parameter sensitivity."""

import random
from time import perf_counter_ns

from fx_exp.filters.fxabf_fuse import FXABFFuse
from fx_exp.generators import token_entries
from .common import ExperimentRun, configure, parser


def combination_count(config):
    layout = config["experiments"]["segments"]
    joint = config["experiments"]["sensitivity"]
    return (len(layout["u"]) * len(layout["segment_length"]) * len(layout["c_fx"]) * int(layout["trials"]) +
            len(joint["u"]) * len(joint["r_max"]) * len(joint["gamma"]) *
            len(joint["c_fx"]) * int(joint["trials"]))


def run(run_context):
    warm_seed = run_context.seed("sensitivity-warmup")
    FXABFFuse().build(token_entries(4, warm_seed), run_context.config["filter"], random.Random(warm_seed))
    _segments(run_context)
    if not run_context.interrupted:
        _joint(run_context)


def _segments(run_context):
    grid = run_context.config["experiments"]["segments"]
    completed = run_context.completed_keys("exp08_segments")
    for u in grid["u"]:
        for segment_length in grid["segment_length"]:
            for c_fx in grid["c_fx"]:
                for trial in range(int(grid["trials"])):
                    key = "u={0}|segment={1}|c={2}|trial={3}".format(u, segment_length, c_fx, trial)
                    if key in completed:
                        continue
                    seed = run_context.seed("segments", u, segment_length, c_fx, trial)
                    try:
                        entries = token_entries(int(u), seed)
                        config = dict(run_context.config["filter"])
                        config.update({"segment_length": int(segment_length), "c_fx": float(c_fx)})
                        backend = FXABFFuse()
                        index = backend.build(entries, config, random.Random(seed))
                        backend.query(index, next(iter(entries)))
                        query_started = perf_counter_ns()
                        for token in entries:
                            backend.query(index, token)
                        query_ns = (perf_counter_ns() - query_started) / float(u)
                        stats = index["build_stats"]
                        size = backend.serialized_size(index)
                        run_context.record("exp08_segments", key, {
                            "u": int(u), "segment_length": int(segment_length),
                            "c_fx": float(c_fx), "trial": trial, "seed": seed,
                            "first_attempt_success": int(stats.first_attempt_success),
                            "retries": stats.retries, "expansions": stats.expansions,
                            "build_ns": index["build_ns"], "mean_query_ns": query_ns,
                            "filter_bytes": size["filter_bytes"],
                        })
                    except Exception as exc:
                        run_context.record_failure("exp08_segments", key, {
                            "u": u, "segment_length": segment_length, "c_fx": c_fx,
                        }, seed, exc)
                    if run_context.interrupted:
                        return


def _joint(run_context):
    grid = run_context.config["experiments"]["sensitivity"]
    completed = run_context.completed_keys("exp11_sensitivity")
    for u in grid["u"]:
        for r_max in grid["r_max"]:
            for gamma in grid["gamma"]:
                for c_fx in grid["c_fx"]:
                    for trial in range(int(grid["trials"])):
                        key = "u={0}|r={1}|g={2}|c={3}|trial={4}".format(u, r_max, gamma, c_fx, trial)
                        if key in completed:
                            continue
                        seed = run_context.seed("sensitivity", u, r_max, gamma, c_fx, trial)
                        try:
                            entries = token_entries(int(u), seed)
                            config = dict(run_context.config["filter"])
                            config.update({"r_max": int(r_max), "gamma": float(gamma), "c_fx": float(c_fx)})
                            backend = FXABFFuse()
                            index = backend.build(entries, config, random.Random(seed))
                            stats = index["build_stats"]
                            size = backend.serialized_size(index)
                            run_context.record("exp11_sensitivity", key, {
                                "u": int(u), "r_max": int(r_max), "gamma": float(gamma),
                                "c_fx": float(c_fx), "trial": trial, "seed": seed,
                                "eventual_success": 1, "retries": stats.retries,
                                "expansions": stats.expansions, "build_ns": index["build_ns"],
                                "final_load_factor": u / float(stats.final_m),
                                "final_bytes_per_token": size["filter_bytes"] / float(u),
                            })
                        except Exception as exc:
                            run_context.record_failure("exp11_sensitivity", key, {
                                "u": u, "r_max": r_max, "gamma": gamma, "c_fx": c_fx,
                            }, seed, exc)
                        if run_context.interrupted:
                            return


def main():
    args = parser(__doc__).parse_args()
    config = configure(args)
    if args.dry_run:
        print("exp08+11 combinations: {0}".format(combination_count(config)))
        return
    context = ExperimentRun(config, args.run_id, args.resume)
    run(context)
    context.summarize()
    print(context.run_dir)


if __name__ == "__main__":
    main()
