"""Experiments 4 and 10: hit/miss breakdown and empirical rejection."""

import random
from time import perf_counter_ns

from experiments.index_v1.filters.fxabf_fuse import FXABFFuse
from experiments.index_v1.generators import nonmember_tokens, token_entries
from .common import ExperimentRun, configure, parser


def combination_count(config):
    query = config["experiments"]["query"]
    rejection = config["experiments"]["rejection"]
    return (len(query["u"]) * len(query["hit_ratios"]) * int(query["trials"]) +
            len(rejection["delta"]) * int(rejection["trials"]))


def run(run_context):
    query = run_context.config["experiments"]["query"]
    completed = run_context.completed_keys("exp04_query")
    for u in query["u"]:
        for ratio in query["hit_ratios"]:
            for trial in range(int(query["trials"])):
                key = "u={0}|ratio={1}|trial={2}".format(u, ratio, trial)
                if key in completed:
                    continue
                seed = run_context.seed("query", u, ratio, trial)
                try:
                    entries = token_entries(int(u), seed)
                    backend = FXABFFuse()
                    index = backend.build(entries, run_context.config["filter"], random.Random(seed))
                    backend.query(index, next(iter(entries)))
                    count = int(query["queries"])
                    hit_count = round(count * float(ratio))
                    members = list(entries)[:hit_count]
                    misses = nonmember_tokens(count - hit_count, seed + 1)
                    workload = members + misses
                    random.Random(seed + 2).shuffle(workload)
                    totals = {}
                    hits = attempts = successes = 0
                    started = perf_counter_ns()
                    for token in workload:
                        result = backend.query(index, token)
                        hits += int(result.hit)
                        attempts += result.metrics.get("aead_attempts", 0)
                        successes += result.metrics.get("aead_successes", 0)
                        for name, value in result.metrics.items():
                            totals[name] = totals.get(name, 0) + value
                    elapsed = perf_counter_ns() - started
                    row = {
                        "u": int(u), "hit_ratio": float(ratio), "trial": trial, "seed": seed,
                        "query_count": count, "hit_count": hits,
                        "aead_attempts": attempts, "aead_successes": successes,
                        "batch_query_ns": elapsed, "mean_query_ns": elapsed / count,
                    }
                    row.update({"total_" + name: value for name, value in totals.items()})
                    run_context.record("exp04_query", key, row)
                except Exception as exc:
                    run_context.record_failure("exp04_query", key, {"u": u, "ratio": ratio}, seed, exc)
                if run_context.interrupted:
                    return
    _run_rejection(run_context)


def _run_rejection(run_context):
    grid = run_context.config["experiments"]["rejection"]
    completed = run_context.completed_keys("exp10_rejection")
    u = int(grid["u"])
    for delta in grid["delta"]:
        for trial in range(int(grid["trials"])):
            key = "delta={0}|trial={1}".format(delta, trial)
            if key in completed:
                continue
            seed = run_context.seed("rejection", delta, trial)
            try:
                entries = token_entries(u, seed)
                config = dict(run_context.config["filter"])
                config["delta"] = int(delta)
                backend = FXABFFuse()
                index = backend.build(entries, config, random.Random(seed))
                counts = {"range": 0, "short-check": 0, "aead": 0, "hit": 0, "malformed": 0}
                attempts = rejected = 0
                queries = nonmember_tokens(int(grid["queries"]), seed + 1)
                for token in queries:
                    result = backend.query(index, token)
                    counts[result.reason] = counts.get(result.reason, 0) + 1
                    attempts += result.metrics.get("aead_attempts", 0)
                    rejected += int(result.reason == "aead")
                total = len(queries)
                run_context.record("exp10_rejection", key, {
                    "u": u, "delta": int(delta), "trial": trial, "seed": seed,
                    "total_nonmember_queries": total,
                    "range_rejected": counts["range"],
                    "short_check_rejected": counts["short-check"],
                    "aead_attempted": attempts, "aead_rejected": rejected,
                    "false_accepted": counts["hit"],
                    "empirical_false_accept_rate": counts["hit"] / float(total),
                })
            except Exception as exc:
                run_context.record_failure("exp10_rejection", key, {"delta": delta}, seed, exc)
            if run_context.interrupted:
                return


def main():
    args = parser(__doc__).parse_args()
    config = configure(args)
    if args.dry_run:
        print("exp04+10 combinations: {0}".format(combination_count(config)))
        return
    context = ExperimentRun(config, args.run_id, args.resume)
    run(context)
    context.summarize()
    print(context.run_dir)


if __name__ == "__main__":
    main()
