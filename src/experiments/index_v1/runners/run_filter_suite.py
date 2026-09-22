"""Experiment 7: uniform eight-backend filter comparison."""

import random
from time import perf_counter_ns

from experiments.index_v1.filters import create_backends
from experiments.index_v1.generators import nonmember_tokens, token_entries
from .common import ExperimentRun, configure, parser


def combination_count(config):
    grid = config["experiments"]["filter_suite"]
    backend_count = len(grid.get("backends", create_backends()))
    return len(grid["u"]) * int(grid["trials"]) * backend_count


def run(run_context):
    grid = run_context.config["experiments"]["filter_suite"]
    backend_names = grid.get("backends")
    completed = run_context.completed_keys("exp07_filter_suite")
    for u in grid["u"]:
        for trial in range(int(grid["trials"])):
            workload_seed = run_context.seed("filter-suite", u, trial)
            entries = token_entries(int(u), workload_seed)
            members = list(entries)
            misses = nonmember_tokens(int(grid["queries"]), workload_seed + 1)
            for backend in create_backends(backend_names):
                key = "u={0}|trial={1}|backend={2}".format(u, trial, backend.name)
                if key in completed:
                    continue
                seed = run_context.seed("filter-backend", u, trial, backend.name)
                try:
                    config = dict(run_context.config["filter"])
                    warm_entries = token_entries(4, seed + 1)
                    warm_index = backend.build(warm_entries, config, random.Random(seed + 1))
                    backend.query(warm_index, next(iter(warm_entries)))
                    index = backend.build(entries, config, random.Random(seed))
                    validation = backend.validate(index, entries)
                    hit_ns = miss_ns = 0
                    false_accepts = 0
                    hit_limit = min(len(members), int(grid["queries"]))
                    started = perf_counter_ns()
                    for token in members[:hit_limit]:
                        before = perf_counter_ns()
                        result = backend.query(index, token)
                        hit_ns += perf_counter_ns() - before
                        if not result.hit:
                            raise AssertionError("member false negative")
                    hit_batch_ns = perf_counter_ns() - started
                    for token in misses:
                        before = perf_counter_ns()
                        result = backend.query(index, token)
                        miss_ns += perf_counter_ns() - before
                        false_accepts += int(result.hit)
                    size = backend.serialized_size(index)
                    total_queries = hit_limit + len(misses)
                    total_ns = hit_ns + miss_ns
                    row = {
                        "backend": backend.name, "u": int(u), "trial": trial, "seed": seed,
                        "build_ns": index["build_ns"], "retries": index.get("retries", 0),
                        "expansions": index.get("expansions", 0),
                        "hit_query_ns": hit_ns / float(hit_limit),
                        "miss_query_ns": miss_ns / float(len(misses)),
                        "mixed_throughput_qps": total_queries * 1e9 / max(1, total_ns),
                        "false_accepts": false_accepts,
                        "false_negatives": validation.false_negatives,
                    }
                    row.update(size)
                    run_context.record("exp07_filter_suite", key, row)
                except Exception as exc:
                    run_context.record_failure("exp07_filter_suite", key, {
                        "backend": backend.name, "u": u,
                    }, seed, exc)
                if run_context.interrupted:
                    return


def main():
    args = parser(__doc__).parse_args()
    config = configure(args)
    if args.dry_run:
        print("exp07 combinations: {0}".format(combination_count(config)))
        return
    context = ExperimentRun(config, args.run_id, args.resume)
    run(context)
    context.summarize()
    print(context.run_dir)


if __name__ == "__main__":
    main()
