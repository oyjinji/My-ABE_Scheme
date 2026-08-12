"""Targeted 8192/16384 FX-ABF Build probe with per-attempt evidence.

The ``before`` phase instruments the production implementation without
changing its retry policy.  The fixed implementation exposes equivalent
attempt records directly, so the same driver can be used for ``after``.
"""

import argparse
import json
import math
import random
from collections import deque
from pathlib import Path
from time import perf_counter_ns

from Code.fxabe_rev.filters import create_index
import Code.fxabe_rev.filters.fxabf as fxabf_module

from fx_exp_v2.benchmarks.common import derive_seed, ns_to_ms, write_csv
from fx_exp_v2.benchmarks.workload import f1_workload


TARGET_FIELDS = [
    "phase", "u", "seed_index", "workload_seed", "filter_seed",
    "attempt_count", "failed_attempt_count", "resize_count", "final_capacity",
    "retry_ms", "position_generation_ms", "peeling_ms", "assignment_ms",
    "pstore_build_ms", "pstore_build_count", "build_total_ms",
    "component_sum_ms", "timing_residual_ms", "member_false_negative_count",
    "integrated_index_bytes",
]

ATTEMPT_FIELDS = [
    "phase", "u", "seed_index", "workload_seed", "filter_seed", "seed",
    "attempt_index", "array_capacity", "load_factor", "segment_length",
    "segment_count", "tail_segment_length", "peeled_edges",
    "remaining_core_edges", "position_generation_ms", "peeling_ms",
    "assignment_ms", "attempt_total_ms", "attempt_success",
    "segment_occupancy_json", "min_segment_occupancy",
    "max_segment_occupancy", "occupancy_cv", "three_position_collision_count",
    "degree_0_count", "degree_1_count", "degree_2_count",
    "degree_3plus_count",
]


def _legacy_instrumented_build(entries, context, filter_seed):
    """Run the pre-fix Build and collect its otherwise-unexposed attempts."""
    rng = random.Random(filter_seed)
    index = create_index("FX-ABF")
    original_fuse = fxabf_module.fuse_positions
    attempt_rows = []
    prepass = {"ns": 0}

    def timed_fuse(seed, token, m, meta):
        started = perf_counter_ns()
        result = original_fuse(seed, token, m, meta)
        prepass["ns"] += perf_counter_ns() - started
        return result

    def probed_peel(tokens, seed, m, meta):
        external_position_ns = prepass["ns"]
        prepass["ns"] = 0
        position_started = perf_counter_ns()
        edges = {token: original_fuse(seed, token, m, meta) for token in tokens}
        adjacent = [[] for _ in range(m)]
        degree = [0] * m
        occupancy = [0] * meta.segment_count
        collisions = 0
        for token, edge in edges.items():
            collisions += 3 - len(set(edge))
            for position in edge:
                adjacent[position].append(token)
                degree[position] += 1
                occupancy[position // meta.segment_length] += 1
        internal_position_ns = perf_counter_ns() - position_started
        initial_degree = tuple(degree)
        peeling_started = perf_counter_ns()
        queue = deque(i for i, value in enumerate(degree) if value == 1)
        removed, stack = set(), []
        while queue:
            pivot = queue.popleft()
            if degree[pivot] != 1:
                continue
            token = next(
                (item for item in adjacent[pivot] if item not in removed), None
            )
            if token is None:
                continue
            removed.add(token)
            stack.append((token, pivot))
            for position in edges[token]:
                degree[position] -= 1
                if degree[position] == 1:
                    queue.append(position)
        peeling_ns = perf_counter_ns() - peeling_started
        mean = sum(occupancy) / float(len(occupancy))
        variance = sum((value - mean) ** 2 for value in occupancy) / len(occupancy)
        attempt_rows.append({
            "seed": seed.hex(), "attempt_index": len(attempt_rows) + 1,
            "array_capacity": m, "load_factor": len(tokens) / float(m),
            "segment_length": meta.segment_length,
            "segment_count": meta.segment_count,
            "tail_segment_length": m - (meta.segment_count - 1) * meta.segment_length,
            "peeled_edges": len(stack),
            "remaining_core_edges": len(tokens) - len(stack),
            "position_generation_ms": ns_to_ms(
                external_position_ns + internal_position_ns),
            "peeling_ms": ns_to_ms(peeling_ns), "assignment_ms": 0.0,
            "attempt_total_ms": ns_to_ms(
                external_position_ns + internal_position_ns + peeling_ns),
            "attempt_success": len(stack) == len(tokens),
            "segment_occupancy_json": json.dumps(occupancy, separators=(",", ":")),
            "min_segment_occupancy": min(occupancy),
            "max_segment_occupancy": max(occupancy),
            "occupancy_cv": math.sqrt(variance) / mean if mean else 0.0,
            "three_position_collision_count": collisions,
            "degree_0_count": sum(value == 0 for value in initial_degree),
            "degree_1_count": sum(value == 1 for value in initial_degree),
            "degree_2_count": sum(value == 2 for value in initial_degree),
            "degree_3plus_count": sum(value >= 3 for value in initial_degree),
        })
        return ((stack, edges) if len(stack) == len(tokens) else (None, edges))

    fxabf_module.fuse_positions = timed_fuse
    index._peel = probed_peel
    try:
        index.build(entries, context, rng)
    finally:
        fxabf_module.fuse_positions = original_fuse
    stats = index.stats()
    attempt_rows[-1]["assignment_ms"] = ns_to_ms(
        stats["reverse_assignment_ns"])
    attempt_rows[-1]["attempt_total_ms"] += attempt_rows[-1]["assignment_ms"]
    return index, stats, attempt_rows


def _normal_diagnostic_build(entries, context, filter_seed):
    index = create_index("FX-ABF")
    index.build(entries, context, random.Random(filter_seed))
    stats = index.stats()
    return index, stats, [dict(row) for row in stats["attempts"]]


def run_phase(phase, output_dir, master_seed=20260729, seed_count=50):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    targeted, attempts = [], []
    for u in (8192, 16384):
        for seed_index in range(seed_count):
            workload_seed = derive_seed(master_seed, "FXABF-target", u, seed_index)
            filter_seed = derive_seed(master_seed, "FXABF-filter", u, seed_index)
            workload = f1_workload(u, "F1-A", workload_seed)
            context = ("FXABF-TARGET|%d|%d" % (u, seed_index)).encode()
            if phase == "before":
                index, stats, details = _legacy_instrumented_build(
                    workload["entries"], context, filter_seed
                )
            else:
                index, stats, details = _normal_diagnostic_build(
                    workload["entries"], context, filter_seed
                )
            for detail in details:
                attempts.append({
                    "phase": phase, "u": u, "seed_index": seed_index,
                    "workload_seed": workload_seed, "filter_seed": filter_seed,
                    **detail,
                })
            sizes = index.size_breakdown()
            member_false_negatives = sum(
                not index.query(token, context).hit for token in workload["entries"]
            )
            component_sum_ns = int(stats.get("component_sum_ns", 0))
            if component_sum_ns <= 0:
                component_sum_ns = (
                    stats["position_generation_ns"] +
                    stats["peeling_or_insertion_ns"] +
                    stats["reverse_assignment_ns"] +
                    stats["pstore_build_ns"]
                )
            targeted.append({
                "phase": phase, "u": u, "seed_index": seed_index,
                "workload_seed": workload_seed, "filter_seed": filter_seed,
                "attempt_count": stats["attempt_count"],
                "failed_attempt_count": stats["attempt_count"] - 1,
                "resize_count": stats["resize_count"],
                "final_capacity": stats["final_capacity"],
                "retry_ms": ns_to_ms(stats["retry_ns"]),
                "position_generation_ms": ns_to_ms(
                    stats["position_generation_ns"]),
                "peeling_ms": ns_to_ms(stats["peeling_or_insertion_ns"]),
                "assignment_ms": ns_to_ms(stats["reverse_assignment_ns"]),
                "pstore_build_ms": ns_to_ms(stats["pstore_build_ns"]),
                "pstore_build_count": stats.get("pstore_build_count", 1),
                "build_total_ms": ns_to_ms(stats["build_total_ns"]),
                "component_sum_ms": ns_to_ms(component_sum_ns),
                "timing_residual_ms": ns_to_ms(
                    stats["build_total_ns"] - component_sum_ns),
                "member_false_negative_count": member_false_negatives,
                "integrated_index_bytes": sum(sizes.values()),
            })
            print(
                "%s u=%d seed=%d attempts=%d resize=%d total=%.1fms" %
                (phase, u, seed_index, stats["attempt_count"],
                 stats["resize_count"], ns_to_ms(stats["build_total_ns"])),
                flush=True,
            )
    write_csv(
        output_dir / ("%s_fxabf_targeted_raw.csv" % phase),
        targeted, TARGET_FIELDS,
    )
    write_csv(
        output_dir / ("%s_fxabf_attempts_raw.csv" % phase),
        attempts, ATTEMPT_FIELDS,
    )
    return targeted, attempts


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=("before", "after"), required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--master-seed", type=int, default=20260729)
    parser.add_argument("--seed-count", type=int, default=50)
    args = parser.parse_args(argv)
    run_phase(args.phase, args.output_dir, args.master_seed, args.seed_count)


if __name__ == "__main__":
    main()
