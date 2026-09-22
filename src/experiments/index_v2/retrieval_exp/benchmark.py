"""R1-R4 benchmark using only the static retrieval structures."""

import hashlib
import random
import statistics
from time import perf_counter_ns

from core.fxabe_rev.retrievals import (
    BuildFailure, create_retrieval, deserialize_retrieval, make_value,
)
from experiments.index_v2.benchmarks.common import derive_seed, write_csv


RAW_FIELDS = [
    "retrieval_name", "u", "seed_index", "workload_id", "master_seed",
    "workload_seed", "build_seed", "success", "build_failure",
    "build_total_ms", "position_hash_ms", "peeling_or_insertion_ms",
    "assignment_ms", "attempt_count", "resize_count", "kick_count",
    "final_capacity", "load_factor", "success_rate",
    "query_count", "warmup_batches", "measured_batches",
    "member_query_ns", "nonmember_query_ns", "mixed_query_ns",
    "hash_count", "array_reads", "xor_count", "temporary_allocations",
    "structure_bytes", "metadata_bytes", "serialized_bytes",
    "bytes_per_key", "payload_bits_per_key", "unused_capacity_bytes",
    "member_false_negative", "nonmember_false_accept",
    "deserialize_query_correctness", "mapping_retained",
    "contains_locator", "contains_pstore",
]


def make_workload(master_seed, u, seed_index, delta):
    workload_seed = derive_seed(
        master_seed, "retrieval-workload", u, seed_index
    )
    tokens = [
        hashlib.sha256(
            ("retrieval-member|%d|%d" % (workload_seed, i)).encode()
        ).digest()
        for i in range(u)
    ]
    b_j = max(1, (u - 1).bit_length())
    mapping = {
        token: make_value(token, identifier, b_j, delta)
        for identifier, token in enumerate(tokens)
    }
    return workload_seed, tokens, mapping


def _nonmembers(workload_seed, count):
    return [
        hashlib.sha256(
            ("retrieval-nonmember|%d|%d" % (workload_seed, i)).encode()
        ).digest()
        for i in range(count)
    ]


def _median_per_query(retrieval, queries, batches, collect_counts=False):
    samples = []
    totals = {
        "hash_count": 0, "array_reads": 0, "xor_count": 0,
        "temporary_allocations": 0,
    }
    result_cache = None
    for batch in range(batches):
        started = perf_counter_ns()
        current = [retrieval.query(token) for token in queries]
        samples.append((perf_counter_ns() - started) / float(len(queries)))
        if collect_counts and batch == 0:
            result_cache = current
            for result in current:
                for field in totals:
                    totals[field] += int(result.metrics[field])
    if collect_counts:
        for field in totals:
            totals[field] /= float(len(queries))
    return statistics.median(samples), totals, result_cache


def _retains_mapping(retrieval, token_set):
    seen = set()

    def visit(value):
        marker = id(value)
        if marker in seen:
            return False
        seen.add(marker)
        if isinstance(value, dict):
            if any(
                isinstance(key, bytes) and key in token_set for key in value
            ):
                return True
            return any(visit(item) for item in value.values())
        if isinstance(value, (list, tuple)):
            return any(visit(item) for item in value)
        return False

    return visit(retrieval.__dict__)


def run(config, raw_path):
    master = int(config["master_seed"])
    delta = int(config["delta"])
    query_count = int(config["query_count"])
    member_count = query_count // 2
    nonmember_count = query_count - member_count
    raw = []
    for u in map(int, config["u"]):
        for seed_index in range(int(config["independent_seeds"])):
            workload_seed, tokens, mapping = make_workload(
                master, u, seed_index, delta
            )
            members = [
                tokens[i % len(tokens)] for i in range(member_count)
            ]
            nonmembers = _nonmembers(workload_seed, nonmember_count)
            mixed = []
            for member, nonmember in zip(members, nonmembers):
                mixed.extend((member, nonmember))
            mixed.extend(members[len(nonmembers):])
            mixed.extend(nonmembers[len(members):])
            workload_id = "retrieval-u%d-seed%02d-%016x" % (
                u, seed_index, workload_seed
            )
            build_seed = derive_seed(master, "retrieval-build", u, seed_index)
            for name in config["retrievals"]:
                retrieval = create_retrieval(name, delta=delta)
                try:
                    retrieval.build(mapping, random.Random(build_seed))
                    stats = retrieval.stats()
                    success = True
                    failure = ""
                except BuildFailure as exc:
                    stats = exc.stats
                    success = False
                    failure = str(exc)
                if not success:
                    raw.append(_failure_row(
                        name, u, seed_index, workload_id, master,
                        workload_seed, build_seed, query_count, config,
                        stats, failure,
                    ))
                    continue

                for _ in range(int(config["warmup_batches"])):
                    for token in mixed:
                        retrieval.query(token)

                member_ns, _, member_results = _median_per_query(
                    retrieval, members, int(config["measured_batches"]), True
                )
                nonmember_ns, _, nonmember_results = _median_per_query(
                    retrieval, nonmembers, int(config["measured_batches"]), True
                )
                mixed_ns, operation_counts, _ = _median_per_query(
                    retrieval, mixed, int(config["measured_batches"]), True
                )
                false_negatives = sum(
                    not result.hit or result.value != mapping[token]
                    for token, result in zip(members, member_results)
                )
                false_accepts = sum(
                    result.hit for result in nonmember_results
                )
                serialized = retrieval.serialize()
                restored = deserialize_retrieval(serialized)
                deserialize_ok = all(
                    restored.query(token).hit
                    and restored.query(token).value == mapping[token]
                    for token in tokens
                ) and all(
                    not restored.query(token).hit for token in nonmembers
                )
                space = retrieval.space_stats()
                raw.append({
                    "retrieval_name": name, "u": u,
                    "seed_index": seed_index, "workload_id": workload_id,
                    "master_seed": master, "workload_seed": workload_seed,
                    "build_seed": build_seed, "success": True,
                    "build_failure": "",
                    "build_total_ms": stats["build_total_ns"] / 1e6,
                    "position_hash_ms": stats["position_hash_ns"] / 1e6,
                    "peeling_or_insertion_ms":
                        stats["peeling_or_insertion_ns"] / 1e6,
                    "assignment_ms": stats["assignment_ns"] / 1e6,
                    "attempt_count": stats["attempt_count"],
                    "resize_count": stats["resize_count"],
                    "kick_count": stats["kick_count"],
                    "final_capacity": stats["final_capacity"],
                    "load_factor": stats["load_factor"],
                    "success_rate": 1,
                    "query_count": query_count,
                    "warmup_batches": int(config["warmup_batches"]),
                    "measured_batches": int(config["measured_batches"]),
                    "member_query_ns": member_ns,
                    "nonmember_query_ns": nonmember_ns,
                    "mixed_query_ns": mixed_ns,
                    **operation_counts,
                    **space,
                    "member_false_negative": false_negatives,
                    "nonmember_false_accept": false_accepts,
                    "deserialize_query_correctness": bool(deserialize_ok),
                    "mapping_retained": _retains_mapping(
                        retrieval, set(mapping)
                    ),
                    "contains_locator": hasattr(retrieval, "locator"),
                    "contains_pstore": hasattr(retrieval, "pstore"),
                })
    write_csv(raw_path, raw, RAW_FIELDS)
    return raw


def _failure_row(name, u, seed_index, workload_id, master, workload_seed,
                 build_seed, query_count, config, stats, failure):
    return {
        "retrieval_name": name, "u": u, "seed_index": seed_index,
        "workload_id": workload_id, "master_seed": master,
        "workload_seed": workload_seed, "build_seed": build_seed,
        "success": False, "build_failure": failure,
        "build_total_ms": stats["build_total_ns"] / 1e6,
        "position_hash_ms": stats["position_hash_ns"] / 1e6,
        "peeling_or_insertion_ms":
            stats["peeling_or_insertion_ns"] / 1e6,
        "assignment_ms": stats["assignment_ns"] / 1e6,
        "attempt_count": stats["attempt_count"],
        "resize_count": stats["resize_count"],
        "kick_count": stats["kick_count"],
        "final_capacity": stats["final_capacity"],
        "load_factor": stats["load_factor"], "success_rate": 0,
        "query_count": query_count,
        "warmup_batches": int(config["warmup_batches"]),
        "measured_batches": int(config["measured_batches"]),
        "member_query_ns": 0, "nonmember_query_ns": 0,
        "mixed_query_ns": 0, "hash_count": 0, "array_reads": 0,
        "xor_count": 0, "temporary_allocations": 0,
        "structure_bytes": 0, "metadata_bytes": 0,
        "serialized_bytes": 0, "bytes_per_key": 0,
        "payload_bits_per_key": 0, "unused_capacity_bytes": 0,
        "member_false_negative": 0, "nonmember_false_accept": 0,
        "deserialize_query_correctness": False,
        "mapping_retained": False, "contains_locator": False,
        "contains_pstore": False,
    }
