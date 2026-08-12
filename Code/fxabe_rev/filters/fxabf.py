"""Binary-Fuse-style segmented three-position FX-ABF retrieval index."""

import hashlib
import json
import math
from collections import deque
from dataclasses import dataclass
from time import perf_counter_ns

from ..crypto_utils import equal
from ..encoding import encode
from .base import (
    AnonymousIndex, QueryResult, build_pstore, common_size, empty_build_stats,
    empty_query_metrics, finalize_build_stats, finalize_query_metrics,
    open_pstore_profiled, plan_pstore, validate_entries,
)

PROFILE = "fxabf-fuse-v2-adaptive"


@dataclass(frozen=True)
class SegmentMeta:
    segment_length: int
    segment_count: int


def plan_segments(m, requested=64):
    """Plan adaptive Binary-Fuse-style segments.

    A fixed 64-slot segment makes the number of local three-segment windows
    grow linearly with ``m`` and caused whole-graph peeling success to collapse.
    The profile therefore uses the Binary-Fuse sizing rule to grow the segment
    length while retaining ``requested`` as a lower bound.
    """
    if m < 3:
        raise ValueError("at least three slots required")
    exponent = math.floor(math.log(max(3, m)) / math.log(3.33) + 2.25)
    adaptive = 1 << max(0, exponent)
    target = max(1, int(requested), adaptive)
    # ceil(m / length) must stay at least three for the three consecutive
    # segment lanes, including tiny test instances.
    length = min(target, max(1, (m - 1) // 2))
    return SegmentMeta(length, math.ceil(m / length))


def _range_hash(seed, token, lane, size):
    if size < 1:
        raise ValueError("empty segment")
    limit = (1 << 64) - ((1 << 64) % size)
    counter = 0
    while True:
        value = int.from_bytes(hashlib.sha256(encode(
            [PROFILE, seed, token, lane, counter]
        )).digest()[:8], "big")
        if value < limit:
            return value % size
        counter += 1


def fuse_positions(seed, token, m, meta):
    """Three reads in consecutive, pairwise-distinct continuous segments."""
    if not isinstance(seed, bytes) or not isinstance(token, bytes):
        raise TypeError("seed and token must be bytes")
    if meta.segment_count < 3 or meta.segment_length < 1:
        raise ValueError("malformed segment metadata")
    if plan_segments(m, meta.segment_length) != meta:
        raise ValueError("segment metadata does not match the profile")
    base_choices = meta.segment_count - 2
    base = _range_hash(seed, token, 0, base_choices)
    result = []
    for lane, segment in enumerate((base, base + 1, base + 2)):
        start = segment * meta.segment_length
        end = min(m, start + meta.segment_length)
        result.append(start + _range_hash(seed, token, lane + 1, end - start))
    if len(set(result)) != 3:
        raise ValueError("positions are not distinct")
    return tuple(result)


class FXABFIndex(AnonymousIndex):
    name = "FX-ABF"

    @staticmethod
    def _build_attempt(tokens, seed, m, meta):
        """Build and peel one hypergraph in O(u+m) time.

        ``xor_edge`` identifies the sole remaining incident edge when a slot
        reaches degree one, avoiding adjacency-list scans and a removed set.
        """
        position_started = perf_counter_ns()
        edges = []
        degree = [0] * m
        xor_edge = [0] * m
        occupancy = [0] * meta.segment_count
        collision_count = 0
        for edge_id, token in enumerate(tokens):
            edge = fuse_positions(seed, token, m, meta)
            edges.append(edge)
            collision_count += 3 - len(set(edge))
            for position in edge:
                degree[position] += 1
                xor_edge[position] ^= edge_id
                occupancy[position // meta.segment_length] += 1
        position_ns = perf_counter_ns() - position_started
        degree_counts = {
            "degree_0_count": sum(value == 0 for value in degree),
            "degree_1_count": sum(value == 1 for value in degree),
            "degree_2_count": sum(value == 2 for value in degree),
            "degree_3plus_count": sum(value >= 3 for value in degree),
        }
        peeling_started = perf_counter_ns()
        queue = deque(i for i, value in enumerate(degree) if value == 1)
        stack = []
        while queue:
            pivot = queue.popleft()
            if degree[pivot] != 1:
                continue
            edge_id = xor_edge[pivot]
            stack.append((edge_id, pivot))
            for position in edges[edge_id]:
                degree[position] -= 1
                xor_edge[position] ^= edge_id
                if degree[position] == 1:
                    queue.append(position)
        peeling_ns = perf_counter_ns() - peeling_started
        mean = sum(occupancy) / float(len(occupancy))
        variance = sum((value - mean) ** 2 for value in occupancy) / len(occupancy)
        return stack, edges, {
            "peeled_edges": len(stack),
            "remaining_core_edges": len(tokens) - len(stack),
            "position_generation_ns": position_ns,
            "peeling_ns": peeling_ns,
            "segment_occupancy": occupancy,
            "min_segment_occupancy": min(occupancy),
            "max_segment_occupancy": max(occupancy),
            "occupancy_cv": math.sqrt(variance) / mean if mean else 0.0,
            "three_position_collision_count": collision_count,
            **degree_counts,
        }

    def _check_int(self, token, identifier, context, b_j, delta):
        digest = hashlib.sha256(encode([
            "FXABF-Check", context, token, {"bits": b_j, "value": identifier},
        ])).digest()
        return int.from_bytes(digest, "big") >> (256 - delta)

    def build(self, token_to_posting_list, context, rng):
        total = perf_counter_ns()
        started = perf_counter_ns()
        entries = validate_entries(token_to_posting_list)
        validation_ns = perf_counter_ns() - started
        started = perf_counter_ns()
        layout = plan_pstore(entries, rng)
        layout_ns = perf_counter_ns() - started
        u = len(entries)
        b_j = max(1, math.ceil(math.log2(u))) if u > 1 else 1
        delta = int(self.options.get("delta", 64))
        payload_bits = b_j + delta
        started = perf_counter_ns()
        payloads = {
            token: (identifier << delta) |
                   self._check_int(token, identifier, context, b_j, delta)
            for token, identifier in layout["ids"].items()
        }
        payload_ns = perf_counter_ns() - started
        tokens = tuple(payloads)
        m = max(3, math.ceil(float(self.options.get("c_fx", 1.30)) * u))
        max_attempts = int(self.options.get(
            "r_max", self.options.get("attempts_before_resize", 8)
        ))
        growth = float(self.options.get(
            "gamma", self.options.get("growth", 1.08)
        ))
        attempts = resizes = retry_ns = peel_ns = position_ns = 0
        attempt_details = []
        while True:
            seed = rng.getrandbits(128).to_bytes(16, "big")
            meta = plan_segments(m, int(self.options.get("segment_length", 64)))
            attempts += 1
            stack, edges, attempt = self._build_attempt(tokens, seed, m, meta)
            position_ns += attempt["position_generation_ns"]
            peel_ns += attempt["peeling_ns"]
            success = len(stack) == u
            attempt_total_ns = (
                attempt["position_generation_ns"] + attempt["peeling_ns"]
            )
            attempt_details.append({
                "u": u, "seed": seed.hex(), "attempt_index": attempts,
                "array_capacity": m, "load_factor": u / float(m),
                "segment_length": meta.segment_length,
                "segment_count": meta.segment_count,
                "tail_segment_length":
                    m - (meta.segment_count - 1) * meta.segment_length,
                "peeled_edges": attempt["peeled_edges"],
                "remaining_core_edges": attempt["remaining_core_edges"],
                "position_generation_ms":
                    attempt["position_generation_ns"] / 1_000_000.0,
                "peeling_ms": attempt["peeling_ns"] / 1_000_000.0,
                "assignment_ms": 0.0,
                "attempt_total_ms": attempt_total_ns / 1_000_000.0,
                "attempt_success": success,
                "segment_occupancy_json":
                    json.dumps(
                        attempt["segment_occupancy"], separators=(",", ":")),
                "min_segment_occupancy": attempt["min_segment_occupancy"],
                "max_segment_occupancy": attempt["max_segment_occupancy"],
                "occupancy_cv": attempt["occupancy_cv"],
                "three_position_collision_count":
                    attempt["three_position_collision_count"],
                "degree_0_count": attempt["degree_0_count"],
                "degree_1_count": attempt["degree_1_count"],
                "degree_2_count": attempt["degree_2_count"],
                "degree_3plus_count": attempt["degree_3plus_count"],
            })
            if success:
                break
            retry_ns += attempt_total_ns
            if attempts % max_attempts == 0:
                m = max(m + 1, math.ceil(m * growth))
                resizes += 1
        started = perf_counter_ns()
        slots = [rng.getrandbits(payload_bits) for _ in range(m)]
        for edge_id, pivot in reversed(stack):
            token = tokens[edge_id]
            value = payloads[token]
            for position in edges[edge_id]:
                if position != pivot:
                    value ^= slots[position]
            slots[pivot] = value
        assignment_ns = perf_counter_ns() - started
        attempt_details[-1]["assignment_ms"] = assignment_ns / 1_000_000.0
        attempt_details[-1]["attempt_total_ms"] += assignment_ns / 1_000_000.0
        pstore_build_count = 0
        pstore, p_ns = build_pstore(
            entries, context, rng, layout=layout, fx_seed=seed
        )
        pstore_build_count += 1
        assert pstore_build_count == 1
        self.state = {
            "slots": slots, "m": m, "seed": seed, "segment_meta": meta,
            "payload_bits": payload_bits, "b_j": b_j, "delta": delta,
            "pstore": pstore, "context_digest": pstore["context_digest"],
        }
        build_total_ns = perf_counter_ns() - total
        component_sum_ns = (
            validation_ns + layout_ns + payload_ns + position_ns + peel_ns +
            assignment_ns + p_ns
        )
        stats = empty_build_stats()
        stats.update({
            "attempt_count": attempts, "failed_attempt_count": attempts - 1,
            "resize_count": resizes, "final_capacity": m,
            "position_generation_ns": position_ns,
            "peeling_or_insertion_ns": peel_ns,
            "reverse_assignment_ns": assignment_ns,
            "pstore_build_ns": p_ns, "retry_ns": retry_ns,
            "pstore_build_count": pstore_build_count,
            "validation_ns": validation_ns, "layout_ns": layout_ns,
            "payload_ns": payload_ns, "component_sum_ns": component_sum_ns,
            "timing_residual_ns": build_total_ns - component_sum_ns,
            "build_total_ns": build_total_ns, "attempts": attempt_details,
        })
        finalize_build_stats(self, stats, total)
        stats["component_sum_ns"] += stats["metadata_build_ns"]
        stats["timing_residual_ns"] = (
            stats["build_total_ns"] - stats["component_sum_ns"]
        )
        self._stats = stats
        return self

    def query(self, token, context):
        started = perf_counter_ns()
        metrics = empty_query_metrics()
        try:
            if hashlib.sha256(context).digest() != self.state["context_digest"]:
                metrics["membership_or_retrieval_ns"] = (
                    perf_counter_ns() - started
                )
                return QueryResult(
                    False, reason="context",
                    metrics=finalize_query_metrics(metrics),
                )
            meta = self.state["segment_meta"]
            positions = fuse_positions(
                self.state["seed"], token, self.state["m"], meta
            )
            recovered = 0
            for position in positions:
                recovered ^= self.state["slots"][position]
            identifier = recovered >> self.state["delta"]
            recovered_check = recovered & ((1 << self.state["delta"]) - 1)
            if identifier >= self.state["pstore"]["u"]:
                metrics["membership_or_retrieval_ns"] = (
                    perf_counter_ns() - started
                )
                return QueryResult(
                    False, reason="range",
                    metrics=finalize_query_metrics(metrics),
                )
            expected = self._check_int(
                token, identifier, context, self.state["b_j"], self.state["delta"]
            )
            if not equal(
                recovered_check.to_bytes((self.state["delta"] + 7) // 8, "big"),
                expected.to_bytes((self.state["delta"] + 7) // 8, "big"),
            ):
                metrics["membership_or_retrieval_ns"] = (
                    perf_counter_ns() - started
                )
                return QueryResult(
                    False, reason="short-check",
                    metrics=finalize_query_metrics(metrics),
                )
            metrics["membership_or_retrieval_ns"] = perf_counter_ns() - started
            metrics["filter_candidate_positive_count"] = 1
            rows, p_metrics, attempts = open_pstore_profiled(
                self.state["pstore"], token, identifier, context
            )
            metrics.update(p_metrics)
            metrics["pstore_aead_attempt_count"] = attempts
            metrics["pstore_aead_reject_count"] = int(
                attempts and rows is None
            )
            return QueryResult(
                rows is not None, rows or (), "hit" if rows else "aead",
                finalize_query_metrics(metrics),
            )
        except Exception:
            metrics["membership_or_retrieval_ns"] = (
                perf_counter_ns() - started
            )
            return QueryResult(
                False, reason="malformed",
                metrics=finalize_query_metrics(metrics),
            )

    def filter_only_size_bytes(self):
        return len(self.state["slots"]) * ((self.state["payload_bits"] + 7) // 8)

    def size_breakdown(self):
        return common_size(self, self.filter_only_size_bytes(), self._metadata())

    def _metadata(self):
        meta = self.state["segment_meta"]
        return {
            "name": self.name, "profile": PROFILE, "m": self.state["m"],
            "seed": self.state["seed"], "segment_length": meta.segment_length,
            "segment_count": meta.segment_count, "b_j": self.state["b_j"],
            "delta": self.state["delta"],
        }

    # Document-spelling aliases.
    Build = build
    Query = query
