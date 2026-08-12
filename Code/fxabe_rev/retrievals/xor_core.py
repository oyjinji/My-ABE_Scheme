"""Peelable XOR static-function core shared by plain, Bloomier and FX layouts."""

import math
import struct
from collections import deque
from time import perf_counter_ns

from .base import (
    BuildFailure, RetrievalResult, StaticRetrieval, random_bytes,
    validate_value,
)


class PeelableXorRetrieval(StaticRetrieval):
    load_factor_target = 1.30
    attempts_before_resize = 8
    growth = 1.08
    max_resizes = 16
    query_hashes = 3

    def _capacity(self, u):
        return max(self.query_hashes, math.ceil(self.load_factor_target * u))

    def _prepare_layout(self, capacity):
        return None

    def _layout_metadata(self):
        return {}

    def _restore_layout(self, metadata):
        return None

    def build(self, mapping, rng=None):
        total_started = perf_counter_ns()
        rng = self._rng(rng)
        items, u, b_j, width = self._validate_mapping(mapping)
        tokens = tuple(token for token, _ in items)
        values = tuple(int.from_bytes(value, "big") for _, value in items)
        capacity = self._capacity(u)
        attempt_count = resize_count = position_ns = peel_ns = 0
        assignment_ns = 0
        while resize_count <= self.max_resizes:
            self._prepare_layout(capacity)
            for _ in range(self.attempts_before_resize):
                attempt_count += 1
                seed = rng.getrandbits(128).to_bytes(16, "big")
                started = perf_counter_ns()
                edges = []
                degree = [0] * capacity
                xor_edge = [0] * capacity
                for edge_id, token in enumerate(tokens):
                    edge = self._positions(seed, token, capacity)
                    edges.append(edge)
                    for position in edge:
                        degree[position] += 1
                        xor_edge[position] ^= edge_id
                position_ns += perf_counter_ns() - started

                started = perf_counter_ns()
                queue = deque(
                    index for index, value in enumerate(degree) if value == 1
                )
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
                peel_ns += perf_counter_ns() - started
                if len(stack) != u:
                    continue

                started = perf_counter_ns()
                payload_bits = width * 8
                slots = [rng.getrandbits(payload_bits) for _ in range(capacity)]
                for edge_id, pivot in reversed(stack):
                    value = values[edge_id]
                    for position in edges[edge_id]:
                        if position != pivot:
                            value ^= slots[position]
                    slots[pivot] = value
                assignment_ns = perf_counter_ns() - started
                self.u = u
                self.b_j = b_j
                self.value_width = width
                self.capacity = capacity
                self.seed = seed
                self.slots = slots
                self._stats = {
                    "success": True,
                    "build_total_ns": perf_counter_ns() - total_started,
                    "position_hash_ns": position_ns,
                    "peeling_or_insertion_ns": peel_ns,
                    "assignment_ns": assignment_ns,
                    "attempt_count": attempt_count,
                    "resize_count": resize_count,
                    "final_capacity": capacity,
                    "load_factor": u / float(capacity),
                    "kick_count": 0,
                }
                return self
            resize_count += 1
            capacity = max(capacity + 1, math.ceil(capacity * self.growth))
        stats = {
            "success": False,
            "build_total_ns": perf_counter_ns() - total_started,
            "position_hash_ns": position_ns,
            "peeling_or_insertion_ns": peel_ns,
            "assignment_ns": 0,
            "attempt_count": attempt_count,
            "resize_count": resize_count,
            "final_capacity": capacity,
            "load_factor": u / float(capacity),
            "kick_count": 0,
        }
        raise BuildFailure("peeling failed after all resizes", stats)

    def query(self, token):
        started = perf_counter_ns()
        positions = self._positions(self.seed, token, self.capacity)
        recovered = 0
        for position in positions:
            recovered ^= self.slots[position]
        value = recovered.to_bytes(self.value_width, "big")
        hit = validate_value(token, value, self.b_j, self.delta)
        elapsed = perf_counter_ns() - started
        return RetrievalResult(
            hit, value if hit else b"", "hit" if hit else "check",
            {
                "query_ns": elapsed,
                "hash_count": self.query_hashes + 1,
                "array_reads": len(positions),
                "xor_count": len(positions),
                "temporary_allocations": self.query_hashes * 2 + 5,
            },
        )

    def _functional_metadata(self):
        return {
            **super()._functional_metadata(),
            "capacity": self.capacity,
            "seed": self.seed.hex(),
            **self._layout_metadata(),
        }

    def _structure_bytes(self):
        return b"".join(
            value.to_bytes(self.value_width, "big") for value in self.slots
        )

    def _load_structure_bytes(self, metadata, body):
        self.capacity = int(metadata["capacity"])
        self.seed = bytes.fromhex(metadata["seed"])
        expected = self.capacity * self.value_width
        if len(body) != expected:
            raise ValueError("malformed XOR retrieval slot array")
        self.slots = [
            int.from_bytes(
                body[offset:offset + self.value_width], "big"
            )
            for offset in range(0, len(body), self.value_width)
        ]
        self._restore_layout(metadata)

    def space_stats(self):
        sizes = self.size_breakdown()
        return {
            **sizes,
            "bytes_per_key": sizes["serialized_bytes"] / float(self.u),
            "payload_bits_per_key": self.b_j + self.delta,
            "unused_capacity_bytes": (
                (self.capacity - self.u) * self.value_width
            ),
        }
