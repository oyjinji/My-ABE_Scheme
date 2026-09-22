"""Greedy three-position legacy ABF retrieval without PStore or locator."""

import math
from time import perf_counter_ns

from .base import (
    BuildFailure, RetrievalResult, StaticRetrieval, sha256_domain,
    validate_value,
)


class LegacyABFRetrieval(StaticRetrieval):
    name = "Legacy ABF retrieval"
    type_id = "legacy-greedy-xor-retrieval-v1"

    def __init__(self, delta=64, c=2.0, attempts_before_resize=8,
                 growth=1.10, max_resizes=16, **options):
        super().__init__(delta=delta, **options)
        self.c = float(c)
        self.attempts_before_resize = int(attempts_before_resize)
        self.growth = float(growth)
        self.max_resizes = int(max_resizes)

    @staticmethod
    def _positions(seed, token, capacity):
        positions = []
        for lane in range(3):
            counter = 0
            while True:
                digest = sha256_domain(
                    "Legacy-ABF-Position-v1", seed, token, lane, counter
                )
                position = int.from_bytes(digest[:8], "big") % capacity
                if position not in positions:
                    positions.append(position)
                    break
                counter += 1
        return tuple(positions)

    def build(self, mapping, rng=None):
        total_started = perf_counter_ns()
        rng = self._rng(rng)
        items, u, b_j, width = self._validate_mapping(mapping)
        # Preserve the legacy deterministic key order, but never retain it.
        items = tuple(sorted(items))
        capacity = max(3, math.ceil(self.c * u))
        attempts = resizes = position_ns = insertion_ns = 0
        while resizes <= self.max_resizes:
            for _ in range(self.attempts_before_resize):
                attempts += 1
                seed = rng.getrandbits(128).to_bytes(16, "big")
                slots = [None] * capacity
                failed = False
                for token, value_bytes in items:
                    started = perf_counter_ns()
                    positions = self._positions(seed, token, capacity)
                    position_ns += perf_counter_ns() - started
                    started = perf_counter_ns()
                    free = [
                        position for position in positions
                        if slots[position] is None
                    ]
                    if not free:
                        insertion_ns += perf_counter_ns() - started
                        failed = True
                        break
                    pivot = free[-1]
                    value = int.from_bytes(value_bytes, "big")
                    for position in positions:
                        if position == pivot:
                            continue
                        if slots[position] is None:
                            slots[position] = rng.getrandbits(width * 8)
                        value ^= slots[position]
                    slots[pivot] = value
                    insertion_ns += perf_counter_ns() - started
                if failed:
                    continue
                started = perf_counter_ns()
                slots = [
                    value if value is not None else rng.getrandbits(width * 8)
                    for value in slots
                ]
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
                    "peeling_or_insertion_ns": insertion_ns,
                    "assignment_ns": assignment_ns,
                    "attempt_count": attempts,
                    "resize_count": resizes,
                    "final_capacity": capacity,
                    "load_factor": u / float(capacity),
                    "kick_count": 0,
                }
                return self
            resizes += 1
            capacity = max(capacity + 1, math.ceil(capacity * self.growth))
        stats = {
            "success": False,
            "build_total_ns": perf_counter_ns() - total_started,
            "position_hash_ns": position_ns,
            "peeling_or_insertion_ns": insertion_ns,
            "assignment_ns": 0,
            "attempt_count": attempts,
            "resize_count": resizes,
            "final_capacity": capacity,
            "load_factor": u / float(capacity),
            "kick_count": 0,
        }
        raise BuildFailure("legacy greedy insertion failed", stats)

    def query(self, token):
        started = perf_counter_ns()
        recovered = 0
        positions = self._positions(self.seed, token, self.capacity)
        for position in positions:
            recovered ^= self.slots[position]
        value = recovered.to_bytes(self.value_width, "big")
        hit = validate_value(token, value, self.b_j, self.delta)
        return RetrievalResult(
            hit, value if hit else b"", "hit" if hit else "check",
            {
                "query_ns": perf_counter_ns() - started,
                "hash_count": 4,
                "array_reads": 3,
                "xor_count": 3,
                "temporary_allocations": 11,
            },
        )

    def _functional_metadata(self):
        return {
            **super()._functional_metadata(),
            "capacity": self.capacity,
            "seed": self.seed.hex(),
            "c": self.c,
        }

    def _structure_bytes(self):
        return b"".join(
            value.to_bytes(self.value_width, "big") for value in self.slots
        )

    def _load_structure_bytes(self, metadata, body):
        self.capacity = int(metadata["capacity"])
        self.seed = bytes.fromhex(metadata["seed"])
        self.c = float(metadata["c"])
        expected = self.capacity * self.value_width
        if len(body) != expected:
            raise ValueError("malformed legacy slot array")
        self.slots = [
            int.from_bytes(body[offset:offset + self.value_width], "big")
            for offset in range(0, len(body), self.value_width)
        ]

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
