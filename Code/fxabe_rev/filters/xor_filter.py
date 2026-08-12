"""Static three-position XOR membership filter with locator and PStore."""

import hashlib
import math
from collections import deque
from time import perf_counter_ns

from ..encoding import encode
from .base import (
    AnonymousIndex, QueryResult, build_locator, build_pstore, common_size,
    empty_build_stats, empty_query_metrics, finalize_build_stats,
    finalize_query_metrics, open_pstore_profiled, profiled_locator_query,
    validate_entries,
)


def xor_positions(seed, token, m):
    positions = []
    lane = 0
    while len(positions) < 3:
        position = int.from_bytes(hashlib.sha256(encode(
            ["Xor-Filter-v1", seed, token, lane]
        )).digest()[:8], "big") % m
        lane += 1
        if position not in positions:
            positions.append(position)
    return tuple(positions)


class XorIndex(AnonymousIndex):
    name = "Xor+Locator"

    def _fingerprint(self, token):
        bits = int(self.options.get("fingerprint_bits", 16))
        value = int.from_bytes(hashlib.sha256(b"Xor-FP-v1" + token).digest(), "big")
        return (value & ((1 << bits) - 1)) or 1

    @staticmethod
    def _peel(tokens, seed, m):
        edges = {token: xor_positions(seed, token, m) for token in tokens}
        adjacent = [[] for _ in range(m)]
        degree = [0] * m
        for token, edge in edges.items():
            for position in edge:
                adjacent[position].append(token)
                degree[position] += 1
        queue = deque(i for i, degree_i in enumerate(degree) if degree_i == 1)
        removed, stack = set(), []
        while queue:
            pivot = queue.popleft()
            if degree[pivot] != 1:
                continue
            token = next((x for x in adjacent[pivot] if x not in removed), None)
            if token is None:
                continue
            removed.add(token)
            stack.append((token, pivot))
            for position in edges[token]:
                degree[position] -= 1
                if degree[position] == 1:
                    queue.append(position)
        return (stack, edges) if len(stack) == len(tokens) else (None, edges)

    def build(self, token_to_posting_list, context, rng):
        total = perf_counter_ns()
        entries = validate_entries(token_to_posting_list)
        pstore, p_ns = build_pstore(entries, context, rng)
        locator, l_ns = build_locator(pstore, context)
        m = max(3, math.ceil(float(self.options.get("xor_c", 1.30)) * len(entries)))
        attempts = resizes = retry_ns = peel_ns = 0
        max_attempts = int(self.options.get("attempts_before_resize", 8))
        while True:
            seed = rng.getrandbits(128).to_bytes(16, "big")
            attempts += 1
            started = perf_counter_ns()
            stack, edges = self._peel(entries, seed, m)
            elapsed = perf_counter_ns() - started
            peel_ns += elapsed
            if stack is not None:
                break
            retry_ns += elapsed
            if attempts % max_attempts == 0:
                m = max(m + 1, math.ceil(m * 1.10))
                resizes += 1
        started = perf_counter_ns()
        bits = int(self.options.get("fingerprint_bits", 16))
        slots = [rng.getrandbits(bits) for _ in range(m)]
        for token, pivot in reversed(stack):
            p0, p1, p2 = edges[token]
            value = self._fingerprint(token)
            for position in (p0, p1, p2):
                if position != pivot:
                    value ^= slots[position]
            slots[pivot] = value
        assign_ns = perf_counter_ns() - started
        self.state = {
            "slots": slots, "m": m, "seed": seed, "bits": bits,
            "pstore": pstore, "locator": locator,
            "context_digest": pstore["context_digest"],
        }
        self._stats = empty_build_stats()
        self._stats.update({
            "attempt_count": attempts, "resize_count": resizes, "final_capacity": m,
            "peeling_or_insertion_ns": peel_ns, "reverse_assignment_ns": assign_ns,
            "locator_build_ns": l_ns, "pstore_build_ns": p_ns,
            "retry_ns": retry_ns,
        })
        finalize_build_stats(self, self._stats, total)
        return self

    def query(self, token, context):
        started = perf_counter_ns()
        positions = xor_positions(self.state["seed"], token, self.state["m"])
        recovered = 0
        for position in positions:
            recovered ^= self.state["slots"][position]
        candidate = recovered == self._fingerprint(token)
        filter_ns = perf_counter_ns() - started
        metrics = empty_query_metrics()
        metrics["membership_or_retrieval_ns"] = filter_ns
        metrics["filter_candidate_positive_count"] = int(candidate)
        if not candidate:
            return QueryResult(
                False, reason="membership",
                metrics=finalize_query_metrics(metrics),
            )
        metrics["locator_attempt_count"] = 1
        identifier, metrics["locator_lookup_ns"] = profiled_locator_query(
            self.state["locator"], token, context
        )
        if identifier is None:
            return QueryResult(
                False, reason="locator",
                metrics=finalize_query_metrics(metrics),
            )
        rows, p_metrics, attempts = open_pstore_profiled(
            self.state["pstore"], token, identifier, context
        )
        metrics.update(p_metrics)
        metrics["pstore_aead_attempt_count"] = attempts
        metrics["pstore_aead_reject_count"] = int(attempts and rows is None)
        return QueryResult(
            rows is not None, rows or (), "hit" if rows else "aead",
            finalize_query_metrics(metrics),
        )

    def filter_only_size_bytes(self):
        return len(self.state["slots"]) * ((self.state["bits"] + 7) // 8)

    def size_breakdown(self):
        return common_size(self, self.filter_only_size_bytes(), self._metadata())

    def _metadata(self):
        return {"name": self.name, "m": self.state["m"], "bits": self.state["bits"],
                "seed": self.state["seed"]}
