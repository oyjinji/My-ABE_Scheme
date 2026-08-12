"""Adapter for the repository's legacy greedy XOR retrieval ABF.

The construction follows ``fx_exp/filters/original_abf.py``: each token hashes
to three distinct slots, one still-free slot is reserved, and XOR assignment
stores a value/pointer plus a short check.  The adapter replaces the legacy
standalone PStore encoding with the same authenticated PStore used by every
other v2 index.  It does not add an exact locator.
"""

import hashlib
import math
from time import perf_counter_ns

from ..crypto_utils import equal
from ..encoding import encode
from .base import (
    AnonymousIndex, QueryResult, build_pstore, common_size, empty_build_stats,
    empty_query_metrics, finalize_build_stats, finalize_query_metrics,
    open_pstore_profiled, plan_pstore, validate_entries,
)


def legacy_positions(seed, token, m, k=3):
    """Preserve the old (seed, hash-index, token, counter) position domain."""
    positions = []
    for hash_index in range(k):
        counter = 0
        while True:
            digest = hashlib.sha256(encode([
                "ABE-H-seed", seed, hash_index, token, counter,
            ])).digest()
            position = int.from_bytes(digest, "big") % m
            counter += 1
            if position not in positions:
                positions.append(position)
                break
    return tuple(positions)


class LegacyABFIndex(AnonymousIndex):
    """Greedy XOR retrieval ABF with direct PStore pointer recovery."""

    name = "Legacy ABF"

    def _check_int(self, token, identifier, context, delta):
        digest = hashlib.sha256(encode([
            "Legacy-ABF-Check", context, token, identifier,
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
        delta = int(self.options.get("delta", 64))
        b_j = max(1, math.ceil(math.log2(u))) if u > 1 else 1
        payload_bits = b_j + delta
        started = perf_counter_ns()
        payloads = {
            token: (
                identifier << delta
            ) | self._check_int(token, identifier, context, delta)
            for token, identifier in layout["ids"].items()
        }
        payload_ns = perf_counter_ns() - started
        ordered = tuple(sorted(entries))
        k = int(self.options.get("legacy_k", 3))
        m = max(k, math.ceil(
            float(self.options.get("legacy_c", 2.0)) * u
        ))
        r_max = int(self.options.get("legacy_r_max", 8))
        gamma = float(self.options.get("legacy_gamma", 1.10))
        attempts = resizes = retry_ns = position_ns = insertion_ns = 0
        while True:
            seed = rng.getrandbits(128).to_bytes(16, "big")
            attempts += 1
            slots = [None] * m
            failed = False
            attempt_started = perf_counter_ns()
            for token in ordered:
                started = perf_counter_ns()
                positions = legacy_positions(seed, token, m, k)
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
                value = payloads[token]
                for position in positions:
                    if position == pivot:
                        continue
                    if slots[position] is None:
                        slots[position] = rng.getrandbits(payload_bits)
                    value ^= slots[position]
                slots[pivot] = value
                insertion_ns += perf_counter_ns() - started
            attempt_ns = perf_counter_ns() - attempt_started
            if not failed:
                break
            retry_ns += attempt_ns
            if attempts % r_max == 0:
                m = max(m + 1, math.ceil(gamma * m))
                resizes += 1
        started = perf_counter_ns()
        slots = [
            slot if slot is not None else rng.getrandbits(payload_bits)
            for slot in slots
        ]
        assignment_ns = perf_counter_ns() - started
        pstore_build_count = 0
        pstore, pstore_ns = build_pstore(
            entries, context, rng, layout=layout, fx_seed=seed
        )
        pstore_build_count += 1
        assert pstore_build_count == 1
        self.state = {
            "slots": slots, "m": m, "k": k, "seed": seed,
            "delta": delta, "b_j": b_j, "payload_bits": payload_bits,
            "pstore": pstore, "context_digest": pstore["context_digest"],
        }
        stats = empty_build_stats()
        stats.update({
            "attempt_count": attempts,
            "failed_attempt_count": attempts - 1,
            "resize_count": resizes,
            "final_capacity": m,
            "position_generation_ns": position_ns,
            "peeling_or_insertion_ns": insertion_ns,
            "reverse_assignment_ns": assignment_ns,
            "pstore_build_ns": pstore_ns,
            "pstore_build_count": pstore_build_count,
            "retry_ns": retry_ns,
            "validation_ns": validation_ns,
            "layout_ns": layout_ns,
            "payload_ns": payload_ns,
        })
        finalize_build_stats(self, stats, total)
        self._stats = stats
        return self

    def query(self, token, context):
        started = perf_counter_ns()
        metrics = empty_query_metrics()
        try:
            if hashlib.sha256(context).digest() != self.state["context_digest"]:
                raise ValueError("context")
            recovered = 0
            for position in legacy_positions(
                    self.state["seed"], token, self.state["m"], self.state["k"]):
                recovered ^= self.state["slots"][position]
            identifier = recovered >> self.state["delta"]
            check = recovered & ((1 << self.state["delta"]) - 1)
            if identifier >= self.state["pstore"]["u"]:
                metrics["membership_or_retrieval_ns"] = (
                    perf_counter_ns() - started
                )
                return QueryResult(
                    False, reason="range",
                    metrics=finalize_query_metrics(metrics),
                )
            expected = self._check_int(
                token, identifier, context, self.state["delta"]
            )
            width = (self.state["delta"] + 7) // 8
            if not equal(check.to_bytes(width, "big"),
                         expected.to_bytes(width, "big")):
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
        width = (self.state["payload_bits"] + 7) // 8
        return len(self.state["slots"]) * width

    def size_breakdown(self):
        return common_size(self, self.filter_only_size_bytes(), self._metadata())

    def _metadata(self):
        return {
            "name": self.name,
            "construction": "legacy-greedy-xor-retrieval",
            "m": self.state["m"],
            "k": self.state["k"],
            "seed": self.state["seed"],
            "delta": self.state["delta"],
            "b_j": self.state["b_j"],
        }

