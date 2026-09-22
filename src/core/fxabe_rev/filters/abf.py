"""Bloom membership bitmap plus exact anonymous locator and PStore.

This is deliberately not the repository's legacy greedy XOR ABF. ``ABFIndex``
is retained as an import-compatible class alias only.
"""

import hashlib
import math
from time import perf_counter_ns

from ..encoding import encode
from .base import (
    AnonymousIndex, QueryResult, build_locator, build_pstore, common_size,
    empty_build_stats, empty_query_metrics, finalize_build_stats,
    finalize_query_metrics, open_pstore_profiled, profiled_locator_query,
    validate_entries,
)


class BloomLocatorIndex(AnonymousIndex):
    name = "Bloom+Locator"

    @staticmethod
    def _positions(token, seed, m, k):
        return tuple(int.from_bytes(hashlib.sha256(encode(
            ["ABF-v1", seed, token, lane]
        )).digest()[:8], "big") % m for lane in range(k))

    def build(self, token_to_posting_list, context, rng):
        total = perf_counter_ns()
        entries = validate_entries(token_to_posting_list)
        pstore, p_ns = build_pstore(entries, context, rng)
        locator, l_ns = build_locator(pstore, context)
        bits_per_item = int(self.options.get("abf_bits_per_item", 12))
        k = int(self.options.get("abf_hashes", 8))
        m = max(8, len(entries) * bits_per_item)
        seed = rng.getrandbits(128).to_bytes(16, "big")
        positions_ns = insertion_ns = 0
        bits = bytearray((m + 7) // 8)
        for token in entries:
            started = perf_counter_ns()
            positions = self._positions(token, seed, m, k)
            positions_ns += perf_counter_ns() - started
            started = perf_counter_ns()
            for position in positions:
                bits[position >> 3] |= 1 << (position & 7)
            insertion_ns += perf_counter_ns() - started
        self.state = {
            "bits": bytes(bits), "m": m, "k": k, "seed": seed,
            "pstore": pstore, "locator": locator,
            "context_digest": pstore["context_digest"],
        }
        self._stats = empty_build_stats()
        self._stats.update({
            "final_capacity": m, "position_generation_ns": positions_ns,
            "peeling_or_insertion_ns": insertion_ns, "locator_build_ns": l_ns,
            "pstore_build_ns": p_ns,
        })
        finalize_build_stats(self, self._stats, total)
        return self

    def query(self, token, context):
        started = perf_counter_ns()
        positions = self._positions(token, self.state["seed"], self.state["m"], self.state["k"])
        candidate = all(self.state["bits"][p >> 3] & (1 << (p & 7)) for p in positions)
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
        return len(self.state["bits"])

    def size_breakdown(self):
        return common_size(self, self.filter_only_size_bytes(), self._metadata())

    def _metadata(self):
        return {"name": self.name, "m": self.state["m"], "k": self.state["k"],
                "seed": self.state["seed"]}


# Compatibility for callers written before the baseline audit. The displayed
# and serialized name remains honest: Bloom+Locator.
ABFIndex = BloomLocatorIndex
