"""Standard two-bucket cuckoo filter plus exact locator and encrypted PStore."""

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


class CuckooIndex(AnonymousIndex):
    name = "Cuckoo+Locator"

    def _fp(self, token):
        bits = int(self.options.get("fingerprint_bits", 16))
        width = (bits + 7) // 8
        value = int.from_bytes(hashlib.sha256(b"Cuckoo-FP-v1" + token).digest(), "big")
        value &= (1 << bits) - 1
        return (value or 1).to_bytes(width, "big")

    @staticmethod
    def _buckets(token, fp, seed, count):
        if count < 2 or count & (count - 1):
            raise ValueError("cuckoo bucket count must be a power of two")
        mask = count - 1
        first = int.from_bytes(hashlib.sha256(encode(
            ["Cuckoo-I1-v1", seed, token]
        )).digest()[:8], "big") & mask
        delta = int.from_bytes(hashlib.sha256(b"Cuckoo-I2-v1" + fp).digest()[:8], "big")
        return first, first ^ (delta & mask)

    def _try_build(self, tokens, count, seed, rng):
        bucket_size = int(self.options.get("bucket_size", 4))
        max_kicks = int(self.options.get("max_kicks", 500))
        buckets = [[] for _ in range(count)]
        for token in tokens:
            fp = self._fp(token)
            i1, i2 = self._buckets(token, fp, seed, count)
            target = i1 if len(buckets[i1]) < bucket_size else i2
            if len(buckets[target]) < bucket_size:
                buckets[target].append(fp)
                continue
            current, index = fp, (i1 if rng.randrange(2) == 0 else i2)
            for _ in range(max_kicks):
                slot = rng.randrange(bucket_size)
                buckets[index][slot], current = current, buckets[index][slot]
                delta = int.from_bytes(hashlib.sha256(
                    b"Cuckoo-I2-v1" + current).digest()[:8], "big")
                index = index ^ (delta & (count - 1))
                if len(buckets[index]) < bucket_size:
                    buckets[index].append(current)
                    break
            else:
                return None
        return buckets

    def build(self, token_to_posting_list, context, rng):
        total = perf_counter_ns()
        entries = validate_entries(token_to_posting_list)
        pstore, p_ns = build_pstore(entries, context, rng)
        locator, l_ns = build_locator(pstore, context)
        bucket_size = int(self.options.get("bucket_size", 4))
        load = float(self.options.get("cuckoo_load", 0.92))
        requested = max(2, math.ceil(len(entries) / (bucket_size * load)))
        count = 1 << (requested - 1).bit_length()
        attempts = 0
        resizes = 0
        retry_ns = 0
        insertion_ns = 0
        tokens = list(entries)
        while True:
            seed = rng.getrandbits(128).to_bytes(16, "big")
            attempts += 1
            started = perf_counter_ns()
            buckets = self._try_build(tokens, count, seed, rng)
            elapsed = perf_counter_ns() - started
            insertion_ns += elapsed
            if buckets is not None:
                break
            retry_ns += elapsed
            if attempts % int(self.options.get("attempts_before_resize", 4)) == 0:
                count *= 2
                resizes += 1
        self.state = {
            "buckets": buckets, "count": count, "seed": seed,
            "bucket_size": bucket_size, "pstore": pstore, "locator": locator,
            "context_digest": pstore["context_digest"],
        }
        self._stats = empty_build_stats()
        self._stats.update({
            "attempt_count": attempts, "resize_count": resizes,
            "final_capacity": count * bucket_size,
            "peeling_or_insertion_ns": insertion_ns, "retry_ns": retry_ns,
            "locator_build_ns": l_ns, "pstore_build_ns": p_ns,
        })
        finalize_build_stats(self, self._stats, total)
        return self

    def query(self, token, context):
        started = perf_counter_ns()
        fp = self._fp(token)
        i1, i2 = self._buckets(token, fp, self.state["seed"], self.state["count"])
        candidate = fp in self.state["buckets"][i1] or fp in self.state["buckets"][i2]
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
        width = (int(self.options.get("fingerprint_bits", 16)) + 7) // 8
        return self.state["count"] * self.state["bucket_size"] * width

    def size_breakdown(self):
        return common_size(self, self.filter_only_size_bytes(), self._metadata())

    def _metadata(self):
        return {"name": self.name, "bucket_count": self.state["count"],
                "bucket_size": self.state["bucket_size"], "seed": self.state["seed"]}
