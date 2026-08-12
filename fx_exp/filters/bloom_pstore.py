import hashlib
import math
from time import perf_counter_ns

from Code.fxdacp.encoding import encode

from .base import FilterBackend, QueryResult, open_pstore, prepare_pstore, size_result, token_digest


class BloomExactPStore(FilterBackend):
    name = "Bloom+Exact-PStore"

    def build(self, entries, config, rng):
        started = perf_counter_ns()
        pstore = prepare_pstore(entries, rng, config.get("context", b"fx-exp"))
        bits_per_token = int(config.get("bloom_bits_per_token", 10))
        bit_count = max(8, bits_per_token * len(entries))
        k = max(1, round(bits_per_token * math.log(2)))
        bitmap = bytearray((bit_count + 7) // 8)
        table = {}
        for token in entries:
            digest = token_digest(token)
            table[digest] = pstore["identifiers"][token]
            for position in self._positions(digest, bit_count, k):
                bitmap[position // 8] |= 1 << (position % 8)
        return {
            "bitmap": bytes(bitmap), "bit_count": bit_count, "k": k,
            "table": table, "pstore": pstore,
            "build_ns": perf_counter_ns() - started, "retries": 0, "expansions": 0,
        }

    def query(self, index, token):
        started = perf_counter_ns()
        digest = token_digest(token)
        positions = self._positions(digest, index["bit_count"], index["k"])
        member = all(index["bitmap"][pos // 8] & (1 << (pos % 8)) for pos in positions)
        identifier = index["table"].get(digest) if member else None
        filter_ns = perf_counter_ns() - started
        if identifier is None:
            return QueryResult(False, metrics={
                "slot_reads": len(positions), "query_ns": filter_ns,
            })
        rows, pstore_ns, attempts = open_pstore(index["pstore"], token, identifier)
        return QueryResult(rows is not None, rows or (), {
            "slot_reads": len(positions), "query_ns": filter_ns + pstore_ns,
            "pstore_ns": pstore_ns, "aead_attempts": attempts,
            "aead_successes": int(rows is not None),
        })

    def serialized_size(self, index):
        exact = sorted((key, value) for key, value in index["table"].items())
        filter_bytes = len(index["bitmap"]) + len(encode(exact))
        return size_result(filter_bytes, index["pstore"], {
            "name": self.name, "k": index["k"], "bits": index["bit_count"],
        })

    @staticmethod
    def _positions(digest, bit_count, k):
        positions = []
        for counter in range(k):
            value = hashlib.sha256(digest + counter.to_bytes(4, "big")).digest()
            positions.append(int.from_bytes(value[:8], "big") % bit_count)
        return positions
