"""Static three-candidate-bin, multi-table as-ACF/Cuckoo-style adapter."""

import hashlib
import math
from time import perf_counter_ns

from core.fxdacp.encoding import encode

from .base import FilterBackend, QueryResult, open_pstore, prepare_pstore, size_result


class CuckooACF(FilterBackend):
    name = "as-ACF/Cuckoo"

    def build(self, entries, config, rng):
        started = perf_counter_ns()
        pstore = prepare_pstore(entries, rng, config.get("context", b"fx-exp"))
        bucket_size = int(config.get("cuckoo_bucket_size", 4))
        fp_bits = int(config.get("fingerprint_bits", 16))
        threshold = float(config.get("cuckoo_threshold", 0.85))
        bin_count = max(3, math.ceil(len(entries) / (bucket_size * threshold)))
        tables = []
        for token in sorted(entries):
            fingerprint = self._fingerprint(token, fp_bits)
            identifier = pstore["identifiers"][token]
            inserted = False
            for table_index, table in enumerate(tables):
                if table["count"] >= int(threshold * bin_count * bucket_size):
                    continue
                for bin_id in self._bins(token, table["seed"], bin_count):
                    if len(table["bins"][bin_id]) < bucket_size:
                        table["bins"][bin_id].append((fingerprint, identifier))
                        table["count"] += 1
                        inserted = True
                        break
                if inserted:
                    break
            if not inserted:
                seed = rng.getrandbits(128).to_bytes(16, "big")
                table = {"seed": seed, "bins": [[] for _ in range(bin_count)], "count": 0}
                tables.append(table)
                for bin_id in self._bins(token, seed, bin_count):
                    if len(table["bins"][bin_id]) < bucket_size:
                        table["bins"][bin_id].append((fingerprint, identifier))
                        table["count"] += 1
                        inserted = True
                        break
            if not inserted:
                raise RuntimeError("new as-ACF table could not accept item")
        return {
            "tables": tables, "bin_count": bin_count, "bucket_size": bucket_size,
            "fingerprint_bits": fp_bits, "threshold": threshold, "pstore": pstore,
            "retries": 0, "expansions": max(0, len(tables) - 1),
            "build_ns": perf_counter_ns() - started,
        }

    def query(self, index, token):
        started = perf_counter_ns()
        fingerprint = self._fingerprint(token, index["fingerprint_bits"])
        candidates = []
        scanned = 0
        for table in index["tables"]:
            scanned += 1
            for bin_id in self._bins(token, table["seed"], index["bin_count"]):
                candidates.extend(identifier for fp, identifier in table["bins"][bin_id]
                                  if fp == fingerprint)
        filter_ns = perf_counter_ns() - started
        pstore_ns = attempts = 0
        for identifier in candidates:
            rows, elapsed, attempted = open_pstore(index["pstore"], token, identifier)
            pstore_ns += elapsed
            attempts += attempted
            if rows is not None:
                return QueryResult(True, rows, {
                    "tables_scanned": scanned, "slot_reads": scanned * 3,
                    "query_ns": filter_ns + pstore_ns, "pstore_ns": pstore_ns,
                    "aead_attempts": attempts, "aead_successes": 1,
                }, "hit")
        return QueryResult(False, metrics={
            "tables_scanned": scanned, "slot_reads": scanned * 3,
            "query_ns": filter_ns + pstore_ns, "pstore_ns": pstore_ns,
            "aead_attempts": attempts, "aead_successes": 0,
        })

    def serialized_size(self, index):
        canonical = []
        for table in index["tables"]:
            canonical.append({"seed": table["seed"], "bins": table["bins"]})
        return size_result(len(encode(canonical)), index["pstore"], {
            key: index[key] for key in ("bin_count", "bucket_size", "fingerprint_bits", "threshold")
        })

    @staticmethod
    def _fingerprint(token, bits):
        width = (bits + 7) // 8
        value = int.from_bytes(hashlib.sha256(b"as-ACF-fp" + token).digest(), "big") >> (256 - bits)
        return value.to_bytes(width, "big")

    @staticmethod
    def _bins(token, seed, count):
        result = []
        for lane in range(3):
            digest = hashlib.sha256(encode(["as-ACF-bin", seed, token, lane])).digest()
            result.append(int.from_bytes(digest[:8], "big") % count)
        return result
