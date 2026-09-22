from time import perf_counter_ns

from core.fxdacp.encoding import encode

from .base import FilterBackend, QueryResult, open_pstore, prepare_pstore, size_result


class LinearScan(FilterBackend):
    name = "Linear Scan"

    def build(self, entries, config, rng):
        started = perf_counter_ns()
        pstore = prepare_pstore(entries, rng, config.get("context", b"fx-exp"))
        pairs = [(token, pstore["identifiers"][token]) for token in sorted(entries)]
        return {
            "pairs": pairs, "pstore": pstore,
            "build_ns": perf_counter_ns() - started, "retries": 0, "expansions": 0,
        }

    def query(self, index, token):
        started = perf_counter_ns()
        identifier = None
        reads = 0
        for candidate, value in index["pairs"]:
            reads += 1
            if candidate == token:
                identifier = value
                break
        lookup_ns = perf_counter_ns() - started
        if identifier is None:
            return QueryResult(False, metrics={"slot_reads": reads, "query_ns": lookup_ns})
        rows, pstore_ns, attempts = open_pstore(index["pstore"], token, identifier)
        return QueryResult(rows is not None, rows or (), {
            "slot_reads": reads, "query_ns": lookup_ns + pstore_ns,
            "pstore_ns": pstore_ns, "aead_attempts": attempts,
            "aead_successes": int(rows is not None),
        }, "hit" if rows is not None else "aead")

    def serialized_size(self, index):
        filter_bytes = len(encode(index["pairs"]))
        return size_result(filter_bytes, index["pstore"], {"name": self.name})
