from time import perf_counter_ns

from core.fxdacp.encoding import encode

from .base import FilterBackend, QueryResult, open_pstore, prepare_pstore, size_result, token_digest


class ExactHash(FilterBackend):
    name = "Exact Hash"

    def build(self, entries, config, rng):
        started = perf_counter_ns()
        pstore = prepare_pstore(entries, rng, config.get("context", b"fx-exp"))
        table = {token_digest(token): pstore["identifiers"][token] for token in entries}
        return {
            "table": table, "pstore": pstore,
            "build_ns": perf_counter_ns() - started, "retries": 0, "expansions": 0,
        }

    def query(self, index, token):
        started = perf_counter_ns()
        identifier = index["table"].get(token_digest(token))
        hash_ns = perf_counter_ns() - started
        if identifier is None:
            return QueryResult(False, metrics={"hash_reads": 1, "query_ns": hash_ns})
        rows, pstore_ns, attempts = open_pstore(index["pstore"], token, identifier)
        return QueryResult(rows is not None, rows or (), {
            "hash_reads": 1, "query_ns": hash_ns + pstore_ns,
            "pstore_ns": pstore_ns, "aead_attempts": attempts,
            "aead_successes": int(rows is not None),
        }, "hit" if rows is not None else "aead")

    def serialized_size(self, index):
        canonical = sorted((key, value) for key, value in index["table"].items())
        return size_result(len(encode(canonical)), index["pstore"], {"name": self.name})
