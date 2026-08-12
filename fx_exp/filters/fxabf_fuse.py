"""Experiment adapter around the formal Code.fxdacp FX-ABF core."""

import math
from time import perf_counter_ns

from Code.fxdacp.fxabf import FXABF, SegmentMeta, fuse_positions

from .base import (
    FilterBackend, QueryResult, check_bytes, open_pstore, prepare_pstore, size_result,
)


class FXABFFuse(FilterBackend):
    name = "FX-ABF"

    def build(self, entries, config, rng):
        started = perf_counter_ns()
        pstore = prepare_pstore(entries, rng, config.get("context", b"fx-exp"))
        delta = int(config.get("delta", 64))
        b_j = max(1, math.ceil(math.log(max(1, len(entries)), 2)))
        payloads = {}
        for token in entries:
            identifier = pstore["identifiers"][token]
            payloads[token] = (identifier << delta) | int.from_bytes(check_bytes(token, identifier, delta), "big")
        core = FXABF(
            c_fx=float(config.get("c_fx", 1.30)), delta=delta,
            r_max=int(config.get("r_max", 8)), gamma=float(config.get("gamma", 1.05)),
            segment_length=int(config.get("segment_length", 64)), rng=rng,
        )
        built, stats = core.build_values(payloads, b_j + delta)
        return {
            "core": built, "pstore": pstore, "delta": delta, "b_j": b_j,
            "build_stats": stats, "retries": stats.retries,
            "expansions": stats.expansions, "build_ns": perf_counter_ns() - started,
        }

    def query(self, index, token):
        total_started = perf_counter_ns()
        try:
            core = index["core"]
            started = perf_counter_ns()
            positions = fuse_positions(core["seed"], token, core["m"], SegmentMeta(
                core["segment_length"], core["segment_count"],
            ))
            position_ns = perf_counter_ns() - started
            started = perf_counter_ns()
            selected = [core["slots"][position] for position in positions]
            slot_read_ns = perf_counter_ns() - started
            started = perf_counter_ns()
            recovered = selected[0] ^ selected[1] ^ selected[2]
            xor_ns = perf_counter_ns() - started
        except Exception:
            return QueryResult(False, metrics={"slot_reads": 0, "query_ns": perf_counter_ns() - total_started}, reason="malformed")
        started = perf_counter_ns()
        identifier = recovered >> index["delta"]
        check = (recovered & ((1 << index["delta"]) - 1)).to_bytes((index["delta"] + 7)//8, "big")
        range_ns = perf_counter_ns() - started
        base_metrics = {
            "slot_reads": 3, "position_ns": position_ns, "slot_read_ns": slot_read_ns,
            "xor_ns": xor_ns, "range_check_ns": range_ns,
        }
        if identifier >= len(index["pstore"]["records"]):
            base_metrics["query_ns"] = perf_counter_ns() - total_started
            return QueryResult(False, metrics=base_metrics, reason="range")
        started = perf_counter_ns()
        valid_check = check == check_bytes(token, identifier, index["delta"])
        base_metrics["short_check_ns"] = perf_counter_ns() - started
        if not valid_check:
            base_metrics["query_ns"] = perf_counter_ns() - total_started
            return QueryResult(False, metrics=base_metrics, reason="short-check")
        rows, pstore_ns, attempts = open_pstore(index["pstore"], token, identifier)
        base_metrics.update({
            "query_ns": perf_counter_ns() - total_started,
            "pstore_ns": pstore_ns, "aead_attempts": attempts,
            "aead_successes": int(rows is not None),
        })
        return QueryResult(rows is not None, rows or (), base_metrics,
                           "hit" if rows is not None else "aead")

    def serialized_size(self, index):
        core = index["core"]
        filter_bytes = len(core["slots"]) * ((core["payload_bits"] + 7) // 8)
        return size_result(filter_bytes, index["pstore"], {
            key: core[key] for key in ("profile", "m", "seed", "segment_length", "segment_count")
        })
