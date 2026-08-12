"""Greedy XOR Attribute-BF adapted to compact PStore identifiers."""

import hashlib
import math
from time import perf_counter_ns

from Code.fxdacp.encoding import encode
from Code.fxdacp.crypto_utils import random_bytes

from .base import (
    FilterBackend, QueryResult, check_bytes, open_pstore, prepare_pstore, size_result,
)


def _xor(left, right):
    return bytes(a ^ b for a, b in zip(left, right))


def _positions(seed, token, m, k):
    result, counter = [], 0
    while len(result) < k:
        digest = hashlib.sha256(encode(["Attribute-BF-2018", seed, token, counter])).digest()
        position = int.from_bytes(digest[:8], "big") % m
        counter += 1
        if position not in result:
            result.append(position)
    return result


class AttributeBFGreedy(FilterBackend):
    name = "Attribute-BF (greedy)"

    def build(self, entries, config, rng):
        started = perf_counter_ns()
        pstore = prepare_pstore(entries, rng, config.get("context", b"fx-exp"))
        delta = int(config.get("delta", 64))
        check_len = (delta + 7) // 8
        identifier_len = max(1, math.ceil(max(1, len(entries)).bit_length() / 8))
        width = identifier_len + check_len
        k = int(config.get("greedy_k", 3))
        c = float(config.get("greedy_c", 2.0))
        r_max = int(config.get("r_max", 8))
        gamma = float(config.get("gamma", 1.10))
        m = max(k, math.ceil(c * len(entries)))
        retries = expansions = 0
        ordered = sorted(entries)
        while True:
            for _ in range(r_max):
                seed = random_bytes(rng, 16)
                slots = [None] * m
                failed = False
                for token in ordered:
                    positions = _positions(seed, token, m, k)
                    free = [position for position in positions if slots[position] is None]
                    if not free:
                        failed = True
                        retries += 1
                        break
                    reserved = free[-1]
                    identifier = pstore["identifiers"][token]
                    payload = identifier.to_bytes(identifier_len, "big") + check_bytes(token, identifier, delta)
                    accumulator = bytes(width)
                    for position in positions:
                        if position == reserved:
                            continue
                        if slots[position] is None:
                            slots[position] = random_bytes(rng, width)
                        accumulator = _xor(accumulator, slots[position])
                    slots[reserved] = _xor(accumulator, payload)
                if failed:
                    continue
                slots = [slot if slot is not None else random_bytes(rng, width) for slot in slots]
                return {
                    "slots": slots, "seed": seed, "m": m, "k": k,
                    "delta": delta, "identifier_len": identifier_len,
                    "pstore": pstore, "retries": retries, "expansions": expansions,
                    "build_ns": perf_counter_ns() - started,
                }
            expansions += 1
            m = max(m + 1, math.ceil(gamma * m))

    def query(self, index, token):
        started = perf_counter_ns()
        positions = _positions(index["seed"], token, index["m"], index["k"])
        recovered = bytes(len(index["slots"][0]))
        for position in positions:
            recovered = _xor(recovered, index["slots"][position])
        identifier = int.from_bytes(recovered[:index["identifier_len"]], "big")
        expected = check_bytes(token, identifier, index["delta"])
        filter_ns = perf_counter_ns() - started
        if identifier >= len(index["pstore"]["records"]) or recovered[index["identifier_len"]:] != expected:
            return QueryResult(False, metrics={"slot_reads": len(positions), "query_ns": filter_ns})
        rows, pstore_ns, attempts = open_pstore(index["pstore"], token, identifier)
        return QueryResult(rows is not None, rows or (), {
            "slot_reads": len(positions), "query_ns": filter_ns + pstore_ns,
            "pstore_ns": pstore_ns, "aead_attempts": attempts,
            "aead_successes": int(rows is not None),
        })

    def serialized_size(self, index):
        return size_result(sum(len(slot) for slot in index["slots"]), index["pstore"], {
            key: index[key] for key in ("m", "k", "delta", "seed", "identifier_len")
        })
