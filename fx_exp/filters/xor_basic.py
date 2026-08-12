"""Three-global-hash XOR retrieval baseline without fuse segmentation."""

import hashlib
import math
from collections import deque
from time import perf_counter_ns

from Code.fxdacp.crypto_utils import random_bytes
from Code.fxdacp.encoding import encode

from .base import (
    FilterBackend, QueryResult, check_bytes, open_pstore, prepare_pstore, size_result,
)


def _positions(seed, token, m):
    positions, counter = [], 0
    while len(positions) < 3:
        digest = hashlib.sha256(encode(["XOR-Retrieval-v1", seed, token, counter])).digest()
        position = int.from_bytes(digest[:8], "big") % m
        counter += 1
        if position not in positions:
            positions.append(position)
    return tuple(positions)


class XORRetrieval(FilterBackend):
    name = "XOR-Retrieval"

    def build(self, entries, config, rng):
        started = perf_counter_ns()
        pstore = prepare_pstore(entries, rng, config.get("context", b"fx-exp"))
        delta = int(config.get("delta", 64))
        b_j = max(1, math.ceil(math.log(max(1, len(entries)), 2)))
        payload_bits = b_j + delta
        payloads = {}
        for token in entries:
            identifier = pstore["identifiers"][token]
            payloads[token] = (identifier << delta) | int.from_bytes(check_bytes(token, identifier, delta), "big")
        c = float(config.get("xor_c", 1.30))
        r_max = int(config.get("r_max", 8))
        gamma = float(config.get("gamma", 1.10))
        m = max(3, math.ceil(c * len(entries)))
        retries = expansions = 0
        while True:
            for _ in range(r_max):
                seed = random_bytes(rng, 16)
                stack, edges = self._peel(payloads, seed, m)
                if stack is None:
                    retries += 1
                    continue
                slots = [rng.getrandbits(payload_bits) for _ in range(m)]
                for token, pivot in reversed(stack):
                    others = [value for value in edges[token] if value != pivot]
                    slots[pivot] = payloads[token] ^ slots[others[0]] ^ slots[others[1]]
                return {
                    "slots": slots, "seed": seed, "m": m, "delta": delta,
                    "b_j": b_j, "payload_bits": payload_bits, "pstore": pstore,
                    "retries": retries, "expansions": expansions,
                    "build_ns": perf_counter_ns() - started,
                }
            expansions += 1
            m = max(m + 1, math.ceil(gamma * m))

    def _peel(self, payloads, seed, m):
        edges = {token: _positions(seed, token, m) for token in payloads}
        adjacent = [[] for _ in range(m)]
        degree = [0] * m
        for token, edge in edges.items():
            for position in edge:
                adjacent[position].append(token)
                degree[position] += 1
        queue = deque(index for index, value in enumerate(degree) if value == 1)
        removed, stack = set(), []
        while queue:
            pivot = queue.popleft()
            if degree[pivot] != 1:
                continue
            token = next((token for token in adjacent[pivot] if token not in removed), None)
            if token is None:
                continue
            removed.add(token)
            stack.append((token, pivot))
            for position in edges[token]:
                degree[position] -= 1
                if degree[position] == 1:
                    queue.append(position)
        return (stack, edges) if len(stack) == len(payloads) else (None, edges)

    def query(self, index, token):
        started = perf_counter_ns()
        positions = _positions(index["seed"], token, index["m"])
        recovered = index["slots"][positions[0]] ^ index["slots"][positions[1]] ^ index["slots"][positions[2]]
        identifier = recovered >> index["delta"]
        check = (recovered & ((1 << index["delta"]) - 1)).to_bytes((index["delta"] + 7)//8, "big")
        filter_ns = perf_counter_ns() - started
        if identifier >= len(index["pstore"]["records"]) or check != check_bytes(token, identifier, index["delta"]):
            return QueryResult(False, metrics={"slot_reads": 3, "query_ns": filter_ns})
        rows, pstore_ns, attempts = open_pstore(index["pstore"], token, identifier)
        return QueryResult(rows is not None, rows or (), {
            "slot_reads": 3, "query_ns": filter_ns + pstore_ns,
            "pstore_ns": pstore_ns, "aead_attempts": attempts,
            "aead_successes": int(rows is not None),
        })

    def serialized_size(self, index):
        filter_bytes = len(index["slots"]) * ((index["payload_bits"] + 7) // 8)
        return size_result(filter_bytes, index["pstore"], {
            key: index[key] for key in ("m", "delta", "b_j", "seed")
        })
