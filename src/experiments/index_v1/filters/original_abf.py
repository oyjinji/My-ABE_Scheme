"""Original ABF baseline following ABE-Scheme+.md (random sid + greedy XOR)."""

import hashlib
import math
from time import perf_counter_ns

from Code.fxdacp.crypto_utils import aead_decrypt, aead_encrypt, kdf, random_bytes
from Code.fxdacp.encoding import decode_posting_list, encode, encode_posting_list

from .attribute_bf_2018 import _xor
from .base import FilterBackend, QueryResult, size_result


class OriginalABF(FilterBackend):
    name = "Original-ABF"

    def build(self, entries, config, rng):
        started = perf_counter_ns()
        delta = int(config.get("delta", 64))
        sid_len = int(config.get("sid_bytes", 16))
        k = int(config.get("original_k", 3))
        c = float(config.get("original_c", 2.0))
        r_max = int(config.get("r_max", 8))
        gamma = float(config.get("gamma", 1.10))
        ell = max((max(rows) for rows in entries.values() if rows), default=0)
        m = max(k, math.ceil(c * len(entries)))
        retries = expansions = 0
        while True:
            for _ in range(r_max):
                seed = random_bytes(rng, 16)
                slots = [None] * m
                pstore = {}
                failed = False
                for token in sorted(entries):
                    sid = random_bytes(rng, sid_len)
                    while sid in pstore:
                        sid = random_bytes(rng, sid_len)
                    key = kdf("ABE-Posting-Key", token, seed)
                    aad = encode(["ABE-Posting", "1", "0", ell, sid])
                    pstore[sid] = aead_encrypt(
                        key, encode_posting_list(entries[token]), aad, random_bytes(rng, 12),
                    )
                    check = hashlib.sha256(encode(["Original-ABF-Check", token])).digest()[:(delta + 7)//8]
                    payload = sid + check
                    positions = _original_positions(seed, token, m, k)
                    free = [position for position in positions if slots[position] is None]
                    if not free:
                        retries += 1
                        failed = True
                        break
                    reserved = free[-1]
                    accumulator = bytes(len(payload))
                    for position in positions:
                        if position == reserved:
                            continue
                        if slots[position] is None:
                            slots[position] = random_bytes(rng, len(payload))
                        accumulator = _xor(accumulator, slots[position])
                    slots[reserved] = _xor(accumulator, payload)
                if failed:
                    continue
                slots = [slot if slot is not None else random_bytes(rng, sid_len + (delta+7)//8)
                         for slot in slots]
                return {
                    "slots": slots, "seed": seed, "m": m, "k": k,
                    "delta": delta, "sid_len": sid_len, "ell": ell,
                    "pstore_map": pstore, "retries": retries, "expansions": expansions,
                    "build_ns": perf_counter_ns() - started,
                }
            expansions += 1
            m = max(m + 1, math.ceil(gamma * m))

    def query(self, index, token):
        started = perf_counter_ns()
        positions = _original_positions(index["seed"], token, index["m"], index["k"])
        payload = bytes(len(index["slots"][0]))
        for position in positions:
            payload = _xor(payload, index["slots"][position])
        sid = payload[:index["sid_len"]]
        check = payload[index["sid_len"]:]
        expected = hashlib.sha256(encode(["Original-ABF-Check", token])).digest()[:len(check)]
        filter_ns = perf_counter_ns() - started
        if check != expected or sid not in index["pstore_map"]:
            return QueryResult(False, metrics={"slot_reads": len(positions), "query_ns": filter_ns})
        key = kdf("ABE-Posting-Key", token, index["seed"])
        aad = encode(["ABE-Posting", "1", "0", index["ell"], sid])
        started = perf_counter_ns()
        plaintext = aead_decrypt(key, index["pstore_map"][sid], aad)
        pstore_ns = perf_counter_ns() - started
        try:
            rows = tuple(decode_posting_list(plaintext, index["ell"])) if plaintext is not None else ()
        except Exception:
            rows = ()
        return QueryResult(bool(rows), rows, {
            "slot_reads": len(positions), "query_ns": filter_ns + pstore_ns,
            "pstore_ns": pstore_ns, "aead_attempts": 1,
            "aead_successes": int(bool(rows)),
        })

    def serialized_size(self, index):
        pstore = {"records": list(index["pstore_map"].values())}
        filter_bytes = sum(len(slot) for slot in index["slots"])
        # sid keys are part of the PStore representation in the original scheme.
        sid_bytes = sum(len(sid) for sid in index["pstore_map"])
        result = size_result(filter_bytes, pstore, {
            key: index[key] for key in ("m", "k", "delta", "seed", "sid_len")
        })
        result["pstore_bytes"] += sid_bytes
        result["total_index_bytes"] += sid_bytes
        return result


def _original_positions(seed, token, m, k):
    """Documented (seed, hash-index, token, counter) rejection sampling."""
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
    return positions
