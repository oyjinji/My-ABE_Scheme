"""Fuse-XOR Attribute Bloomier Filter (``fxabf-fuse-v1``).

This module fixes the segment planner and position function as part of the
profile.  The core is a static three-hyperedge XOR retrieval structure; the
``FXABFIndex`` wrapper adds compact random PStore identifiers, short checks,
token-derived AES-GCM keys and canonical posting-list validation.
"""

import hashlib
import math
import random
from collections import deque
from dataclasses import dataclass
from time import perf_counter_ns

from .crypto_utils import aead_decrypt, aead_encrypt, constant_time_equal, kdf, random_bytes
from .encoding import decode_posting_list, encode, encode_posting_list
from .metrics import FXABFBuildStats, FXABFQueryStats


PROFILE = "fxabf-fuse-v1"
MASK64 = (1 << 64) - 1


@dataclass(frozen=True)
class SegmentMeta:
    segment_length: int
    segment_count: int


@dataclass
class QueryResult:
    hit: bool
    posting_list: tuple = ()
    stats: FXABFQueryStats = None
    reason: str = "miss"


def _splitmix64(value):
    value = (value + 0x9E3779B97F4A7C15) & MASK64
    value = ((value ^ (value >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
    value = ((value ^ (value >> 27)) * 0x94D049BB133111EB) & MASK64
    return (value ^ (value >> 31)) & MASK64


def plan_segments(m, requested_length=64):
    """Plan contiguous non-empty segments, including at least three segments."""
    if m < 3:
        raise ValueError("FX-ABF requires at least three slots")
    requested_length = max(1, int(requested_length))
    segment_length = min(requested_length, max(1, m // 3))
    segment_count = (m + segment_length - 1) // segment_length
    if segment_count < 3:  # Defensive; m//3 rule already guarantees this.
        segment_count = 3
        segment_length = max(1, m // 3)
    return SegmentMeta(segment_length, segment_count)


def _segment_bounds(segment, m, meta):
    start = segment * meta.segment_length
    end = min(m, start + meta.segment_length)
    if start >= end:
        raise ValueError("empty segment in metadata")
    return start, end


def _uniform(seed, token, lane, size):
    """Deterministic unbiased reduction from a SHA-256/SplitMix64 stream."""
    if size <= 0:
        raise ValueError("range must be positive")
    threshold = (1 << 64) % size
    counter = 0
    while True:
        digest = hashlib.sha256(encode([
            PROFILE, seed, token, int(lane), counter,
        ])).digest()
        value = _splitmix64(int.from_bytes(digest[:8], "big"))
        if value >= threshold:
            return value % size
        counter += 1


def fuse_positions(seed, token, m, meta):
    """Return one position in each of three consecutive profile segments."""
    if not isinstance(seed, bytes) or not isinstance(token, bytes):
        raise TypeError("seed and token must be bytes")
    expected = plan_segments(m, meta.segment_length)
    if expected != meta:
        raise ValueError("segment metadata is inconsistent with m")
    base = _uniform(seed, token, 0, meta.segment_count - 2)
    positions = []
    for lane in range(3):
        start, end = _segment_bounds(base + lane, m, meta)
        positions.append(start + _uniform(seed, token, lane + 1, end - start))
    if len(set(positions)) != 3 or any(pos < 0 or pos >= m for pos in positions):
        raise AssertionError("profile generated invalid positions")
    return tuple(positions)


class FXABF:
    """Generic fixed-width value retrieval core."""

    def __init__(self, c_fx=1.30, delta=64, r_max=8, gamma=1.05,
                 segment_length=64, rng=None):
        if c_fx <= 1:
            raise ValueError("c_fx must be greater than one")
        if delta < 1:
            raise ValueError("delta must be positive")
        if r_max < 1 or gamma <= 1:
            raise ValueError("r_max >= 1 and gamma > 1 are required")
        self.c_fx = float(c_fx)
        self.delta = int(delta)
        self.r_max = int(r_max)
        self.gamma = float(gamma)
        self.segment_length = int(segment_length)
        self.rng = rng or random.SystemRandom()

    def build_values(self, values, payload_bits, initial_m=None):
        if not values:
            raise ValueError("FX-ABF cannot build an empty key set")
        if any(not isinstance(token, bytes) for token in values):
            raise TypeError("FX-ABF tokens must be bytes")
        if len(values) != len(set(values)):
            raise ValueError("FX-ABF tokens must be distinct")
        limit = 1 << payload_bits
        if any(not isinstance(value, int) or value < 0 or value >= limit
               for value in values.values()):
            raise ValueError("payload is outside fixed width")
        started = perf_counter_ns()
        u = len(values)
        m = max(3, int(initial_m) if initial_m is not None else math.ceil(self.c_fx * u))
        stats = FXABFBuildStats(initial_m=m)
        failures = 0
        while True:
            meta = plan_segments(m, self.segment_length)
            for _attempt in range(self.r_max):
                seed = random_bytes(self.rng, 16)
                peel_started = perf_counter_ns()
                stack, edges = self._peel(values, seed, m, meta)
                stats.peeling_ns += perf_counter_ns() - peel_started
                if stack is None:
                    failures += 1
                    continue
                assignment_started = perf_counter_ns()
                slots = [self.rng.getrandbits(payload_bits) for _ in range(m)]
                for token, pivot in reversed(stack):
                    p0, p1, p2 = edges[token]
                    other = [pos for pos in (p0, p1, p2) if pos != pivot]
                    slots[pivot] = values[token] ^ slots[other[0]] ^ slots[other[1]]
                stats.assignment_ns += perf_counter_ns() - assignment_started
                stats.retries = failures
                stats.first_attempt_success = failures == 0
                stats.final_m = m
                stats.total_ns = perf_counter_ns() - started
                return {
                    "profile": PROFILE,
                    "slots": slots,
                    "m": m,
                    "payload_bits": int(payload_bits),
                    "seed": seed,
                    "segment_length": meta.segment_length,
                    "segment_count": meta.segment_count,
                    "r_max": self.r_max,
                }, stats
            stats.expansions += 1
            new_m = max(m + 1, math.ceil(self.gamma * m))
            m = new_m

    def _peel(self, values, seed, m, meta):
        edges = {token: fuse_positions(seed, token, m, meta) for token in values}
        adjacent = [[] for _ in range(m)]
        degree = [0] * m
        for token, positions in edges.items():
            for pos in positions:
                adjacent[pos].append(token)
                degree[pos] += 1
        queue = deque(pos for pos, value in enumerate(degree) if value == 1)
        removed = set()
        stack = []
        while queue:
            pivot = queue.popleft()
            if degree[pivot] != 1:
                continue
            token = next((item for item in adjacent[pivot] if item not in removed), None)
            if token is None:
                continue
            removed.add(token)
            stack.append((token, pivot))
            for pos in edges[token]:
                degree[pos] -= 1
                if degree[pos] == 1:
                    queue.append(pos)
        if len(stack) != len(values):
            return None, edges
        return stack, edges

    @staticmethod
    def query_value(index, token):
        FXABF.validate_core(index)
        meta = SegmentMeta(index["segment_length"], index["segment_count"])
        positions = fuse_positions(index["seed"], token, index["m"], meta)
        value = index["slots"][positions[0]] ^ index["slots"][positions[1]] ^ index["slots"][positions[2]]
        return value, positions

    @staticmethod
    def validate_core(index):
        required = {"profile", "slots", "m", "payload_bits", "seed",
                    "segment_length", "segment_count", "r_max"}
        if not isinstance(index, dict) or not required.issubset(index):
            raise ValueError("malformed FX-ABF")
        if index["profile"] != PROFILE or index["m"] != len(index["slots"]):
            raise ValueError("unsupported or inconsistent FX-ABF")
        meta = SegmentMeta(index["segment_length"], index["segment_count"])
        if plan_segments(index["m"], meta.segment_length) != meta:
            raise ValueError("invalid segment metadata")


class FXABFIndex:
    """Authenticated token-to-posting-list retrieval index."""

    def __init__(self, c_fx=1.30, delta=64, r_max=8, gamma=1.05,
                 segment_length=64, rng=None):
        self.core = FXABF(c_fx, delta, r_max, gamma, segment_length, rng)
        self.delta = int(delta)
        self.rng = self.core.rng

    def build(self, entries, ctx, ell, initial_m=None):
        if not entries:
            raise ValueError("entries cannot be empty")
        tokens = list(entries)
        if any(not isinstance(token, bytes) for token in tokens):
            raise TypeError("entry tokens must be serialized bytes")
        for rows in entries.values():
            encoded = encode_posting_list(rows)
            decode_posting_list(encoded, ell)
        shuffled = list(tokens)
        self.rng.shuffle(shuffled)
        identifiers = {token: index for index, token in enumerate(shuffled)}
        u = len(tokens)
        b_j = max(1, math.ceil(math.log(u, 2))) if u > 1 else 1
        payloads = {}
        for token, identifier in identifiers.items():
            check = self._check(ctx, token, identifier, b_j)
            payloads[token] = (identifier << self.delta) | int.from_bytes(check, "big")
        core_index, stats = self.core.build_values(
            payloads, b_j + self.delta, initial_m=initial_m,
        )
        seed = core_index["seed"]
        pstore = [None] * u
        pstore_started = perf_counter_ns()
        for token, identifier in identifiers.items():
            key = self._posting_key(ctx, token, seed)
            aad = self._posting_aad(ctx, u, ell, identifier)
            nonce = random_bytes(self.rng, 12)
            pstore[identifier] = aead_encrypt(
                key, encode_posting_list(entries[token]), aad, nonce=nonce,
            )
        pstore_ns = perf_counter_ns() - pstore_started
        index = {
            "profile": PROFILE,
            "u": u,
            "ell": int(ell),
            "b_j": b_j,
            "delta": self.delta,
            "fxabf": core_index,
            "pstore": pstore,
        }
        return index, stats, pstore_ns

    def query(self, index, token, ctx):
        stats = FXABFQueryStats()
        try:
            self._validate(index)
            started = perf_counter_ns()
            core = index["fxabf"]
            meta = SegmentMeta(core["segment_length"], core["segment_count"])
            positions = fuse_positions(core["seed"], token, core["m"], meta)
            stats.position_ns = perf_counter_ns() - started
            started = perf_counter_ns()
            selected = [core["slots"][pos] for pos in positions]
            stats.slot_reads = 3
            stats.slot_read_ns = perf_counter_ns() - started
            started = perf_counter_ns()
            recovered = selected[0] ^ selected[1] ^ selected[2]
            stats.xor_ns = perf_counter_ns() - started
            started = perf_counter_ns()
            identifier = recovered >> index["delta"]
            mask = (1 << index["delta"]) - 1
            recovered_check = (recovered & mask).to_bytes((index["delta"] + 7) // 8, "big")
            in_range = 0 <= identifier < index["u"]
            stats.range_check_ns = perf_counter_ns() - started
            if not in_range:
                return QueryResult(False, stats=stats, reason="range")
            started = perf_counter_ns()
            expected = self._check(ctx, token, identifier, index["b_j"])
            check_ok = constant_time_equal(recovered_check, expected)
            stats.short_check_ns = perf_counter_ns() - started
            if not check_ok:
                return QueryResult(False, stats=stats, reason="short-check")
            started = perf_counter_ns()
            stats.aead_attempts = 1
            key = self._posting_key(ctx, token, core["seed"])
            aad = self._posting_aad(ctx, index["u"], index["ell"], identifier)
            plaintext = aead_decrypt(key, index["pstore"][identifier], aad)
            stats.pstore_ns = perf_counter_ns() - started
            if plaintext is None:
                return QueryResult(False, stats=stats, reason="aead")
            stats.aead_successes = 1
            started = perf_counter_ns()
            rows = decode_posting_list(plaintext, index["ell"])
            stats.posting_decode_ns = perf_counter_ns() - started
            stats.outcome = "hit"
            return QueryResult(True, tuple(rows), stats, "hit")
        except Exception:
            return QueryResult(False, stats=stats, reason="malformed")

    def serialized_size(self, index):
        self._validate(index)
        core = index["fxabf"]
        slot_bytes = (core["payload_bits"] + 7) // 8
        filter_bytes = len(core["slots"]) * slot_bytes
        pstore_bytes = sum(len(item["nonce"]) + len(item["ciphertext"])
                           for item in index["pstore"])
        metadata_bytes = len(encode({
            key: value for key, value in index.items()
            if key not in ("fxabf", "pstore")
        })) + len(encode({
            key: value for key, value in core.items() if key != "slots"
        }))
        return {
            "filter_bytes": filter_bytes,
            "pstore_bytes": pstore_bytes,
            "metadata_bytes": metadata_bytes,
            "total_index_bytes": filter_bytes + pstore_bytes + metadata_bytes,
        }

    def _validate(self, index):
        required = {"profile", "u", "ell", "b_j", "delta", "fxabf", "pstore"}
        if not isinstance(index, dict) or not required.issubset(index):
            raise ValueError("malformed FX-ABF index")
        if index["profile"] != PROFILE or index["u"] < 1:
            raise ValueError("unsupported FX-ABF index")
        if len(index["pstore"]) != index["u"]:
            raise ValueError("PStore length mismatch")
        if index["fxabf"]["payload_bits"] != index["b_j"] + index["delta"]:
            raise ValueError("payload width mismatch")
        FXABF.validate_core(index["fxabf"])

    def _check(self, ctx, token, identifier, b_j):
        width = (self.delta + 7) // 8
        digest = hashlib.sha256(encode([
            "FXABF-Check", ctx, token, {"bits": b_j, "value": identifier},
        ])).digest()
        value = int.from_bytes(digest, "big") >> (256 - self.delta)
        return value.to_bytes(width, "big")

    @staticmethod
    def _posting_key(ctx, token, seed):
        return kdf("FXABF-Posting-Key", ctx, token, seed)

    @staticmethod
    def _posting_aad(ctx, u, ell, identifier):
        return encode(["FXABF-Posting-AD", ctx, int(u), int(ell), int(identifier)])
