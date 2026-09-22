"""Real three-segment FX-ABF and authenticated PStore for profile 05.3."""

import hashlib
import math
import struct
from collections import deque
from dataclasses import dataclass, field
from time import perf_counter_ns

from .crypto import ct_equal, kdf, open_seal, seal, seeded_rng
from .encoding import decode_posting, encode, encode_posting


PROFILE = "FXABE05.3-SEGMENTED-XOR-V1"
PAYLOAD_BYTES = 20
CHECK_BYTES = 16
MAX_ATTEMPTS = 32


@dataclass
class FXQueryResult:
    hit: bool
    posting_list: tuple = ()
    reason: str = "miss"
    metrics: dict = field(default_factory=dict)


def _xor(left, right):
    return bytes(a ^ b for a, b in zip(left, right))


def _randbytes(rng, size):
    return bytes(rng.getrandbits(8) for _ in range(size))


def _reduce(seed, token, lane, modulus):
    if modulus < 1:
        raise ValueError("empty FX segment")
    limit = (1 << 64) - ((1 << 64) % modulus)
    counter = 0
    while True:
        value = int.from_bytes(hashlib.sha256(encode([
            PROFILE, seed, token, int(lane), counter,
        ])).digest()[:8], "big")
        if value < limit:
            return value % modulus
        counter += 1


def positions(seed, token, segment_length):
    result = tuple(lane * segment_length + _reduce(seed, token, lane, segment_length)
                   for lane in range(3))
    if len(set(result)) != 3:
        raise AssertionError("segmented FX positions collided")
    return result


class FXIndex:
    """Final state contains only metadata, fixed slots and integer PStore."""

    __slots__ = ("metadata", "slots", "pstore", "build_metrics")

    def __init__(self, metadata, slots, pstore, build_metrics):
        self.metadata = metadata
        self.slots = tuple(slots)
        self.pstore = tuple(pstore)
        self.build_metrics = dict(build_metrics)

    @classmethod
    def build(cls, token_to_rows, ctx, ell, seed=None, c_fx=1.30):
        started_total = perf_counter_ns()
        rng = seeded_rng(seed)
        if not isinstance(token_to_rows, dict) or not token_to_rows:
            raise ValueError("FX build requires entries")
        entries = {}
        for token, rows in token_to_rows.items():
            if not isinstance(token, bytes):
                raise TypeError("FX tokens must be bytes")
            encoded = encode_posting(rows)
            entries[token] = decode_posting(encoded, ell)
        u = len(entries)
        if u > 0xFFFFFFFF:
            raise ValueError("compact j overflow")
        # Tiny two-key instances need two choices in each part; with one slot
        # per part both hyperedges are necessarily identical and unpeelable.
        segment_length = max(2 if u > 1 else 1,
                             math.ceil(float(c_fx) * u / 3.0))
        m = 3 * segment_length
        tokens = tuple(entries)
        retry_ns = peel_ns = position_ns = 0
        stack = edges = fx_seed = None
        for attempt in range(1, MAX_ATTEMPTS + 1):
            attempt_started = perf_counter_ns()
            candidate_seed = _randbytes(rng, 16)
            pos_started = perf_counter_ns()
            candidate_edges = [positions(candidate_seed, token, segment_length)
                               for token in tokens]
            position_ns += perf_counter_ns() - pos_started
            degree = [0] * m
            xor_edge = [0] * m
            for edge_id, edge in enumerate(candidate_edges):
                for slot in edge:
                    degree[slot] += 1
                    xor_edge[slot] ^= edge_id
            peel_started = perf_counter_ns()
            queue = deque(i for i, value in enumerate(degree) if value == 1)
            candidate_stack = []
            while queue:
                pivot = queue.popleft()
                if degree[pivot] != 1:
                    continue
                edge_id = xor_edge[pivot]
                candidate_stack.append((edge_id, pivot))
                for slot in candidate_edges[edge_id]:
                    degree[slot] -= 1
                    xor_edge[slot] ^= edge_id
                    if degree[slot] == 1:
                        queue.append(slot)
            peel_ns += perf_counter_ns() - peel_started
            if len(candidate_stack) == u:
                stack, edges, fx_seed = candidate_stack, candidate_edges, candidate_seed
                break
            retry_ns += perf_counter_ns() - attempt_started
        if stack is None:
            raise RuntimeError("FX peeling failed after 32 fresh-seed attempts")
        identifiers = list(range(u))
        rng.shuffle(identifiers)
        token_to_j = dict(zip(tokens, identifiers))  # build-only; never retained
        checks = {
            token: hashlib.sha256(encode([
                "FX-check", ctx, token, token_to_j[token], fx_seed,
            ])).digest()[:CHECK_BYTES]
            for token in tokens
        }
        payloads = {
            token: struct.pack(">I", token_to_j[token]) + checks[token]
            for token in tokens
        }
        assign_started = perf_counter_ns()
        slots = [_randbytes(rng, PAYLOAD_BYTES) for _ in range(m)]
        for edge_id, pivot in reversed(stack):
            value = payloads[tokens[edge_id]]
            for slot in edges[edge_id]:
                if slot != pivot:
                    value = _xor(value, slots[slot])
            slots[pivot] = value
        assignment_ns = perf_counter_ns() - assign_started
        metadata = {
            "profile": PROFILE, "seed": fx_seed, "m": m,
            "segment_length": segment_length, "payload_width": PAYLOAD_BYTES,
            "check_width": CHECK_BYTES, "attempt": attempt, "u": u,
            "ell": int(ell), "ctx_digest": hashlib.sha256(ctx).digest(),
        }
        pstore_started = perf_counter_ns()
        pstore = [None] * u
        for token in tokens:
            j = token_to_j[token]
            key = kdf("FX53-POSTKEY", ctx, token, fx_seed)
            aad = encode(["FXABE05.3/PSTORE", ctx, j, metadata])
            pstore[j] = seal(key, encode_posting(entries[token]), aad, rng)
        pstore_ns = perf_counter_ns() - pstore_started
        metrics = {
            "attempts": attempt, "retry": attempt - 1, "slot_count": m,
            "load_factor": u / float(m), "position_ns": position_ns,
            "peeling_ns": peel_ns, "retry_ns": retry_ns,
            "assignment_ns": assignment_ns, "pstore_build_ns": pstore_ns,
            "total_ns": perf_counter_ns() - started_total,
        }
        # token_to_j, entries, checks, payloads and graph objects leave scope here.
        return cls(metadata, slots, pstore, metrics)

    def query(self, token, ctx):
        metrics = {"retrieval_ns": 0, "short_check_ns": 0, "pstore_aead_ns": 0,
                   "posting_decode_ns": 0, "total_ns": 0}
        total_started = perf_counter_ns()
        try:
            meta = self.metadata
            if (meta["profile"] != PROFILE or meta["m"] != len(self.slots) or
                    meta["u"] != len(self.pstore) or meta["payload_width"] != PAYLOAD_BYTES or
                    meta["check_width"] != CHECK_BYTES or
                    not ct_equal(meta["ctx_digest"], hashlib.sha256(ctx).digest())):
                raise ValueError("metadata")
            started = perf_counter_ns()
            p0, p1, p2 = positions(meta["seed"], token, meta["segment_length"])
            payload = _xor(_xor(self.slots[p0], self.slots[p1]), self.slots[p2])
            metrics["retrieval_ns"] = perf_counter_ns() - started
            started = perf_counter_ns()
            j = struct.unpack(">I", payload[:4])[0]
            expected = hashlib.sha256(encode([
                "FX-check", ctx, token, j, meta["seed"],
            ])).digest()[:CHECK_BYTES]
            if j >= meta["u"] or not ct_equal(payload[4:], expected):
                metrics["short_check_ns"] = perf_counter_ns() - started
                metrics["total_ns"] = perf_counter_ns() - total_started
                return FXQueryResult(False, reason="short-check/range", metrics=metrics)
            metrics["short_check_ns"] = perf_counter_ns() - started
            started = perf_counter_ns()
            key = kdf("FX53-POSTKEY", ctx, token, meta["seed"])
            aad = encode(["FXABE05.3/PSTORE", ctx, j, meta])
            plaintext = open_seal(key, self.pstore[j], aad)
            metrics["pstore_aead_ns"] = perf_counter_ns() - started
            if plaintext is None:
                metrics["total_ns"] = perf_counter_ns() - total_started
                return FXQueryResult(False, reason="aead", metrics=metrics)
            started = perf_counter_ns()
            rows = decode_posting(plaintext, meta["ell"])
            metrics["posting_decode_ns"] = perf_counter_ns() - started
            metrics["total_ns"] = perf_counter_ns() - total_started
            return FXQueryResult(True, rows, "hit", metrics)
        except Exception:
            metrics["total_ns"] = perf_counter_ns() - total_started
            return FXQueryResult(False, reason="malformed", metrics=metrics)

    def accounting(self):
        metadata_bytes = len(encode(self.metadata))
        slot_bytes = len(self.slots) * PAYLOAD_BYTES
        nonce_bytes = sum(len(r["nonce"]) for r in self.pstore)
        ciphertext_bytes = sum(len(r["ciphertext"]) for r in self.pstore)
        tag_bytes = 16 * len(self.pstore)
        posting_payload_bytes = ciphertext_bytes - tag_bytes
        return {
            "FX_slot_bytes": slot_bytes,
            "FX_metadata_bytes": metadata_bytes,
            "PStore_ciphertext_bytes": ciphertext_bytes,
            "PStore_nonce_bytes": nonce_bytes,
            "PStore_tag_bytes": tag_bytes,
            "posting_payload_bytes": posting_payload_bytes,
            "FX_PStore_serialized_bytes": slot_bytes + metadata_bytes + nonce_bytes + ciphertext_bytes,
        }

    def has_exact_locator(self):
        forbidden = {"ids", "locator", "token_to_j", "token_map", "entries", "tokens"}
        return bool(forbidden & set(self.metadata)) or any(
            isinstance(x, dict) and forbidden & set(x) for x in self.pstore
        )
