"""Two-bucket Cuckoo table storing fingerprint plus complete payload."""

import math
from time import perf_counter_ns

from .base import (
    BuildFailure, RetrievalResult, StaticRetrieval, sha256_domain,
    validate_value,
)


class CuckooPayloadRetrieval(StaticRetrieval):
    name = "Cuckoo payload table"
    type_id = "cuckoo-payload-v1"

    def __init__(self, delta=64, bucket_size=4, fingerprint_bits=16,
                 target_load=0.92, max_kicks=500,
                 attempts_before_resize=4, max_resizes=12, **options):
        super().__init__(delta=delta, **options)
        self.bucket_size = int(bucket_size)
        self.fingerprint_bits = int(fingerprint_bits)
        self.target_load = float(target_load)
        self.max_kicks = int(max_kicks)
        self.attempts_before_resize = int(attempts_before_resize)
        self.max_resizes = int(max_resizes)

    @property
    def fingerprint_width(self):
        return (self.fingerprint_bits + 7) // 8

    def _fingerprint(self, token):
        value = int.from_bytes(
            sha256_domain("Cuckoo-Payload-Fingerprint-v1", token), "big"
        ) & ((1 << self.fingerprint_bits) - 1)
        return value or 1

    def _bucket_pair(self, seed, token, fingerprint, bucket_count):
        mask = bucket_count - 1
        first = int.from_bytes(sha256_domain(
            "Cuckoo-Payload-Bucket-v1", seed, token
        )[:8], "big") & mask
        delta = int.from_bytes(sha256_domain(
            "Cuckoo-Payload-Alternate-v1", fingerprint
        )[:8], "big") & mask
        return first, first ^ delta

    def build(self, mapping, rng=None):
        total_started = perf_counter_ns()
        rng = self._rng(rng)
        items, u, b_j, width = self._validate_mapping(mapping)
        requested = max(
            2, math.ceil(u / (self.bucket_size * self.target_load))
        )
        bucket_count = 1 << (requested - 1).bit_length()
        attempts = resizes = kicks = position_ns = insertion_ns = 0
        while resizes <= self.max_resizes:
            for _ in range(self.attempts_before_resize):
                attempts += 1
                seed = rng.getrandbits(128).to_bytes(16, "big")
                buckets = [
                    [None] * self.bucket_size for _ in range(bucket_count)
                ]
                failed = False
                for token, value in items:
                    started = perf_counter_ns()
                    fingerprint = self._fingerprint(token)
                    first, second = self._bucket_pair(
                        seed, token, fingerprint, bucket_count
                    )
                    position_ns += perf_counter_ns() - started
                    record = (
                        fingerprint.to_bytes(self.fingerprint_width, "big") +
                        value
                    )
                    started = perf_counter_ns()
                    target = first
                    if all(slot is not None for slot in buckets[target]):
                        target = second
                    if any(slot is None for slot in buckets[target]):
                        slot = buckets[target].index(None)
                        buckets[target][slot] = record
                        insertion_ns += perf_counter_ns() - started
                        continue
                    target = first if rng.randrange(2) == 0 else second
                    current = record
                    for _kick in range(self.max_kicks):
                        kicks += 1
                        slot = rng.randrange(self.bucket_size)
                        buckets[target][slot], current = (
                            current, buckets[target][slot]
                        )
                        current_fp = int.from_bytes(
                            current[:self.fingerprint_width], "big"
                        )
                        alternate = int.from_bytes(sha256_domain(
                            "Cuckoo-Payload-Alternate-v1", current_fp
                        )[:8], "big") & (bucket_count - 1)
                        target ^= alternate
                        empty = next(
                            (i for i, value_at_slot in enumerate(buckets[target])
                             if value_at_slot is None), None
                        )
                        if empty is not None:
                            buckets[target][empty] = current
                            current = None
                            break
                    insertion_ns += perf_counter_ns() - started
                    if current is not None:
                        failed = True
                        break
                if failed:
                    continue
                self.u = u
                self.b_j = b_j
                self.value_width = width
                self.bucket_count = bucket_count
                self.capacity = bucket_count * self.bucket_size
                self.seed = seed
                self.buckets = buckets
                self._stats = {
                    "success": True,
                    "build_total_ns": perf_counter_ns() - total_started,
                    "position_hash_ns": position_ns,
                    "peeling_or_insertion_ns": insertion_ns,
                    "assignment_ns": 0,
                    "attempt_count": attempts,
                    "resize_count": resizes,
                    "final_capacity": self.capacity,
                    "load_factor": u / float(self.capacity),
                    "kick_count": kicks,
                    "bucket_count": bucket_count,
                    "bucket_size": self.bucket_size,
                    "fingerprint_bits": self.fingerprint_bits,
                    "payload_bits": b_j + self.delta,
                }
                return self
            resizes += 1
            bucket_count *= 2
        stats = {
            "success": False,
            "build_total_ns": perf_counter_ns() - total_started,
            "position_hash_ns": position_ns,
            "peeling_or_insertion_ns": insertion_ns,
            "assignment_ns": 0,
            "attempt_count": attempts,
            "resize_count": resizes,
            "final_capacity": bucket_count * self.bucket_size,
            "load_factor": u / float(bucket_count * self.bucket_size),
            "kick_count": kicks,
        }
        raise BuildFailure("cuckoo payload insertion failed", stats)

    def query(self, token):
        started = perf_counter_ns()
        fingerprint = self._fingerprint(token)
        first, second = self._bucket_pair(
            self.seed, token, fingerprint, self.bucket_count
        )
        fingerprint_bytes = fingerprint.to_bytes(
            self.fingerprint_width, "big"
        )
        reads = 0
        check_count = 0
        for bucket in (first, second):
            for record in self.buckets[bucket]:
                reads += 1
                if record is None or not record.startswith(fingerprint_bytes):
                    continue
                value = record[self.fingerprint_width:]
                check_count += 1
                if validate_value(token, value, self.b_j, self.delta):
                    return RetrievalResult(
                        True, value, "hit",
                        {
                            "query_ns": perf_counter_ns() - started,
                            "hash_count": 3 + check_count,
                            "array_reads": reads,
                            "xor_count": 0,
                            "temporary_allocations": 9,
                        },
                    )
        return RetrievalResult(
            False, b"", "fingerprint",
            {
                "query_ns": perf_counter_ns() - started,
                "hash_count": 3 + check_count,
                "array_reads": reads,
                "xor_count": 0,
                "temporary_allocations": 7,
            },
        )

    def _functional_metadata(self):
        return {
            **super()._functional_metadata(),
            "capacity": self.capacity,
            "seed": self.seed.hex(),
            "bucket_count": self.bucket_count,
            "bucket_size": self.bucket_size,
            "fingerprint_bits": self.fingerprint_bits,
            "target_load": self.target_load,
        }

    def _structure_bytes(self):
        record_width = self.fingerprint_width + self.value_width
        empty = bytes(record_width)
        parts = []
        for bucket in self.buckets:
            for record in bucket:
                parts.append(b"\1" + record if record is not None else b"\0" + empty)
        return b"".join(parts)

    def _load_structure_bytes(self, metadata, body):
        self.capacity = int(metadata["capacity"])
        self.seed = bytes.fromhex(metadata["seed"])
        self.bucket_count = int(metadata["bucket_count"])
        self.bucket_size = int(metadata["bucket_size"])
        self.fingerprint_bits = int(metadata["fingerprint_bits"])
        self.target_load = float(metadata["target_load"])
        record_width = 1 + self.fingerprint_width + self.value_width
        if len(body) != self.capacity * record_width:
            raise ValueError("malformed cuckoo payload table")
        self.buckets = []
        offset = 0
        for _ in range(self.bucket_count):
            bucket = []
            for _ in range(self.bucket_size):
                occupied = body[offset]
                record = body[offset + 1:offset + record_width]
                if occupied not in (0, 1):
                    raise ValueError("invalid cuckoo occupancy marker")
                bucket.append(record if occupied else None)
                offset += record_width
            self.buckets.append(bucket)

    def space_stats(self):
        sizes = self.size_breakdown()
        slot_width = 1 + self.fingerprint_width + self.value_width
        return {
            **sizes,
            "bytes_per_key": sizes["serialized_bytes"] / float(self.u),
            "payload_bits_per_key": self.b_j + self.delta,
            "unused_capacity_bytes": (self.capacity - self.u) * slot_width,
        }
