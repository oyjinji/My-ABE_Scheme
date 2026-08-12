"""Low-overhead metrics helpers and typed FX-ABF statistics."""

from dataclasses import dataclass, field
from time import perf_counter_ns


@dataclass
class FXABFBuildStats:
    first_attempt_success: bool = False
    retries: int = 0
    expansions: int = 0
    initial_m: int = 0
    final_m: int = 0
    peeling_ns: int = 0
    assignment_ns: int = 0
    total_ns: int = 0


@dataclass
class FXABFQueryStats:
    position_ns: int = 0
    slot_read_ns: int = 0
    xor_ns: int = 0
    range_check_ns: int = 0
    short_check_ns: int = 0
    pstore_ns: int = 0
    posting_decode_ns: int = 0
    slot_reads: int = 0
    aead_attempts: int = 0
    aead_successes: int = 0
    outcome: str = "miss"


@dataclass
class OperationMetrics:
    values: dict = field(default_factory=dict)

    def add(self, name, amount=1):
        self.values[name] = self.values.get(name, 0) + amount

    def set(self, name, value):
        self.values[name] = value

    def as_dict(self):
        return dict(self.values)


class Timer:
    def __enter__(self):
        self.started = perf_counter_ns()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.elapsed_ns = perf_counter_ns() - self.started
