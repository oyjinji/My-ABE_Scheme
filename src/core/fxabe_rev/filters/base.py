"""Common retrieval contract, exact locator adapter and encrypted PStore."""

import abc
import hashlib
import math
from dataclasses import dataclass, field
from time import perf_counter_ns

from ..crypto_utils import aead_decrypt, aead_encrypt, kdf, random_bytes
from ..encoding import decode_posting_list, encode, encode_posting_list


@dataclass
class QueryResult:
    hit: bool
    posting_list: tuple = ()
    reason: str = "miss"
    metrics: dict = field(default_factory=dict)


class AnonymousIndex(abc.ABC):
    """All implementations retrieve authenticated postings, never bare booleans."""

    name = "abstract"

    def __init__(self, **options):
        self.options = options
        self.state = None
        self._stats = {}

    @abc.abstractmethod
    def build(self, token_to_posting_list, context, rng):
        raise NotImplementedError

    @abc.abstractmethod
    def query(self, token, context):
        """Return a QueryResult hit(posting_list) or miss."""
        raise NotImplementedError

    @abc.abstractmethod
    def filter_only_size_bytes(self):
        raise NotImplementedError

    def serialized_size_bytes(self):
        return sum(self.size_breakdown().values())

    def stats(self):
        return dict(self._stats)

    def size_breakdown(self):
        return {
            "filter_only_bytes": self.filter_only_size_bytes(),
            "locator_bytes": 0,
            "pstore_bytes": pstore_size(self.state["pstore"]),
            "metadata_bytes": len(encode(self._metadata())),
        }

    def _metadata(self):
        return {"name": self.name, "context_digest": self.state["context_digest"]}


def validate_entries(entries):
    if not isinstance(entries, dict) or not entries:
        raise ValueError("anonymous index requires a nonempty token mapping")
    normalized = {}
    for token, rows in entries.items():
        if not isinstance(token, bytes):
            raise TypeError("tokens must be serialized bytes")
        rows = tuple(rows)
        if not rows or rows != tuple(sorted(rows)) or len(rows) != len(set(rows)):
            raise ValueError("posting lists must be nonempty, sorted and unique")
        normalized[token] = rows
    return normalized


def plan_pstore(entries, rng):
    """Choose the per-ciphertext compact random identifiers without AEAD."""
    tokens = list(entries)
    rng.shuffle(tokens)
    ids = {token: i for i, token in enumerate(tokens)}
    ell = max(max(rows) for rows in entries.values())
    return {"ids": ids, "ell": ell, "u": len(tokens)}


def build_pstore(entries, context, rng, layout=None, fx_seed=None):
    """Materialize PStore exactly once.

    FX-ABF passes its successful seed, so no KDF/AEAD work occurs for failed
    attempts. Membership baselines omit ``fx_seed`` and receive a random salt.
    """
    started = perf_counter_ns()
    layout = plan_pstore(entries, rng) if layout is None else layout
    ids = layout["ids"]
    ell = layout["ell"]
    u = layout["u"]
    salt = bytes(fx_seed) if fx_seed is not None else random_bytes(rng, 16)
    records = [None] * u
    for token, identifier in ids.items():
        key = posting_key(context, token, salt)
        aad = posting_ad(context, u, ell, identifier)
        records[identifier] = aead_encrypt(
            key, encode_posting_list(entries[token]), aad, random_bytes(rng, 12)
        )
    return {
        "ids": ids, "records": records, "ell": ell, "u": u,
        "salt": salt, "context_digest": hashlib.sha256(context).digest(),
    }, perf_counter_ns() - started


def posting_key(context, token, salt):
    return kdf("FXABF-Posting-Key", context, token, salt)


def posting_ad(context, u, ell, identifier):
    # revocation_epoch is deliberately absent.
    return encode(["FXABF-Posting-AD", "1", context, int(u), int(ell), int(identifier)])


def open_pstore(pstore, token, identifier, context):
    rows, metrics, attempts = open_pstore_profiled(
        pstore, token, identifier, context
    )
    return rows, (
        metrics["pstore_kdf_ns"] + metrics["pstore_aead_ns"] +
        metrics["posting_decode_ns"]
    ), attempts


def open_pstore_profiled(pstore, token, identifier, context):
    """Open one posting record with non-overlapping phase timings."""
    metrics = {
        "pstore_kdf_ns": 0,
        "pstore_aead_ns": 0,
        "posting_decode_ns": 0,
    }
    started = perf_counter_ns()
    try:
        if hashlib.sha256(context).digest() != pstore["context_digest"]:
            metrics["pstore_kdf_ns"] = perf_counter_ns() - started
            return None, metrics, 0
        if identifier < 0 or identifier >= pstore["u"]:
            metrics["pstore_kdf_ns"] = perf_counter_ns() - started
            return None, metrics, 0
        key = posting_key(context, token, pstore["salt"])
        metrics["pstore_kdf_ns"] = perf_counter_ns() - started
        started = perf_counter_ns()
        aad = posting_ad(context, pstore["u"], pstore["ell"], identifier)
        plaintext = aead_decrypt(key, pstore["records"][identifier], aad)
        metrics["pstore_aead_ns"] = perf_counter_ns() - started
        if plaintext is None:
            return None, metrics, 1
        started = perf_counter_ns()
        rows = decode_posting_list(plaintext, pstore["ell"])
        metrics["posting_decode_ns"] = perf_counter_ns() - started
        return rows, metrics, 1
    except Exception:
        return None, metrics, 1


def pstore_size(pstore):
    return sum(len(record["nonce"]) + len(record["ciphertext"])
               for record in pstore["records"])


def locator_digest(context, token):
    return hashlib.sha256(encode(["Anonymous-Exact-Locator-v1", context, token])).digest()


def build_locator(pstore, context):
    started = perf_counter_ns()
    locator = {locator_digest(context, token): identifier
               for token, identifier in pstore["ids"].items()}
    return locator, perf_counter_ns() - started


def locator_size(locator, u):
    width = max(1, math.ceil(max(1, u).bit_length() / 8))
    return sum(len(key) + width for key in locator)


def locator_query(locator, token, context):
    return locator.get(locator_digest(context, token))


def profiled_locator_query(locator, token, context):
    started = perf_counter_ns()
    identifier = locator_query(locator, token, context)
    return identifier, perf_counter_ns() - started


def empty_query_metrics():
    return {
        "membership_or_retrieval_ns": 0,
        "locator_lookup_ns": 0,
        "pstore_kdf_ns": 0,
        "pstore_aead_ns": 0,
        "posting_decode_ns": 0,
        "integrated_index_query_ns": 0,
        # Compatibility aggregates used by the Transform implementation.
        "index_query_ns": 0,
        "pstore_processing_ns": 0,
        "filter_candidate_positive_count": 0,
        "locator_attempt_count": 0,
        "pstore_aead_attempt_count": 0,
        "pstore_aead_reject_count": 0,
    }


def finalize_query_metrics(metrics):
    metrics["index_query_ns"] = (
        metrics["membership_or_retrieval_ns"] + metrics["locator_lookup_ns"]
    )
    metrics["pstore_processing_ns"] = (
        metrics["pstore_kdf_ns"] + metrics["pstore_aead_ns"] +
        metrics["posting_decode_ns"]
    )
    metrics["integrated_index_query_ns"] = (
        metrics["index_query_ns"] + metrics["pstore_processing_ns"]
    )
    return metrics


def finalize_build_stats(index, stats, total_started_ns):
    """Close build accounting with disjoint components equal to wall time.

    ``structure_build_ns`` is the wall-time remainder after the separately
    measured locator, PStore, and canonical metadata construction phases.  It
    therefore includes input validation, layout/payload preparation, retries,
    and the concrete filter/retrieval-structure construction.
    """
    started = perf_counter_ns()
    encode(index._metadata())
    metadata_ns = perf_counter_ns() - started
    total_ns = perf_counter_ns() - total_started_ns
    locator_ns = int(stats.get("locator_build_ns", 0))
    pstore_ns = int(stats.get("pstore_build_ns", 0))
    structure_ns = total_ns - locator_ns - pstore_ns - metadata_ns
    if structure_ns < 0:
        raise AssertionError("negative structure build phase")
    stats.update({
        "structure_build_ns": structure_ns,
        "metadata_build_ns": metadata_ns,
        "integrated_build_ns": total_ns,
        "build_total_ns": total_ns,
    })
    if int(stats.get("component_sum_ns", 0)) <= 0:
        stats["component_sum_ns"] = total_ns
        stats["timing_residual_ns"] = 0
    return stats


def common_size(index, filter_bytes, metadata):
    state = index.state
    locator = state.get("locator")
    return {
        "filter_only_bytes": int(filter_bytes),
        "locator_bytes": 0 if locator is None else locator_size(locator, state["pstore"]["u"]),
        "pstore_bytes": pstore_size(state["pstore"]),
        "metadata_bytes": len(encode(metadata)),
    }


def empty_build_stats():
    return {
        "success": True, "attempt_count": 1, "resize_count": 0,
        "final_capacity": 0, "position_generation_ns": 0,
        "peeling_or_insertion_ns": 0, "reverse_assignment_ns": 0,
        "locator_build_ns": 0, "pstore_build_ns": 0, "retry_ns": 0,
        "pstore_build_count": 1, "validation_ns": 0, "layout_ns": 0,
        "payload_ns": 0, "component_sum_ns": 0, "timing_residual_ns": 0,
        "structure_build_ns": 0, "metadata_build_ns": 0,
        "integrated_build_ns": 0,
        "build_total_ns": 0, "failure_reason": "", "attempts": [],
    }
