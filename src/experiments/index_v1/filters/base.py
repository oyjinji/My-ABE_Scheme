"""Uniform token-to-posting-list filter interface and shared PStore."""

import abc
import hashlib
from dataclasses import dataclass, field
from time import perf_counter_ns

from core.fxdacp.crypto_utils import aead_decrypt, aead_encrypt, kdf, random_bytes
from core.fxdacp.encoding import decode_posting_list, encode, encode_posting_list


@dataclass
class QueryResult:
    hit: bool
    posting_list: tuple = ()
    metrics: dict = field(default_factory=dict)
    reason: str = "miss"


@dataclass
class ValidationReport:
    valid: bool
    false_negatives: int
    errors: tuple = ()


class FilterBackend(abc.ABC):
    name = "abstract"

    @abc.abstractmethod
    def build(self, entries, config, rng):
        raise NotImplementedError

    @abc.abstractmethod
    def query(self, index, token):
        raise NotImplementedError

    @abc.abstractmethod
    def serialized_size(self, index):
        raise NotImplementedError

    def validate(self, index, entries):
        errors = []
        for token, expected in entries.items():
            result = self.query(index, token)
            if not result.hit or list(result.posting_list) != list(expected):
                errors.append(token.hex())
        return ValidationReport(not errors, len(errors), tuple(errors))


def token_digest(token):
    return hashlib.sha256(b"FXEXP-Token-v1" + token).digest()


def check_bytes(token, identifier, bits):
    digest = hashlib.sha256(encode(["FXEXP-Check-v1", token, identifier])).digest()
    value = int.from_bytes(digest, "big") >> (256 - bits)
    return value.to_bytes((bits + 7) // 8, "big")


def prepare_pstore(entries, rng, context=b"fx-exp", random_identifiers=True):
    tokens = sorted(entries)
    ordered = list(tokens)
    if random_identifiers:
        rng.shuffle(ordered)
    identifiers = {token: index for index, token in enumerate(ordered)}
    ell = max((max(rows) for rows in entries.values() if rows), default=0)
    records = [None] * len(tokens)
    encryption_ns = 0
    for token, identifier in identifiers.items():
        key = kdf("FXEXP-Posting-Key", context, token)
        aad = encode(["FXEXP-PStore-v1", context, identifier, ell])
        started = perf_counter_ns()
        records[identifier] = aead_encrypt(
            key, encode_posting_list(entries[token]), aad,
            random_bytes(rng, 12),
        )
        encryption_ns += perf_counter_ns() - started
    return {
        "records": records, "identifiers": identifiers, "ell": ell,
        "context": context, "encryption_ns": encryption_ns,
    }


def open_pstore(pstore, token, identifier):
    started = perf_counter_ns()
    try:
        if identifier < 0 or identifier >= len(pstore["records"]):
            return None, perf_counter_ns() - started, 0
        key = kdf("FXEXP-Posting-Key", pstore["context"], token)
        aad = encode([
            "FXEXP-PStore-v1", pstore["context"], identifier, pstore["ell"],
        ])
        plaintext = aead_decrypt(key, pstore["records"][identifier], aad)
        if plaintext is None:
            return None, perf_counter_ns() - started, 1
        return tuple(decode_posting_list(plaintext, pstore["ell"])), perf_counter_ns() - started, 1
    except Exception:
        return None, perf_counter_ns() - started, 1


def pstore_size(pstore):
    return sum(len(record["nonce"]) + len(record["ciphertext"])
               for record in pstore["records"])


def size_result(filter_bytes, pstore, metadata):
    p_bytes = pstore_size(pstore)
    metadata_bytes = len(encode(metadata))
    return {
        "filter_bytes": int(filter_bytes), "pstore_bytes": p_bytes,
        "metadata_bytes": metadata_bytes,
        "total_index_bytes": int(filter_bytes) + p_bytes + metadata_bytes,
    }
