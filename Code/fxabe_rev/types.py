"""Typed metric containers used by the scheme and experiments."""

from dataclasses import dataclass, asdict


@dataclass
class TransformMetrics:
    metadata_validation_ns: int = 0
    membership_or_retrieval_ns: int = 0
    locator_lookup_ns: int = 0
    pstore_kdf_ns: int = 0
    pstore_aead_ns: int = 0
    posting_decode_ns: int = 0
    integrated_index_query_ns: int = 0
    index_query_ns: int = 0
    pstore_processing_ns: int = 0
    path_cover_lookup_ns: int = 0
    revocation_pairing_ns: int = 0
    row_pairing_ns: int = 0
    core_transform_ns: int = 0
    transform_total_ns: int = 0
    pairing_count: int = 0
    r: int = 0
    status: str = "unset"

    def as_dict(self):
        return asdict(self)
