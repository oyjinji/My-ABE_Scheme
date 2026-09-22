from .attribute_bf_2018 import AttributeBFGreedy
from .bloom_pstore import BloomExactPStore
from .cuckoo_acf import CuckooACF
from .exact_hash import ExactHash
from .fxabf_fuse import FXABFFuse
from .linear_scan import LinearScan
from .original_abf import OriginalABF
from .xor_basic import XORRetrieval


BACKENDS = {
    backend.name: backend for backend in (
        LinearScan, ExactHash, BloomExactPStore, AttributeBFGreedy,
        OriginalABF, CuckooACF, XORRetrieval, FXABFFuse,
    )
}


def create_backends(names=None):
    names = names or list(BACKENDS)
    return [BACKENDS[name]() for name in names]


__all__ = ["create_backends", "BACKENDS"]
