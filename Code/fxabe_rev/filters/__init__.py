"""Unified anonymous token-to-posting-list index implementations."""

from .base import AnonymousIndex, QueryResult
from .abf import ABFIndex, BloomLocatorIndex
from .cuckoo import CuckooIndex
from .xor_filter import XorIndex
from .fxabf import FXABFIndex
from .legacy_abf import LegacyABFIndex

FILTERS = {
    "Legacy ABF": LegacyABFIndex,
    "Bloom+Locator": BloomLocatorIndex,
    "Cuckoo+Locator": CuckooIndex,
    "Xor+Locator": XorIndex,
    "FX-ABF": FXABFIndex,
}

FILTER_ALIASES = {
    "ABF": "Bloom+Locator",
    "Original-ABF": "Legacy ABF",
    "Cuckoo": "Cuckoo+Locator",
    "Xor": "Xor+Locator",
}


def create_index(name, **options):
    try:
        return FILTERS[FILTER_ALIASES.get(name, name)](**options)
    except KeyError as exc:
        raise ValueError("unknown anonymous index %r" % name) from exc


__all__ = [
    "AnonymousIndex", "QueryResult", "ABFIndex", "BloomLocatorIndex",
    "CuckooIndex", "XorIndex", "FXABFIndex", "LegacyABFIndex", "FILTERS",
    "FILTER_ALIASES", "create_index",
]
