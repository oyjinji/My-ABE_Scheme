import random

from core.fxabe_rev.filters import FILTERS, AnonymousIndex


def test_all_filters_share_retrieval_contract():
    entries = {b"token-%02d" % i: [i + 1] for i in range(32)}
    for offset, (name, cls) in enumerate(FILTERS.items()):
        index = cls().build(entries, b"context", random.Random(100 + offset))
        assert isinstance(index, AnonymousIndex)
        for token, posting in entries.items():
            result = index.query(token, b"context")
            assert result.hit and list(result.posting_list) == posting
        sizes = index.size_breakdown()
        assert set(sizes) == {
            "filter_only_bytes", "locator_bytes", "pstore_bytes", "metadata_bytes"
        }
        assert index.serialized_size_bytes() == sum(sizes.values())
        if name in ("Legacy ABF", "FX-ABF"):
            assert sizes["locator_bytes"] == 0
        else:
            assert sizes["locator_bytes"] > 0
        result = index.query(next(iter(entries)), b"context")
        components = sum(result.metrics[key] for key in (
            "membership_or_retrieval_ns", "locator_lookup_ns",
            "pstore_kdf_ns", "pstore_aead_ns", "posting_decode_ns",
        ))
        assert result.metrics["integrated_index_query_ns"] == components
        if name in ("Legacy ABF", "FX-ABF"):
            assert result.metrics["locator_lookup_ns"] == 0
