import random

from Code.fxabe_rev.filters import FILTERS


def test_five_indexes_return_same_postings_and_exact_query_sum():
    entries = {
        b"alpha": [1, 4],
        b"beta": [2],
        b"gamma": [3, 5],
    }
    observed = {}
    for offset, (name, cls) in enumerate(FILTERS.items()):
        index = cls().build(entries, b"same-context", random.Random(300 + offset))
        observed[name] = {
            token: index.query(token, b"same-context").posting_list
            for token in entries
        }
        for token in entries:
            metrics = index.query(token, b"same-context").metrics
            assert metrics["integrated_index_query_ns"] == sum(
                metrics[field] for field in (
                    "membership_or_retrieval_ns", "locator_lookup_ns",
                    "pstore_kdf_ns", "pstore_aead_ns", "posting_decode_ns",
                )
            )
        sizes = index.size_breakdown()
        assert index.serialized_size_bytes() == sum(sizes.values())
    expected = {token: tuple(rows) for token, rows in entries.items()}
    assert all(postings == expected for postings in observed.values())
