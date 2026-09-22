import random

from experiments.index_v1.filters import create_backends
from experiments.index_v1.generators import nonmember_tokens, token_entries


def test_all_required_backends_share_interface_and_validate():
    entries = token_entries(16, 101)
    required = {
        "Linear Scan", "Exact Hash", "Bloom+Exact-PStore",
        "Attribute-BF (greedy)", "Original-ABF", "as-ACF/Cuckoo",
        "XOR-Retrieval", "FX-ABF",
    }
    backends = create_backends()
    assert {backend.name for backend in backends} == required
    for backend in backends:
        index = backend.build(entries, {"delta": 32, "r_max": 4}, random.Random(99))
        report = backend.validate(index, entries)
        assert report.valid and report.false_negatives == 0
        assert backend.serialized_size(index)["total_index_bytes"] > 0


def test_nonmembers_do_not_false_accept_in_fixed_workload():
    entries = token_entries(32, 102)
    misses = nonmember_tokens(50, 103)
    for backend in create_backends():
        index = backend.build(entries, {"delta": 32, "r_max": 4}, random.Random(100))
        assert not any(backend.query(index, token).hit for token in misses)
