import copy
import random

from core.fxdacp.fxabf import FXABF, FXABFIndex, SegmentMeta, fuse_positions, plan_segments


def entries(count=32):
    return {(b"token-%03d" % index): [index + 1] for index in range(count)}


def test_member_queries_have_no_false_negatives():
    builder = FXABFIndex(rng=random.Random(9))
    source = entries()
    index, _, _ = builder.build(source, b"context", len(source))
    for token, rows in source.items():
        result = builder.query(index, token, b"context")
        assert result.hit and list(result.posting_list) == rows


def test_nonmember_is_a_miss():
    builder = FXABFIndex(rng=random.Random(10))
    index, _, _ = builder.build(entries(), b"context", 32)
    assert not builder.query(index, b"not-a-member", b"context").hit


def test_seed_retry_is_recorded():
    core = FXABF(rng=random.Random(11), r_max=4)
    original = core._peel
    calls = {"count": 0}

    def fail_once(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            return None, {}
        return original(*args, **kwargs)

    core._peel = fail_once
    _, stats = core.build_values({b"a": 1, b"b": 2, b"c": 3}, 3)
    assert stats.retries >= 1 and not stats.first_attempt_success


def test_small_m_forces_expansion():
    core = FXABF(c_fx=1.01, r_max=1, gamma=1.5, rng=random.Random(12))
    values = {b"k-%02d" % i: i for i in range(12)}
    index, stats = core.build_values(values, 4, initial_m=3)
    assert stats.expansions > 0 and index["m"] > 3


def test_fixed_seed_rng_is_reproducible():
    values = {b"a": 1, b"b": 2, b"c": 3}
    first, _ = FXABF(rng=random.Random(13)).build_values(values, 3)
    second, _ = FXABF(rng=random.Random(13)).build_values(values, 3)
    assert first == second


def test_fuse_positions_are_deterministic_distinct_and_in_range():
    for m in (3, 4, 17, 129):
        meta = plan_segments(m, 32)
        first = fuse_positions(b"s" * 16, b"token", m, meta)
        second = fuse_positions(b"s" * 16, b"token", m, meta)
        assert first == second and len(set(first)) == 3
        assert all(0 <= value < m for value in first)
        segments = [value // meta.segment_length for value in first]
        assert segments == list(range(segments[0], segments[0] + 3))


def test_tampered_pstore_ciphertext_is_rejected():
    builder = FXABFIndex(rng=random.Random(14))
    index, _, _ = builder.build({b"member": [1]}, b"ctx", 1)
    damaged = copy.deepcopy(index)
    ciphertext = bytearray(damaged["pstore"][0]["ciphertext"])
    ciphertext[-1] ^= 1
    damaged["pstore"][0]["ciphertext"] = bytes(ciphertext)
    assert not builder.query(damaged, b"member", b"ctx").hit
