import copy
import random
import struct

from Code.fxabe_rev.crypto_utils import aead_encrypt
from Code.fxabe_rev.filters import FILTERS, create_index
from Code.fxabe_rev.filters.base import posting_ad, posting_key
from Code.fxabe_rev.filters.fxabf import FXABFIndex, plan_segments


def test_members_never_false_negative_and_nonmembers_never_final_accept():
    entries = {b"member-%03d" % i: [i + 1] for i in range(64)}
    for offset, cls in enumerate(FILTERS.values()):
        index = cls().build(entries, b"ctx", random.Random(20 + offset))
        assert all(index.query(token, b"ctx").hit for token in entries)
        assert all(not index.query(b"absent-%03d" % i, b"ctx").hit for i in range(500))


def test_pstore_tampering_is_a_miss():
    token = b"member"
    for offset, cls in enumerate(FILTERS.values()):
        index = cls().build({token: [1]}, b"ctx", random.Random(30 + offset))
        damaged = copy.deepcopy(index)
        identifier = damaged.state["pstore"]["ids"][token]
        record = damaged.state["pstore"]["records"][identifier]
        ciphertext = bytearray(record["ciphertext"])
        ciphertext[-1] ^= 1
        record["ciphertext"] = bytes(ciphertext)
        assert not damaged.query(token, b"ctx").hit


def test_noncanonical_posting_list_is_a_miss():
    token, context = b"member", b"ctx"
    for offset, cls in enumerate(FILTERS.values()):
        index = cls().build({token: [1, 2]}, context, random.Random(40 + offset))
        identifier = index.state["pstore"]["ids"][token]
        pstore = index.state["pstore"]
        malformed = struct.pack(">III", 2, 2, 1)
        record = pstore["records"][identifier]
        pstore["records"][identifier] = aead_encrypt(
            posting_key(context, token, pstore["salt"]), malformed,
            posting_ad(context, pstore["u"], pstore["ell"], identifier),
            record["nonce"],
        )
        assert not index.query(token, context).hit


def test_fxabf_builds_pstore_once_after_successful_seed():
    entries = {b"token-%03d" % i: [i + 1] for i in range(128)}
    index = FXABFIndex().build(entries, b"ctx", random.Random(77))
    stats = index.stats()
    assert stats["pstore_build_count"] == 1
    assert index.state["pstore"]["salt"] == index.state["seed"]
    assert len(stats["attempts"]) == stats["attempt_count"]
    assert sum(row["attempt_success"] for row in stats["attempts"]) == 1
    assert stats["attempts"][-1]["attempt_success"]


def test_adaptive_segment_profile_avoids_fixed_64_window_growth():
    small = plan_segments(10650, 64)
    large = plan_segments(21300, 64)
    assert (small.segment_length, small.segment_count) == (512, 21)
    assert (large.segment_length, large.segment_count) == (1024, 21)


def test_legacy_abf_is_greedy_direct_retrieval_not_bloom_alias():
    legacy = create_index("Legacy ABF")
    bloom = create_index("ABF")
    assert legacy.name == "Legacy ABF"
    assert bloom.name == "Bloom+Locator"
    assert legacy.__class__ is not bloom.__class__
    entries = {b"a": [1, 3], b"b": [2]}
    legacy.build(entries, b"ctx", random.Random(91))
    assert legacy.size_breakdown()["locator_bytes"] == 0
    assert {
        token: legacy.query(token, b"ctx").posting_list for token in entries
    } == {token: tuple(rows) for token, rows in entries.items()}
