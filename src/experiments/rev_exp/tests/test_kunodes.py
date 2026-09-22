import random

from core.fxabe_rev.revocation import BinaryRevocationTree
from experiments.rev_exp.src.revocation import kunodes


def _registered(count, capacity=64):
    tree = BinaryRevocationTree(capacity)
    for index in range(count):
        tree.register("u%d" % index)
    return tree


def test_c1_no_revocation_cover_is_root():
    tree = _registered(19)
    assert kunodes(tree, 1) == (1,)


def test_c2_random_partial_revocation_has_exact_intersections():
    for seed in range(10):
        tree = _registered(37)
        revoked = set(random.Random(seed).sample(range(37), 11))
        for index in revoked:
            tree.revoke("u%d" % index, 2)
        cover = set(kunodes(tree, 2))
        for index in range(37):
            intersection = set(tree.path("u%d" % index)) & cover
            assert len(intersection) == (0 if index in revoked else 1)


def test_c3_all_registered_revoked_is_empty_and_unassigned_are_irrelevant():
    tree = _registered(13, capacity=64)
    for index in range(13):
        tree.revoke("u%d" % index, 3)
    assert kunodes(tree, 3) == ()


def test_empty_tree_has_empty_cover():
    assert kunodes(BinaryRevocationTree(8), 1) == ()

