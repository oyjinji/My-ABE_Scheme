"""Instrumented tree-cover and real KU generation used only by Rev_Exp."""

import bisect
import struct
from dataclasses import dataclass, asdict
from time import perf_counter_ns


@dataclass
class RevKeyMetrics:
    kunodes_ns: int
    ku_crypto_ns: int
    total_ns: int
    cover_size: int
    ku_g2_elements: int
    ku_metadata_bytes: int
    ku_serialized_bytes: int
    cover_invariant_valid: bool

    def as_dict(self):
        return asdict(self)


def kunodes(tree, epoch):
    """Minimal cover of registered live leaves, without scanning subtrees.

    FABEO assigns leaves from left to right.  Bisect counts revoked leaves in a
    node interval, giving O(output + r log n) traversal while preserving the
    project's no-revocation root special case and ignoring unregistered leaves.
    """
    registered = int(tree.next_leaf)
    if registered == 0:
        return ()
    revoked = sorted(tree.revoked_leaves(int(epoch)))
    if not revoked:
        return (1,)
    if len(revoked) >= registered:
        return ()

    assigned_lo = tree.leaf_base
    assigned_hi = assigned_lo + registered
    cover = []

    def count_revoked(lo, hi):
        return bisect.bisect_left(revoked, hi) - bisect.bisect_left(revoked, lo)

    def visit(node, lo, hi):
        active_lo = max(lo, assigned_lo)
        active_hi = min(hi, assigned_hi)
        if active_lo >= active_hi:
            return
        assigned_count = active_hi - active_lo
        revoked_count = count_revoked(active_lo, active_hi)
        if revoked_count == assigned_count:
            return
        if revoked_count == 0:
            cover.append(node)
            return
        mid = (lo + hi) // 2
        visit(node * 2, lo, mid)
        visit(node * 2 + 1, mid, hi)

    visit(1, tree.leaf_base, tree.leaf_base + tree.leaf_count)
    return tuple(cover)


def serialize_ku(ku, group):
    """Fixed binary wire encoding for KU communication-size accounting.

    Header: magic(6), version length(2), version, epoch(8), component count(8).
    Each component: node label(8), then two length-prefixed canonical Charm G2
    serializations.  Dictionary/Python object overhead is deliberately absent.
    """
    version = str(ku["version"]).encode("utf-8")
    header = b"RKU001" + struct.pack(">H", len(version)) + version
    header += struct.pack(">QQ", int(ku["epoch"]), len(ku["cover"]))
    parts = [header]
    for node in sorted(ku["cover"]):
        update = ku["cover"][node]
        u0 = group.serialize(update["U0"])
        u1 = group.serialize(update["U1"])
        parts.append(struct.pack(">QI", int(node), len(u0)))
        parts.append(u0)
        parts.append(struct.pack(">I", len(u1)))
        parts.append(u1)
    return b"".join(parts), len(header)


def validate_cover(tree, epoch, cover):
    """Validate the cover as disjoint live-leaf intervals in O(|Cover|+r)."""
    assigned_lo = tree.leaf_base
    assigned_hi = assigned_lo + int(tree.next_leaf)
    intervals = []
    for node in cover:
        depth = int(node).bit_length() - 1
        width = tree.leaf_count >> depth
        offset = int(node) - (1 << depth)
        lo = tree.leaf_base + offset * width
        hi = lo + width
        intervals.append((max(lo, assigned_lo), min(hi, assigned_hi)))
    intervals = sorted((lo, hi) for lo, hi in intervals if lo < hi)
    if any(left[1] > right[0] for left, right in zip(intervals, intervals[1:])):
        return False
    revoked = tree.revoked_leaves(epoch)
    if any(lo <= leaf < hi for lo, hi in intervals for leaf in revoked):
        return False
    covered = sum(hi - lo for lo, hi in intervals)
    return covered == int(tree.next_leaf) - len(revoked)


def measured_rev_key_upt(scheme, pp, revocation_epoch):
    """Publish a frozen KU while timing cover and genuine G2 operations."""
    scheme._require_state()
    epoch = int(revocation_epoch)
    if epoch in scheme.state["ku"]:
        raise ValueError("benchmark requires a fresh revocation epoch")
    latest = scheme.state["latest_revocation_epoch"]
    if latest is not None and epoch <= latest:
        raise ValueError("revocation epochs must be published monotonically")

    total_started = perf_counter_ns()
    started = perf_counter_ns()
    cover = kunodes(scheme.state["tree"], epoch)
    kunodes_ns = perf_counter_ns() - started

    started = perf_counter_ns()
    h_r = scheme._epoch_scalar(epoch)
    updates = {}
    for node in cover:
        beta = scheme._node_secret(node)
        q = scheme.scalar_source.scalar()
        updates[node] = {
            "U0": pp["g2"] ** (beta + h_r * q),
            "U1": pp["g2"] ** q,
        }
    ku_crypto_ns = perf_counter_ns() - started
    ku = {"epoch": epoch, "version": pp["version"], "cover": updates}
    scheme.state["ku"][epoch] = ku
    scheme.state["tree"].published[epoch] = tuple(cover)
    scheme.state["latest_revocation_epoch"] = epoch
    total_ns = perf_counter_ns() - total_started
    invariant_valid = validate_cover(scheme.state["tree"], epoch, cover)
    if not invariant_valid:
        raise AssertionError("Path/Cover invariant failed")
    wire, metadata_bytes = serialize_ku(ku, scheme.group)
    return ku, RevKeyMetrics(
        kunodes_ns=kunodes_ns,
        ku_crypto_ns=ku_crypto_ns,
        total_ns=total_ns,
        cover_size=len(cover),
        ku_g2_elements=2 * len(cover),
        ku_metadata_bytes=metadata_bytes,
        ku_serialized_bytes=len(wire),
        cover_invariant_valid=invariant_valid,
    )


def register_users(tree, count, prefix="user"):
    """Register sequential identities outside timed benchmark regions."""
    for index in range(int(count)):
        tree.register("%s-%d" % (prefix, index))


def revoke_indices(tree, indices, epoch, prefix="user"):
    for index in indices:
        tree.revoke("%s-%d" % (prefix, int(index)), int(epoch))
