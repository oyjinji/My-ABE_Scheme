"""Complete-binary-tree indirect revocation with frozen epochs."""

from dataclasses import dataclass, field


@dataclass
class BinaryRevocationTree:
    capacity: int
    next_leaf: int = 0
    user_leaf: dict = field(default_factory=dict)
    revoked_from: dict = field(default_factory=dict)
    published: dict = field(default_factory=dict)

    def __post_init__(self):
        leaves = 1
        while leaves < self.capacity:
            leaves *= 2
        self.leaf_count = leaves
        self.leaf_base = leaves

    def register(self, identity):
        identity = str(identity)
        if identity in self.user_leaf:
            return self.user_leaf[identity]
        if self.next_leaf >= self.capacity:
            raise ValueError("revocation tree is full")
        leaf = self.leaf_base + self.next_leaf
        self.next_leaf += 1
        self.user_leaf[identity] = leaf
        return leaf

    def path(self, identity):
        node = self.user_leaf[str(identity)]
        result = []
        while node:
            result.append(node)
            node //= 2
        return tuple(result)

    def revoke(self, identity, effective_epoch):
        identity, epoch = str(identity), int(effective_epoch)
        if identity not in self.user_leaf:
            raise KeyError("unknown user")
        if epoch in self.published:
            raise ValueError("published revocation epoch is frozen")
        previous = self.revoked_from.get(identity)
        self.revoked_from[identity] = epoch if previous is None else min(previous, epoch)

    def revoked_leaves(self, epoch):
        return {self.user_leaf[user] for user, start in self.revoked_from.items()
                if start <= int(epoch)}

    def registered_leaves(self):
        return set(self.user_leaf.values())


def KUNodes(tree, epoch):
    """Return a minimal cover of registered, non-revoked leaves."""
    assigned = tree.registered_leaves()
    if not assigned:
        return tuple()
    revoked = tree.revoked_leaves(epoch)
    if not revoked:
        return (1,)
    active = assigned - revoked
    if not active:
        return tuple()
    cover = []

    def visit(node, lo, hi):
        here = {leaf for leaf in assigned if lo <= leaf < hi}
        live = here - revoked
        if not live:
            return
        if live == here:
            cover.append(node)
            return
        mid = (lo + hi) // 2
        visit(node * 2, lo, mid)
        visit(node * 2 + 1, mid, hi)

    visit(1, tree.leaf_base, tree.leaf_base + tree.leaf_count)
    return tuple(cover)
