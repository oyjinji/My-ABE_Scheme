"""Four-partition peelable Bloomier/static-function retrieval.

Each key selects one cell in each of four disjoint partitions.  Hypergraph
peeling followed by reverse XOR assignment stores the common fixed-width value.
No Bloom bitmap, exact map, or locator is present.
"""

from .base import sha256_domain
from .xor_core import PeelableXorRetrieval


class BloomierRetrieval(PeelableXorRetrieval):
    name = "Bloomier retrieval"
    type_id = "bloomier-partitioned-xor-v1"
    load_factor_target = 1.30
    query_hashes = 4

    def _positions(self, seed, token, capacity):
        result = []
        for lane in range(4):
            start = lane * capacity // 4
            end = (lane + 1) * capacity // 4
            digest = sha256_domain(
                "Bloomier-Position-v1", seed, token, lane
            )
            result.append(
                start + int.from_bytes(digest[:8], "big") % (end - start)
            )
        return tuple(result)

    def _capacity(self, u):
        # Four nonempty partitions are required.
        return max(4, super()._capacity(u))
