"""Three independent global-position XOR retrieval."""

from .base import sha256_domain
from .xor_core import PeelableXorRetrieval


class PlainXorRetrieval(PeelableXorRetrieval):
    name = "Plain XOR retrieval"
    type_id = "plain-xor-v1"
    load_factor_target = 1.30
    query_hashes = 3

    def _positions(self, seed, token, capacity):
        positions = []
        for lane in range(3):
            counter = 0
            while True:
                digest = sha256_domain(
                    "Plain-XOR-Position-v1", seed, token, lane, counter
                )
                position = int.from_bytes(digest[:8], "big") % capacity
                if position not in positions:
                    positions.append(position)
                    break
                counter += 1
        return tuple(positions)
