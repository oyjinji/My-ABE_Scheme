"""PStore-free fixed-width retrieval view of the repaired FX-ABF core."""

from ..filters.fxabf import PROFILE, plan_segments
from .base import sha256_domain
from .xor_core import PeelableXorRetrieval


class FXABFRetrieval(PeelableXorRetrieval):
    name = "FX-ABF retrieval"
    type_id = "fxabf-fuse-v2-retrieval"
    load_factor_target = 1.30
    query_hashes = 4  # base segment plus three within-segment range hashes

    def __init__(self, delta=64, segment_length=64, **options):
        super().__init__(delta=delta, **options)
        self.requested_segment_length = int(segment_length)
        self.segment_meta = None

    def _prepare_layout(self, capacity):
        self.segment_meta = plan_segments(
            capacity, self.requested_segment_length
        )

    def _range_hash(self, seed, token, lane, size):
        limit = (1 << 64) - ((1 << 64) % size)
        counter = 0
        while True:
            value = int.from_bytes(sha256_domain(
                PROFILE, seed, token, lane, counter
            )[:8], "big")
            if value < limit:
                return value % size
            counter += 1

    def _positions(self, seed, token, capacity):
        meta = self.segment_meta
        base = self._range_hash(
            seed, token, 0, meta.segment_count - 2
        )
        positions = []
        for lane, segment in enumerate((base, base + 1, base + 2), 1):
            start = segment * meta.segment_length
            end = min(capacity, start + meta.segment_length)
            positions.append(
                start + self._range_hash(
                    seed, token, lane, end - start
                )
            )
        return tuple(positions)

    def _layout_metadata(self):
        return {
            "requested_segment_length": self.requested_segment_length,
            "segment_length": self.segment_meta.segment_length,
            "segment_count": self.segment_meta.segment_count,
        }

    def _restore_layout(self, metadata):
        self.requested_segment_length = int(
            metadata["requested_segment_length"]
        )
        self.segment_meta = plan_segments(
            self.capacity, self.requested_segment_length
        )
        if (
            self.segment_meta.segment_length != int(metadata["segment_length"])
            or self.segment_meta.segment_count != int(metadata["segment_count"])
        ):
            raise ValueError("malformed FX segment metadata")
