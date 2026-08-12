"""Public API for the FXDACP algorithm prototype."""

from .fxabf import (
    FXABF, FXABFIndex, PROFILE, QueryResult, SegmentMeta,
    fuse_positions, plan_segments,
)
from .metrics import FXABFBuildStats, FXABFQueryStats, OperationMetrics
from .scheme import FXDACP

FXDACPCPABE = FXDACP

__all__ = [
    "FXDACP", "FXDACPCPABE", "FXABF", "FXABFIndex", "PROFILE",
    "QueryResult", "SegmentMeta", "fuse_positions", "plan_segments",
    "FXABFBuildStats", "FXABFQueryStats", "OperationMetrics",
]
