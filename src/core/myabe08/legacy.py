"""Explicit test-only namespace for the original Phase-1 contract scaffold.

This class deliberately raises for the eight algorithms and is not the
supported MYABE-08 public facade. Use ``core.myabe08.PublicMyABE08``.
"""

from .scheme import MyABE08 as LegacyMyABE08

__all__ = ["LegacyMyABE08"]
