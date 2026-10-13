"""MYABE-08 public TEST integration facade and profile constants.

The Phase-1 placeholder is available only from ``core.myabe08.legacy``.
"""

from .profile import (
    EMULATED_TEE_PROFILE,
    FABEO_COMPAT_PROFILE,
    SECURITY_PROFILE_BLS12_381,
)
from .tee import EmulatedAnonymousAuthorizationEnclave

IMPLEMENTATION_STATUS = "PHASE_4EF_PUBLIC_TEST_FACADE"
BENCHMARK_READY = False

__all__ = [
    "PublicMyABE08", "EmulatedAnonymousAuthorizationEnclave",
    "SECURITY_PROFILE_BLS12_381", "FABEO_COMPAT_PROFILE",
    "EMULATED_TEE_PROFILE", "IMPLEMENTATION_STATUS", "BENCHMARK_READY",
]


def __getattr__(name):
    # Keep the measured SGX service's package import independent of host-only
    # facade modules. Explicit clients may still import PublicMyABE08 here.
    if name == 'PublicMyABE08':
        from .public import PublicMyABE08
        return PublicMyABE08
    raise AttributeError(name)
