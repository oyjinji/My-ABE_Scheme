"""Provider ports for SGX DEBUG integration; production defaults fail closed."""
from dataclasses import dataclass, field
import secrets

from ..errors import StateSynchronizationError
from ..profile import SGX_DEBUG_GRAMINE_V1
from ..sealing import EmulatedSealingService


@dataclass(frozen=True)
class SgxDebugBootstrapBundle:
    """TEST ONLY internal state; no KGC MSK, RK, or production provisioning."""
    sys_id: bytes
    k_tok: bytes = field(repr=False)
    k_rev: bytes = field(repr=False)
    sk_cap: object = field(repr=False)
    k_seal: bytes = field(repr=False)
    k_state: bytes = field(repr=False)
    k_head: bytes = field(repr=False)
    profile_id: str = SGX_DEBUG_GRAMINE_V1


class SgxResidentApplicationSealingProvider(EmulatedSealingService):
    """Application AEAD with process-resident key, NOT SGX hardware sealing."""
    def __init__(self,key,backend):
        super().__init__(key,backend,profile_id=SGX_DEBUG_GRAMINE_V1)


class UnavailableTrustedCurrentHeadProvider:
    def authorization_transaction(self,**kwargs):
        raise StateSynchronizationError('trusted current head not configured')


class UnavailableTrustedTimeProvider:
    def now(self):
        raise StateSynchronizationError('trusted time not configured')


class DebugTestTimeProvider:
    """Explicit test semantics only; not a trusted hardware time source."""
    def __init__(self,value):
        if type(value) is not int or value<0:
            raise ValueError('nonnegative test time required')
        self.value=value
    def now(self):
        return self.value


def new_internal_bundle(sys_id,k_rev):
    """K_rev is TEST KGC-supplied; other secrets are generated inside SGX."""
    from ..signing import new_private_key
    return SgxDebugBootstrapBundle(sys_id,secrets.token_bytes(32),k_rev,
        new_private_key(),secrets.token_bytes(32),secrets.token_bytes(32),
        secrets.token_bytes(32))
