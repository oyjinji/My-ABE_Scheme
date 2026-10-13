"""Strict identity predicate for a future cryptographically verified quote.

This is policy logic only. It cannot authenticate quote bytes and is not wired
to provisioning while the installed DCAP verifier path is unavailable.
"""
from dataclasses import dataclass

from ..encoding import require_bytes
from ..errors import ContractError


@dataclass(frozen=True)
class SgxIdentityPolicy:
    """Deployment-owned exact measurement OR constrained signer policy."""
    policy_id: str
    profile_id: str
    mrenclave: bytes = None
    mrsigner: bytes = None
    product_id: int = None
    min_svn: int = None
    allow_debug: bool = False

    def __post_init__(self):
        if type(self.policy_id) is not str or not self.policy_id:
            raise ContractError('policy identifier required')
        if type(self.profile_id) is not str or not self.profile_id:
            raise ContractError('profile identifier required')
        if (self.mrenclave is None) == (self.mrsigner is None):
            raise ContractError('exactly one SGX identity mode required')
        if self.mrenclave is not None:
            require_bytes(self.mrenclave,'expected MRENCLAVE',32)
        if self.mrsigner is not None:
            require_bytes(self.mrsigner,'expected MRSIGNER',32)
            if (type(self.product_id) is not int or not 0<=self.product_id<=65535 or
                    type(self.min_svn) is not int or not 0<=self.min_svn<=65535):
                raise ContractError('signer mode requires product ID and minimum SVN')
        elif self.product_id is not None or self.min_svn is not None:
            raise ContractError('product/SVN constraints belong to signer policy')
        if type(self.allow_debug) is not bool:
            raise ContractError('allow_debug must be explicit boolean')

    def check_authenticated_fields(self,*,profile_id,mrenclave,mrsigner,
                                   product_id,svn,debug):
        """Only call after a trusted quote verifier authenticates these fields."""
        require_bytes(mrenclave,'quote MRENCLAVE',32)
        require_bytes(mrsigner,'quote MRSIGNER',32)
        if (profile_id!=self.profile_id or type(debug) is not bool or
                type(product_id) is not int or type(svn) is not int or
                product_id<0 or svn<0 or (debug and not self.allow_debug)):
            return False
        if self.mrenclave is not None:
            return mrenclave == self.mrenclave
        return (mrsigner == self.mrsigner and product_id == self.product_id
                and svn >= self.min_svn)
