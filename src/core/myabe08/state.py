"""Linearizable current-state and replay ports (NOT implemented in Phase 1).

Snapshots in types.py are NOT a coordinator. In particular version monotonicity
and caller version_hint do not prove freshness. No local fallback exists.
"""

from dataclasses import dataclass
from typing import ContextManager, Protocol

from .errors import unimplemented
from .types import KGCState, RevocationAck, RevocationOperation, RevocationUpdate


@dataclass(frozen=True)
class CurrentHeadPermit:
    """Internal transaction-bound evidence; cannot be reused across requests."""

    sys_id: bytes
    fresh_nonce: bytes
    rev_version: int
    state_digest: bytes
    transaction_id: bytes
    authenticated_record: bytes
    active: bool = False  # no permissive default


class AuthorizationTransaction(Protocol):
    def current_head(self) -> CurrentHeadPermit:
        raise NotImplementedError

    def commit_authorization(self, request_nonce: bytes, bundle_digest: bytes) -> None:
        """Recheck version and atomically mark issuance before releasing Auth.

        A conflicting revoke cannot be acknowledged during this permit. Failure
        or context-manager exit before commit must abort without releasing Auth.
        """
        raise NotImplementedError


class CurrentStateCoordinator(Protocol):
    def authorization_transaction(self, *, sys_id: bytes,
                                  fresh_nonce: bytes) -> ContextManager[AuthorizationTransaction]:
        """Online fresh current-head + serialization, not async push alone."""
        raise NotImplementedError

    def commit_revocation(self, state: KGCState, acknowledgement: RevocationAck) -> KGCState:
        """Only authenticated Ack moves a queued Rev from pending to committed."""
        raise NotImplementedError


class TrustedClock(Protocol):
    def now(self) -> int:
        """Integer UTC seconds; unavailable/untrusted clock must reject access."""
        raise NotImplementedError


class AtomicRequestStore(Protocol):
    def issue_once(self, nonce: bytes, expiry: int) -> None:
        raise NotImplementedError

    def consume_once(self, nonce: bytes, expiry: int) -> None:
        raise NotImplementedError


class RevocationChannel(Protocol):
    def protect_update(self, *, sys_id: bytes, version: int,
                       operation: RevocationOperation, handle: bytes,
                       previous_digest: bytes) -> RevocationUpdate:
        """Independent channel key; fixed-width schema; no public clear handle."""
        raise NotImplementedError


def commit_ack(state: KGCState, acknowledgement: RevocationAck, *,
               coordinator: CurrentStateCoordinator) -> KGCState:
    """Required pending->committed transition, unavailable in this scaffold."""
    unimplemented("KGC revocation Ack commit")


class UnavailableCurrentStateCoordinator:
    """Runtime default: no current-head service means no authorization."""
    def authorization_transaction(self, *, sys_id: bytes, fresh_nonce: bytes):
        from .errors import StateSynchronizationError
        raise StateSynchronizationError('current-state coordinator unavailable')


class EmulatedClock:
    """Software wall clock only; no hardware trusted-time claim."""
    def now(self):
        import time
        return int(time.time())


@dataclass(frozen=True)
class DURequestState:
    """DU-local request binding snapshot; no credential or recovery key."""
    header_digest: bytes
    ctx_priv: bytes
    request_nonce: bytes
    expiry: int
    session_id: bytes
    challenge: bytes

    @classmethod
    def from_host_request(cls, request):
        from .encoding import require_bytes, require_uint
        for name,width in (('header_digest',32),('ctx_priv',32),
                           ('session_id',32),('challenge',32)):
            require_bytes(getattr(request,name),name,width)
        require_bytes(request.request_nonce,'request nonce')
        if len(request.request_nonce)<32:
            from .errors import ContractError
            raise ContractError('request nonce requires 32 bytes')
        require_uint(request.expiry,64,'expiry')
        return cls(request.header_digest,request.ctx_priv,request.request_nonce,
                   request.expiry,request.session_id,request.challenge)

    def verify_response_binding(self,request,authorization):
        from .errors import ProtocolRejectedError
        if self!=type(self).from_host_request(request):
            raise ProtocolRejectedError('DU request state mismatch')
        cap=authorization.capability
        if (cap.header_digest!=self.header_digest or cap.ctx_priv!=self.ctx_priv or
            cap.request_nonce!=self.request_nonce or cap.expiry!=self.expiry):
            raise ProtocolRejectedError('DU authorization binding mismatch')


class TEEIssueStore:
    """Software reserved/issued nonce state; no durable rollback protection."""
    def __init__(self):
        import threading
        self._lock=threading.Lock();self._state={}
    def reserve(self,sys_id,nonce):
        from .errors import ReplayRejectedError
        with self._lock:
            key=(sys_id,nonce)
            if key in self._state: raise ReplayRejectedError('request nonce already reserved or issued')
            self._state[key]='reserved'
    def mark_issued(self,sys_id,nonce):
        from .errors import ReplayRejectedError
        with self._lock:
            key=(sys_id,nonce)
            if self._state.get(key)!='reserved': raise ReplayRejectedError('request not reserved')
            self._state[key]='issued'
    def abort(self,sys_id,nonce):
        with self._lock:
            key=(sys_id,nonce)
            if self._state.get(key)=='reserved': del self._state[key]
    def state(self,sys_id,nonce):
        with self._lock: return self._state.get((sys_id,nonce))


class CSPRequestState:
    """Software one-time cap consumption. Copied B_q bytes remain computable."""
    def __init__(self):
        import threading
        self._lock=threading.Lock();self._consumed=set()
    def consume_once(self,sys_id,nonce):
        from .errors import ReplayRejectedError
        with self._lock:
            key=(sys_id,nonce)
            if key in self._consumed: raise ReplayRejectedError('capability already consumed')
            self._consumed.add(key)
    def count(self):
        with self._lock: return len(self._consumed)
