"""Quote-bound SGX DEBUG TEST channel mechanics; never a production ingress.

The enclave keeps its ephemeral X25519 private key in this process only.
The verifier must check QVL and policy before activating a session. The
enclave cannot independently authenticate a host's QVL decision, so this
module makes no production remote-attestation claim.
"""
from dataclasses import dataclass, field
import hashlib
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..channel import EmulatedChannelEndpoint, x25519_private_new, x25519_public_bytes
from ..encoding import UInt32, encode, decode, require_bytes
from ..errors import AuthenticationError, ContractError, ReplayRejectedError
from ..profile import SGX_DEBUG_GRAMINE_V1
from ..revocation import parse_record, record_wire
from .attestation import attestation_binding, quote_for_public

FEASIBILITY_MODE = 'QVL_VERIFIED_OUTDATED_TCB_DEBUG_FEASIBILITY_V1'
STRICT_MODE = 'STRICT_CURRENT_TCB'
OUTDATED_TCB = 0xA002
CLIENT_TO_ENCLAVE = 'CLIENT->ENCLAVE'
ENCLAVE_TO_CLIENT = 'ENCLAVE->CLIENT'


def channel_endpoint(local_private, peer_public, *, enclave_side, sys_id,
                     session_id, challenge, quote_digest, qv_result, mode):
    """Derive direction-separated keys from all attestation session context."""
    require_bytes(sys_id, 'RA SysID')
    require_bytes(peer_public, 'peer X25519 public', 32)
    require_bytes(session_id, 'RA session ID', 32)
    require_bytes(challenge, 'RA challenge', 32)
    require_bytes(quote_digest, 'RA quote digest', 32)
    if not sys_id or mode not in (FEASIBILITY_MODE, STRICT_MODE):
        raise ContractError('RA channel scope rejected')
    if type(qv_result) is not int or not ((mode == STRICT_MODE and qv_result == 0)
                                          or (mode == FEASIBILITY_MODE and
                                              qv_result == OUTDATED_TCB)):
        raise ContractError('RA mode/QV result rejected')
    local_public = x25519_public_bytes(local_private)
    enclave_public, client_public = ((local_public, peer_public) if enclave_side
                                     else (peer_public, local_public))
    transcript = encode(('MYABE-RA-X25519-TRANSCRIPT-V1', sys_id,
        SGX_DEBUG_GRAMINE_V1, mode, UInt32(1), session_id, challenge,
        quote_digest, UInt32(qv_result), enclave_public, client_public))
    digest = hashlib.sha256(transcript).digest()
    shared = local_private.exchange(X25519PublicKey.from_public_bytes(peer_public))
    def key(direction):
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=digest,
            info=b'MYABE-RA-X25519-V1|' + direction.encode()).derive(shared)
    send = ENCLAVE_TO_CLIENT if enclave_side else CLIENT_TO_ENCLAVE
    recv = CLIENT_TO_ENCLAVE if enclave_side else ENCLAVE_TO_CLIENT
    return EmulatedChannelEndpoint(session_id, digest, challenge, enclave_public,
        key(send), key(recv), send, recv)


@dataclass
class _Session:
    sys_id: bytes
    challenge: bytes
    session_id: bytes
    private: object = field(repr=False)
    public: bytes
    quote_digest: bytes
    endpoint: object = field(default=None, repr=False)
    mode: str = ''
    request_ids: set = field(default_factory=set, repr=False)
    dummy_count: int = 0


class AttestationSessionManager:
    """SGX-process-resident TEST state; no private key is returned by RPC."""
    def __init__(self):
        self._sessions = {}
        self._challenges = set()

    def open(self, sys_id, challenge, session_id):
        require_bytes(sys_id, 'RA SysID')
        require_bytes(challenge, 'RA challenge', 32)
        require_bytes(session_id, 'RA session ID', 32)
        if not sys_id or session_id in self._sessions or challenge in self._challenges:
            raise ReplayRejectedError('RA session or challenge replay')
        if len(self._sessions) >= 128:
            raise ContractError('RA TEST session limit')
        private = x25519_private_new()
        public = x25519_public_bytes(private)
        report_data, quote = quote_for_public(sys_id, challenge, public)
        if report_data != attestation_binding(sys_id, challenge, public):
            raise AuthenticationError('RA report data mismatch')
        state = _Session(sys_id, challenge, session_id, private, public,
                         hashlib.sha256(quote).digest())
        self._sessions[session_id] = state
        self._challenges.add(challenge)
        return public, report_data, quote

    def activate(self, session_id, client_public, quote_digest, qv_result, mode):
        require_bytes(session_id, 'RA session ID', 32)
        require_bytes(client_public, 'client X25519 public', 32)
        require_bytes(quote_digest, 'RA quote digest', 32)
        state = self._sessions.get(session_id)
        if state is None or state.endpoint is not None:
            raise ReplayRejectedError('RA pending session unavailable')
        if quote_digest != state.quote_digest:
            raise AuthenticationError('RA quote digest substitution')
        if not ((mode == FEASIBILITY_MODE and qv_result == OUTDATED_TCB) or
                (mode == STRICT_MODE and qv_result == 0)):
            raise AuthenticationError('RA mode/QV mismatch')
        endpoint = channel_endpoint(state.private, client_public,
            enclave_side=True, sys_id=state.sys_id, session_id=session_id,
            challenge=state.challenge, quote_digest=quote_digest,
            qv_result=qv_result, mode=mode)
        state.endpoint, state.mode = endpoint, mode
        return record_wire(endpoint.send(encode(('MYABE-RA-CHANNEL-READY',
                                                  session_id))))

    def provision_dummy(self, session_id, protected_record):
        require_bytes(session_id, 'RA session ID', 32)
        state = self._sessions.get(session_id)
        if state is None or state.endpoint is None or state.mode != FEASIBILITY_MODE:
            raise AuthenticationError('RA dummy ingress requires feasibility session')
        payload = decode(state.endpoint.receive(parse_record(protected_record)))
        if (type(payload) is not tuple or len(payload) != 3 or
                payload[0] != 'MYABE-RA-DUMMY-PROVISION'):
            raise ContractError('RA dummy payload schema')
        request_id, dummy = payload[1:]
        require_bytes(request_id, 'RA dummy request ID', 16)
        require_bytes(dummy, 'RA TEST dummy', 32)
        if request_id in state.request_ids or state.dummy_count != 0:
            raise ReplayRejectedError('RA dummy replay or duplicate')
        state.request_ids.add(request_id)
        state.dummy_count += 1
        # The dummy is not echoed, hashed into logs, or persisted.
        return record_wire(state.endpoint.send(encode(('PROVISION_TEST_OK',
            UInt32(len(dummy)), request_id))))
