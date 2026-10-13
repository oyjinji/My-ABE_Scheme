"""Signature-bound software evidence, explicitly not a hardware quote."""
from dataclasses import dataclass, field
import hashlib
import threading

from .encoding import UInt64, encode, require_bytes, require_uint
from .errors import ContractError, ProtocolRejectedError, ReplayRejectedError
from .profile import EMULATED_TEE_PROFILE
from .signing import sign_canonical,verify_canonical


@dataclass(frozen=True)
class EmulatedAttestationEvidence:
    sys_id: bytes
    tee_profile_id: str
    measurement: bytes
    security_version: int
    challenge: bytes
    channel_public_key: bytes
    session_id: bytes
    signature: bytes = field(repr=False)


def evidence_fields(e):
    if type(e) is not EmulatedAttestationEvidence: raise ContractError('emulated evidence required')
    require_bytes(e.sys_id,'SysID')
    require_bytes(e.measurement,'measurement',32)
    require_bytes(e.challenge,'challenge',32)
    require_bytes(e.channel_public_key,'X25519 public key',32)
    require_bytes(e.session_id,'session ID',32)
    require_uint(e.security_version,64,'security version')
    if e.tee_profile_id!=EMULATED_TEE_PROFILE: raise ContractError('wrong TEE profile')
    return (e.sys_id,e.tee_profile_id,e.measurement,UInt64(e.security_version),
            e.challenge,e.channel_public_key,e.session_id)


def issue_emulated_evidence(root_private,sys_id,measurement,security_version,
                            challenge,channel_public_key,session_id):
    unsigned=EmulatedAttestationEvidence(sys_id,EMULATED_TEE_PROFILE,measurement,
                                         security_version,challenge,channel_public_key,
                                         session_id,b'')
    signature=sign_canonical(root_private,'MYABE-EMULATED-ATTEST',*evidence_fields(unsigned))
    return EmulatedAttestationEvidence(sys_id,EMULATED_TEE_PROFILE,measurement,
            security_version,challenge,channel_public_key,session_id,signature)


def evidence_digest(e):
    return hashlib.sha256(encode(('MYABE-EMULATED-EVIDENCE',)+evidence_fields(e)+
                                 (e.signature,))).digest()


class EmulatedChallengeStore:
    def __init__(self):
        self._lock=threading.Lock(); self._seen=set()
    def consume(self,sys_id,challenge):
        with self._lock:
            key=(sys_id,challenge)
            if key in self._seen: raise ReplayRejectedError('challenge already used')
            self._seen.add(key)


def verify_emulated_evidence(e,root_public,sys_id,measurement,min_security_version,
                             challenge,challenge_store):
    fields=evidence_fields(e)
    if (e.sys_id!=sys_id or e.measurement!=measurement or
        e.security_version<min_security_version or e.challenge!=challenge):
        raise ProtocolRejectedError('emulated evidence policy mismatch')
    verify_canonical(root_public,e.signature,'MYABE-EMULATED-ATTEST',*fields)
    if challenge_store is None: raise ProtocolRejectedError('challenge state unavailable')
    challenge_store.consume(sys_id,challenge)
    return e
