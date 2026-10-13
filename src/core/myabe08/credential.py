"""Private provisioning/session and verification ports; no permissive verifier."""

from dataclasses import dataclass, field
from typing import Protocol

from .types import (
    ChannelBinding, Credential, NamespaceCertificate, PossessionProof,
    PublicParameters, SealedUserBlob, UserBaseState,
)


class AttestedConfidentialChannel(Protocol):
    """Software implementation cannot attest to SGX/measurement/isolation.

    Session binding requires role, fresh challenge and peer proof, not a bool
    supplied by the caller. No cleartext credential/blob logging is permitted.
    """

    def binding(self) -> ChannelBinding:
        raise NotImplementedError

    def verify_peer(self, expected_public_key: bytes, proof: PossessionProof) -> None:
        raise NotImplementedError

    def send_confidential(self, payload: bytes) -> None:
        raise NotImplementedError


@dataclass(frozen=True)
class DOSession:
    channel: AttestedConfidentialChannel = field(repr=False)
    namespace_certificate: NamespaceCertificate
    publication_signing_key: bytes = field(repr=False)  # DO-local, not TEE input
    batch_limit: int


@dataclass(frozen=True)
class AdministrativeAuthorization:
    """KGC-private management proof, distinct from user possession proof."""

    signed_command: bytes = field(repr=False)


class CredentialVerifier(Protocol):
    def verify(self, pp: PublicParameters, credential: Credential, *,
               current_version: int, current_digest: bytes, trusted_now: int) -> None:
        """Signature, SysID, validity, registered version/digest; all mandatory."""
        raise NotImplementedError

    def verify_possession(self, credential: Credential, proof: PossessionProof,
                          channel: ChannelBinding, request_digest: bytes) -> None:
        """Bind current challenge, request and credential auth key; never RK."""
        raise NotImplementedError


class SealingService(Protocol):
    def seal(self, base_state: UserBaseState) -> SealedUserBlob:
        """Binding: SysID/profile/schema and credential digest/version."""
        raise NotImplementedError

    def unseal(self, blob: SealedUserBlob, *, pp: PublicParameters) -> UserBaseState:
        """Ordinary encrypted files are not durable rollback protection."""
        raise NotImplementedError

# Phase 3B software protocol primitives; scaffold ports above remain separate.
import hashlib
import threading
import unicodedata

from .crypto import compute_ctx_priv, contextual_token
from .encoding import (StructuredRecord, UInt64, decode, encode,
                       encode_attribute, require_bytes, require_uint)
from .errors import AuthenticationError, ContractError, ProtocolRejectedError
from .signing import public_key_bytes, sign_canonical, verify_canonical
from .types import Attribute, Validity


def _name(value, label):
    if type(value) is not str or not value or '\x00' in value or unicodedata.normalize('NFC',value)!=value:
        raise ContractError('invalid canonical '+label)
    return value


def canonical_attributes(attributes):
    if type(attributes) is not tuple or not attributes:
        raise ContractError('nonempty tuple of certified attributes required')
    for attr in attributes:
        if type(attr) is not Attribute:
            raise ContractError('Attribute required')
        for label,value in (('namespace',attr.namespace),('name',attr.name),('value',attr.value)):
            _name(value,label)
    if attributes != tuple(sorted(set(attributes))):
        raise ContractError('attributes must be sorted and duplicate-free')
    return attributes


def credential_fields(credential):
    if type(credential) is not Credential:
        raise ContractError('Credential required')
    require_bytes(credential.sys_id,'SysID')
    if not credential.sys_id: raise ContractError('empty SysID')
    _name(credential.uid,'UID')
    canonical_attributes(credential.attributes)
    require_bytes(credential.pk_auth,'pk_auth',32)
    if type(credential.validity) is not Validity:
        raise ContractError('Validity required')
    require_uint(credential.credential_version,64,'credential version')
    if credential.credential_version==0: raise ContractError('positive credential version required')
    return (credential.sys_id,credential.uid,
            tuple(encode_attribute(a.namespace,a.name,a.value) for a in credential.attributes),
            (UInt64(credential.validity.not_before),UInt64(credential.validity.not_after)),
            UInt64(credential.credential_version),credential.pk_auth)


def credential_bytes(credential):
    return encode(('MYABE-CRED',)+credential_fields(credential))


def credential_digest(credential):
    return hashlib.sha256(credential_bytes(credential)+credential.signature).digest()


def issue_credential(kgc_private_key,sys_id,uid,attributes,validity,version,pk_auth):
    unsigned=Credential(sys_id,uid,attributes,validity,version,pk_auth,b'')
    signature=sign_canonical(kgc_private_key,'MYABE-CRED',*credential_fields(unsigned))
    return Credential(sys_id,uid,attributes,validity,version,pk_auth,signature)


class CredentialVersionRegistry:
    """Credential renewal version only. No RevSet or active flag."""
    def __init__(self):
        self._lock=threading.Lock()
        self._current={}
    def register(self,credential):
        digest=credential_digest(credential)
        with self._lock:
            old=self._current.get(credential.uid)
            if old is not None and credential.credential_version<=old[0]:
                raise ProtocolRejectedError('credential version not increasing')
            self._current[credential.uid]=(credential.credential_version,digest)
    def verify_current(self,credential):
        digest=credential_digest(credential)
        with self._lock:
            if self._current.get(credential.uid)!=(credential.credential_version,digest):
                raise ProtocolRejectedError('credential version mismatch')

    def count(self):
        with self._lock:
            return len(self._current)

    def logical_bytes(self):
        """Canonical TEST accounting only; never expose registry entries."""
        with self._lock:
            return len(encode(tuple((uid,UInt64(version),digest)
                for uid,(version,digest) in sorted(self._current.items()))))


def verify_credential(kgc_public_key,credential,sys_id,registry,clock):
    if clock is None or registry is None: raise ProtocolRejectedError('time/version source unavailable')
    fields=credential_fields(credential)
    if credential.sys_id!=sys_id: raise ProtocolRejectedError('credential SysID mismatch')
    verify_canonical(kgc_public_key,credential.signature,'MYABE-CRED',*fields)
    now=clock.now()
    if type(now) is not int or not credential.validity.not_before<=now<credential.validity.not_after:
        raise ProtocolRejectedError('credential validity rejected')
    registry.verify_current(credential)
    return credential


def possession_fields(sys_id,binding,header_digest,request_nonce):
    require_bytes(sys_id,'SysID')
    require_bytes(header_digest,'header digest',32)
    require_bytes(request_nonce,'request nonce')
    if len(request_nonce)<32: raise ContractError('request nonce requires 32 bytes')
    for name in ('session_id','fresh_challenge','transcript_digest','peer_ephemeral_public_key'):
        require_bytes(getattr(binding,name),name)
    return (sys_id,binding.session_id,binding.fresh_challenge,
            binding.transcript_digest,binding.peer_ephemeral_public_key,
            header_digest,request_nonce)


def sign_possession(auth_private_key,sys_id,binding,header_digest,request_nonce):
    return PossessionProof(sign_canonical(auth_private_key,'MYABE-DU-POSSESSION',
                          *possession_fields(sys_id,binding,header_digest,request_nonce)))


def verify_possession(credential,proof,binding,header_digest,request_nonce):
    if type(proof) is not PossessionProof: raise ContractError('PossessionProof required')
    return verify_canonical(credential.pk_auth,proof.challenge_signature,'MYABE-DU-POSSESSION',
                            *possession_fields(credential.sys_id,binding,header_digest,request_nonce))


def certified_user_tokens(credential,k_tok,policy_context_id,policy_version):
    """Only verified credential attributes; caller never supplies requested labels."""
    canonical_attributes(credential.attributes)
    ctx=compute_ctx_priv(credential.sys_id,policy_context_id,policy_version)
    return tuple(sorted({contextual_token(k_tok,credential.sys_id,ctx,
                         encode_attribute(a.namespace,a.name,a.value))
                         for a in credential.attributes}))


def encode_private_ingress(credential,blob,proof):
    """Private channel payload; no host-visible clear credential/UID fields."""
    if type(blob) is not SealedUserBlob or type(proof) is not PossessionProof:
        raise ContractError('private ingress fields required')
    return encode(('MYABE-PRIVATE-INGRESS',credential_bytes(credential),
                   credential.signature,blob.opaque,proof.challenge_signature))


def decode_private_ingress(data):
    value=decode(data)
    if type(value) is not tuple or len(value)!=5 or value[0]!='MYABE-PRIVATE-INGRESS':
        raise ContractError('private ingress schema mismatch')
    _,raw,sig,blob,proof=value
    parts=decode(raw)
    if type(parts) is not tuple or len(parts)!=7 or parts[0]!='MYABE-CRED':
        raise ContractError('credential wire schema mismatch')
    _,sys_id,uid,attrs,validity,version,pk_auth=parts
    if type(attrs) is not tuple or any(type(x) is not bytes for x in attrs):
        raise ContractError('attribute list malformed')
    decoded=[]
    for raw_attr in attrs:
        rec=decode(raw_attr)
        if (type(rec) is not StructuredRecord or rec.schema!='MYABE08.AttributeV1'
                or tuple(name for name,_ in rec.fields)!=('namespace','name','value')):
            raise ContractError('attribute schema mismatch')
        decoded.append(Attribute(*(value for _,value in rec.fields)))
    if (type(validity) is not tuple or len(validity)!=2 or
            any(type(x) is not UInt64 for x in validity) or type(version) is not UInt64):
        raise ContractError('credential integer schema mismatch')
    cred=Credential(sys_id,uid,tuple(decoded),Validity(validity[0].value,validity[1].value),
                    version.value,pk_auth,sig)
    if credential_bytes(cred)!=raw: raise ContractError('noncanonical credential ingress')
    return cred,SealedUserBlob(blob),PossessionProof(proof)
