"""X25519/HKDF/GCM-SIV software channel; no real TEE isolation claim."""
from dataclasses import dataclass, field
import hashlib
import secrets
import threading

from .attestation import evidence_digest,verify_emulated_evidence
from .encoding import UInt64, encode, require_bytes
from .errors import AuthenticationError,ContractError,ReplayRejectedError
from .profile import EMULATED_TEE_PROFILE
from .types import ChannelBinding

CHANNEL_INFO=b'MYABE-EMULATED-CHANNEL-V1'


def x25519_private_from_seed(seed):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    require_bytes(seed,'X25519 TEST seed',32)
    return X25519PrivateKey.from_private_bytes(seed)


def x25519_private_new():
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    return X25519PrivateKey.generate()


def x25519_public_bytes(private_key):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    if not isinstance(private_key,X25519PrivateKey): raise ContractError('X25519 private key required')
    return private_key.public_key().public_bytes(serialization.Encoding.Raw,
                                                 serialization.PublicFormat.Raw)


@dataclass(frozen=True)
class EmulatedChannelRecord:
    session_id: bytes
    direction: str
    sequence: int
    nonce: bytes
    ciphertext: bytes = field(repr=False)


class EmulatedChannelEndpoint:
    def __init__(self,session_id,transcript_digest,challenge,server_public_key,
                 send_key,recv_key,send_direction,recv_direction,nonce_source=None):
        self.binding=ChannelBinding(session_id,challenge,transcript_digest,server_public_key)
        self._send_key=send_key; self._recv_key=recv_key
        self._send_direction=send_direction; self._recv_direction=recv_direction
        self._send_seq=0; self._recv_seq=0
        self._send_lock=threading.Lock();self._recv_lock=threading.Lock()
        self._nonce_source=secrets.token_bytes if nonce_source is None else nonce_source

    def _ad(self,direction,seq):
        return encode(('MYABE-CHANNEL-RECORD',direction,self.binding.session_id,
                       UInt64(seq),self.binding.transcript_digest))

    def send(self,payload):
        from .crypto import AES256GCMSIV
        require_bytes(payload,'channel payload')
        if not payload: raise ContractError('empty channel payload unsupported by installed AEAD')
        with self._send_lock:
            nonce=self._nonce_source(12);require_bytes(nonce,'channel nonce',12)
            seq=self._send_seq
            ciphertext=AES256GCMSIV().encrypt(self._send_key,nonce,payload,
                                               self._ad(self._send_direction,seq))
            self._send_seq+=1
            return EmulatedChannelRecord(self.binding.session_id,self._send_direction,seq,
                                         nonce,ciphertext)

    def receive(self,record):
        from .crypto import AES256GCMSIV
        if type(record) is not EmulatedChannelRecord:
            raise ContractError('channel record required')
        with self._recv_lock:
            if (record.session_id!=self.binding.session_id or
                record.direction!=self._recv_direction or
                type(record.sequence) is not int or record.sequence!=self._recv_seq):
                raise ReplayRejectedError('channel record direction/sequence mismatch')
            plaintext=AES256GCMSIV().decrypt(self._recv_key,record.nonce,record.ciphertext,
                                              self._ad(record.direction,record.sequence))
            self._recv_seq+=1
            return plaintext


def establish_emulated_channel(client_private,server_private,evidence,root_public,
                               expected_sys_id,expected_measurement,min_security_version,
                               expected_challenge,challenge_store,*,nonce_source=None,
                               purpose='DU'):
    """Verify software evidence before using the attested server X25519 key."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    verify_emulated_evidence(evidence,root_public,expected_sys_id,expected_measurement,
                             min_security_version,expected_challenge,challenge_store)
    server_pub=x25519_public_bytes(server_private)
    if server_pub!=evidence.channel_public_key:
        raise AuthenticationError('channel public-key substitution')
    client_pub=x25519_public_bytes(client_private)
    if purpose == 'DU':
        transcript_label, info, forward, backward = (
            'MYABE-EMULATED-CHANNEL-TRANSCRIPT',CHANNEL_INFO,'DU->TEE','TEE->DU')
    elif purpose == 'REV':
        transcript_label, info, forward, backward = (
            'MYABE-REV-UPDATE-TRANSCRIPT-V1',b'MYABE-REV-UPDATE-V1',
            'KGC->TEE','TEE->KGC')
    else:
        raise ContractError('unknown channel purpose')
    transcript=encode((transcript_label,expected_sys_id,
        EMULATED_TEE_PROFILE,evidence_digest(evidence),client_pub,server_pub,
        evidence.challenge,evidence.session_id))
    digest=hashlib.sha256(transcript).digest()
    shared_client=client_private.exchange(X25519PublicKey.from_public_bytes(server_pub))
    shared_server=server_private.exchange(X25519PublicKey.from_public_bytes(client_pub))
    if shared_client!=shared_server: raise AuthenticationError('X25519 agreement mismatch')
    def key(direction):
        return HKDF(algorithm=hashes.SHA256(),length=32,salt=digest,
                    info=info+b'|'+direction.encode()).derive(shared_client)
    du_to_tee=key(forward);tee_to_du=key(backward)
    if du_to_tee==tee_to_du: raise AuthenticationError('direction keys not separated')
    client=EmulatedChannelEndpoint(evidence.session_id,digest,evidence.challenge,
        server_pub,du_to_tee,tee_to_du,forward,backward,nonce_source)
    server=EmulatedChannelEndpoint(evidence.session_id,digest,evidence.challenge,
        server_pub,tee_to_du,du_to_tee,backward,forward,nonce_source)
    return client,server
