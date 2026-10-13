"""Unauthenticated X25519 encrypted TEST ingress over framed RPC.

No remote attestation binds these keys to an enclave measurement. Do not use
this transport for production secret provisioning or claim MITM resistance.
"""
import hashlib
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,X25519PublicKey)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..channel import EmulatedChannelEndpoint,x25519_public_bytes
from ..encoding import encode,require_bytes
from ..errors import ContractError
from ..profile import SGX_DEBUG_GRAMINE_V1

PURPOSES=frozenset(('DO','DU','KGC'))


def _endpoint(local_private,peer_public,sys_id,purpose,challenge,session_id,*,server):
    if purpose not in PURPOSES: raise ContractError('unknown TEST session purpose')
    require_bytes(peer_public,'peer X25519 public key',32)
    require_bytes(challenge,'session challenge',32)
    require_bytes(session_id,'session ID',32)
    local_public=x25519_public_bytes(local_private)
    client_public,server_public=(peer_public,local_public) if server else (local_public,peer_public)
    transcript=encode(('MYABE08-SGX-DEBUG-TEST-CHANNEL-V1',SGX_DEBUG_GRAMINE_V1,
        sys_id,purpose,client_public,server_public,challenge,session_id))
    digest=hashlib.sha256(transcript).digest()
    shared=local_private.exchange(X25519PublicKey.from_public_bytes(peer_public))
    def key(direction):
        return HKDF(algorithm=hashes.SHA256(),length=32,salt=digest,
            info=b'MYABE08-SGX-DEBUG-TEST-CHANNEL-V1|'+direction.encode()).derive(shared)
    forward=purpose+'->TEE';backward='TEE->'+purpose
    return EmulatedChannelEndpoint(session_id,digest,challenge,server_public,
        key(backward if server else forward),key(forward if server else backward),
        backward if server else forward,forward if server else backward)


def open_server_session(sys_id,purpose,client_public,challenge,session_id):
    private=X25519PrivateKey.generate()
    return x25519_public_bytes(private),_endpoint(private,client_public,sys_id,
        purpose,challenge,session_id,server=True)


def open_client_session(sys_id,purpose,private,server_public,challenge,session_id):
    return _endpoint(private,server_public,sys_id,purpose,challenge,session_id,server=False)
