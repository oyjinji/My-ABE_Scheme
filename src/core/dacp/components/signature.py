'''
Replaceable row-binding signature components for DACP.

PrototypeHashSignature is only a deterministic hash tag. It is not a digital
signature and provides no public-key security. Ed25519Signature is a real
digital-signature adapter for protocol benchmarks, while still using the local
simulation message flow around it.
'''

import hashlib
import json

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
except ImportError:  # pragma: no cover - exercised only when dependency lacks.
    InvalidSignature = None
    serialization = None
    Ed25519PrivateKey = None
    Ed25519PublicKey = None


class SignatureAdapter:
    def keygen(self):
        raise NotImplementedError

    def sign(self, sk, message, **kwargs):
        raise NotImplementedError

    def verify(self, pk, message, signature, **kwargs):
        raise NotImplementedError


class PrototypeHashSignature(SignatureAdapter):
    def keygen(self):
        key = 'prototype-hash-signature-key'
        return key, key

    def sign(self, sk, message, **kwargs):
        return self._digest(str(sk), message)

    def verify(self, pk, message, signature, **kwargs):
        return self._digest(str(pk), message) == signature

    def _digest(self, key_material, message):
        payload = 'dacp::Sig::{0}|{1}'.format(key_material, self._message_repr(message))
        return hashlib.sha256(payload.encode('utf-8')).hexdigest()

    def _message_repr(self, message):
        if isinstance(message, dict):
            items = sorted(message.items(), key=lambda item: str(item[0]))
            return repr(items)
        return repr(message)


class Ed25519Signature(SignatureAdapter):
    """
    Real Ed25519 signature adapter for DACP row-binding benchmarks.

    This component provides actual Ed25519 sign/verify operations. It does not
    by itself create a secure transport, certificate chain, or replay-resistant
    protocol; those remain protocol-layer concerns.
    """

    def __init__(self):
        if Ed25519PrivateKey is None or Ed25519PublicKey is None:
            raise RuntimeError(
                'Ed25519Signature requires the cryptography package. '
                'Install it with: pip install cryptography'
            )

    def keygen(self):
        sk = Ed25519PrivateKey.generate()
        pk = sk.public_key()
        return sk, pk

    def sign(self, sk, message, **kwargs):
        private_key = self.load_private_key(sk)
        return private_key.sign(self._stable_bytes(message)).hex()

    def verify(self, pk, message, signature, **kwargs):
        try:
            public_key = self.load_public_key(pk)
            signature_bytes = self._signature_bytes(signature)
            public_key.verify(signature_bytes, self._stable_bytes(message))
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False

    def serialize_public_key(self, pk):
        public_key = self.load_public_key(pk)
        return public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def serialize_private_key(self, sk):
        private_key = self.load_private_key(sk)
        return private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def load_public_key(self, data):
        if isinstance(data, Ed25519PublicKey):
            return data
        raw = self._key_bytes(data)
        return Ed25519PublicKey.from_public_bytes(raw)

    def load_private_key(self, data):
        if isinstance(data, Ed25519PrivateKey):
            return data
        raw = self._key_bytes(data)
        return Ed25519PrivateKey.from_private_bytes(raw)

    def _key_bytes(self, data):
        if isinstance(data, bytes):
            return data
        if isinstance(data, bytearray):
            return bytes(data)
        if isinstance(data, str):
            try:
                return bytes.fromhex(data)
            except ValueError:
                return data.encode('utf-8')
        raise TypeError('unsupported Ed25519 key type: {0}'.format(type(data).__name__))

    def _signature_bytes(self, signature):
        if isinstance(signature, bytes):
            return signature
        if isinstance(signature, bytearray):
            return bytes(signature)
        if isinstance(signature, str):
            return bytes.fromhex(signature)
        raise TypeError('unsupported Ed25519 signature type: {0}'.format(type(signature).__name__))

    def _stable_bytes(self, message):
        return json.dumps(
            self._jsonable(message),
            sort_keys=True,
            separators=(',', ':'),
        ).encode('utf-8')

    def _jsonable(self, value):
        if isinstance(value, dict):
            return {
                str(key): self._jsonable(value[key])
                for key in sorted(value.keys(), key=lambda item: str(item))
            }
        if isinstance(value, (list, tuple)):
            return [self._jsonable(item) for item in value]
        if isinstance(value, bytes):
            return {'__bytes_hex__': value.hex()}
        if isinstance(value, bytearray):
            return {'__bytes_hex__': bytes(value).hex()}
        if isinstance(value, (str, int, float, bool)) or value is None:
            return value
        # Charm elements are not JSON-serializable without a group object here.
        # The row messages passed by DACP use stable digests/token ids, but this
        # fallback keeps the adapter usable for lightweight protocol metadata.
        return {'__repr__': repr(value)}
