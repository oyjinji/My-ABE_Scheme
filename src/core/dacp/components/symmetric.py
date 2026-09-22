'''
Replaceable symmetric envelopes for DACP.

PrototypeGTEnvelope keeps the current Charm GT benchmark behavior:
C_sym = msg * E and msg = C_sym / E, with a hash tag as a structural check.
It is not AEAD. AESGCMEnvelope provides a real KDF + AES-GCM envelope for
bytes plaintexts in protocol-level benchmarks.
'''

import hashlib
import os

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # pragma: no cover - exercised only when dependency lacks.
    AESGCM = None


class SymmetricEnvelope:
    def seal(self, msg, shared_secret, aad=None, **kwargs):
        raise NotImplementedError

    def open(self, ciphertext, shared_secret, aad=None, **kwargs):
        raise NotImplementedError


class PrototypeGTEnvelope(SymmetricEnvelope):
    def __init__(self, group):
        self.group = group

    def seal(self, msg, shared_secret, aad=None, **kwargs):
        nonce = kwargs.get('nonce') or os.urandom(16).hex()
        C_sym = msg * shared_secret
        K_ses = self.kdf(shared_secret)
        tag = self.tag(K_ses, nonce, C_sym, aad or b'', msg)
        return {
            'C_sym': C_sym,
            'nonce_AEAD': nonce,
            'aead_tag': tag,
            'K_ses': K_ses,
        }

    def open(self, ciphertext, shared_secret, aad=None, **kwargs):
        C_sym = ciphertext['C_sym']
        msg = C_sym / shared_secret
        K_ses = self.kdf(shared_secret)
        expected = self.tag(K_ses, ciphertext['nonce_AEAD'], C_sym, aad or b'', msg)
        if expected != ciphertext['aead_tag']:
            return None
        return msg

    def kdf(self, element):
        return hashlib.sha256(b'dacp::KDF::' + self.group.serialize(element)).hexdigest()

    def tag(self, K_ses, nonce, C_sym, aad, msg):
        digest = hashlib.sha256()
        digest.update(b'dacp::AEAD::')
        digest.update(str(K_ses).encode('utf-8'))
        digest.update(str(nonce).encode('utf-8'))
        digest.update(self.group.serialize(C_sym))
        digest.update(aad or b'')
        digest.update(self.group.serialize(msg))
        return digest.hexdigest()


class AESGCMEnvelope(SymmetricEnvelope):
    """
    KDF + AES-GCM envelope for bytes plaintexts.

    This is a real AEAD primitive, but the surrounding DACP protocol is still a
    local simulation. The KDF falls back to repr(shared_secret) only for local
    benchmark compatibility when Charm serialization is unavailable.
    """

    def __init__(self, key_len=32, nonce_len=12, group=None):
        if AESGCM is None:
            raise RuntimeError(
                'AESGCMEnvelope requires the cryptography package. '
                'Install it with: pip install cryptography'
            )
        if int(key_len) not in (16, 24, 32):
            raise ValueError('AES-GCM key_len must be 16, 24, or 32 bytes')
        self.key_len = int(key_len)
        self.nonce_len = int(nonce_len)
        self.group = group

    def set_group(self, group):
        self.group = group

    def kdf(self, shared_secret, context=b""):
        if isinstance(context, str):
            context = context.encode('utf-8')
        digest = hashlib.sha256()
        digest.update(b'dacp::AESGCM::KDF::')
        digest.update(self._secret_bytes(shared_secret))
        digest.update(context or b'')
        return digest.digest()[:self.key_len]

    def seal(self, msg, shared_secret, aad=None, **kwargs):
        if not isinstance(msg, bytes):
            raise TypeError('AESGCMEnvelope requires bytes plaintext')
        nonce = kwargs.get('nonce') or os.urandom(self.nonce_len)
        if isinstance(nonce, str):
            nonce = bytes.fromhex(nonce)
        aad_bytes = self._aad_bytes(aad)
        key = self.kdf(shared_secret, context=aad_bytes)
        ciphertext = AESGCM(key).encrypt(nonce, msg, aad_bytes)
        return {
            'mode': 'AESGCM',
            'nonce': nonce.hex(),
            'ciphertext': ciphertext.hex(),
            # Compatibility aliases consumed by DACPCPABE ciphertext fields.
            'nonce_AEAD': nonce.hex(),
            'C_sym': ciphertext.hex(),
            'aead_tag': 'AESGCM',
        }

    def open(self, ciphertext, shared_secret, aad=None, **kwargs):
        try:
            nonce = ciphertext.get('nonce', ciphertext.get('nonce_AEAD'))
            ct = ciphertext.get('ciphertext', ciphertext.get('C_sym'))
            nonce_bytes = self._decode_bytes(nonce)
            ciphertext_bytes = self._decode_bytes(ct)
            aad_bytes = self._aad_bytes(aad)
            key = self.kdf(shared_secret, context=aad_bytes)
            return AESGCM(key).decrypt(nonce_bytes, ciphertext_bytes, aad_bytes)
        except Exception:
            return None

    def _secret_bytes(self, shared_secret):
        if self.group is not None:
            try:
                return self.group.serialize(shared_secret)
            except Exception:
                pass
        # Fallback is benchmark-only; production wire formats should serialize
        # pairing elements explicitly and canonically.
        return repr(shared_secret).encode('utf-8')

    def _aad_bytes(self, aad):
        if aad is None:
            return b''
        if isinstance(aad, bytes):
            return aad
        if isinstance(aad, bytearray):
            return bytes(aad)
        if isinstance(aad, str):
            return aad.encode('utf-8')
        return repr(aad).encode('utf-8')

    def _decode_bytes(self, value):
        if isinstance(value, bytes):
            return value
        if isinstance(value, bytearray):
            return bytes(value)
        if isinstance(value, str):
            return bytes.fromhex(value)
        raise TypeError('expected bytes or hex string')
