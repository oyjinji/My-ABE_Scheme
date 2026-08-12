"""Hash, deterministic scalar source, KDF and AES-GCM helpers."""

import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from charm.toolbox.pairinggroup import ZR

from .encoding import encode


def sha256(*parts):
    h = hashlib.sha256()
    for part in parts:
        if not isinstance(part, bytes):
            raise TypeError("hash input must be bytes")
        h.update(part)
    return h.digest()


def kdf(domain, *parts, length=32):
    material = encode([domain] + list(parts))
    out = b""
    counter = 1
    while len(out) < length:
        out += sha256(b"FXABE-KDF-v1", counter.to_bytes(4, "big"), material)
        counter += 1
    return out[:length]


def aead_encrypt(key, plaintext, aad, nonce):
    if len(nonce) != 12:
        raise ValueError("AES-GCM nonce must be 12 bytes")
    return {"nonce": nonce, "ciphertext": AESGCM(key).encrypt(nonce, plaintext, aad)}


def aead_decrypt(key, record, aad):
    try:
        if len(record["nonce"]) != 12:
            return None
        return AESGCM(key).decrypt(record["nonce"], record["ciphertext"], aad)
    except Exception:
        return None


def random_bytes(rng, size):
    if rng is None:
        return os.urandom(size)
    return bytes(rng.getrandbits(8) for _ in range(size))


def equal(left, right):
    return hmac.compare_digest(left, right)


class ScalarSource:
    """Reproducible scalar generation while retaining real Charm operations."""

    def __init__(self, group, seed=None):
        self.group = group
        self.seed = None if seed is None else str(seed).encode("utf-8")
        self.counter = 0

    def scalar(self, nonzero=False):
        while True:
            if self.seed is None:
                value = self.group.random(ZR)
            else:
                self.counter += 1
                digest = hashlib.sha256(
                    encode(["FXABE-Scalar-v1", self.seed, self.counter])
                ).hexdigest()
                # Charm 0.63's MNT224 byte-input hashing is not reliably
                # domain-sensitive; feed the digest as an ASCII string.
                value = self.group.hash("FXABE-ZR-" + digest, ZR)
            if not nonzero or value != 0:
                return value
