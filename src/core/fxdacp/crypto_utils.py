"""Domain-separated KDF and AES-GCM helpers for FXDACP."""

import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .encoding import encode


def sha256(*parts):
    digest = hashlib.sha256()
    for part in parts:
        if not isinstance(part, bytes):
            raise TypeError("hash inputs must be bytes")
        digest.update(part)
    return digest.digest()


def kdf(domain, *parts, length=32):
    """Counter-mode SHA-256 KDF with explicit framing and domain separation."""
    if isinstance(domain, str):
        domain = domain.encode("ascii")
    material = encode([domain] + list(parts))
    output = b""
    counter = 1
    while len(output) < length:
        output += sha256(b"FXDACP-KDF-v1", counter.to_bytes(4, "big"), material)
        counter += 1
    return output[:length]


def aead_encrypt(key, plaintext, aad, nonce=None):
    nonce = nonce if nonce is not None else os.urandom(12)
    if len(nonce) != 12:
        raise ValueError("AES-GCM nonce must be 12 bytes")
    return {"nonce": nonce, "ciphertext": AESGCM(key).encrypt(nonce, plaintext, aad)}


def aead_decrypt(key, record, aad):
    try:
        nonce = record["nonce"]
        ciphertext = record["ciphertext"]
        if not isinstance(nonce, bytes) or len(nonce) != 12:
            return None
        if not isinstance(ciphertext, bytes):
            return None
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except Exception:
        return None


def constant_time_equal(left, right):
    return hmac.compare_digest(left, right)


def random_bytes(rng, length):
    if rng is None:
        return os.urandom(length)
    return bytes(rng.getrandbits(8) for _ in range(length))
