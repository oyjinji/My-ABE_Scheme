"""Domain-separated crypto helpers; group operations remain real Charm calls."""

import hashlib
import hmac
import random

from charm.toolbox.pairinggroup import G1, ZR
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .encoding import canonical_attribute, encode, encode_group


def digest(domain, *parts):
    return hashlib.sha256(encode([domain] + list(parts))).digest()


def kdf(domain, *parts, length=32):
    return hashlib.blake2b(encode([domain] + list(parts)), digest_size=length).digest()


class ScalarSource:
    def __init__(self, group, seed=None):
        self.group = group
        self.seed = seed
        self.counter = 0

    def scalar(self, nonzero=False):
        while True:
            if self.seed is None:
                value = self.group.random(ZR)
            else:
                self.counter += 1
                material = digest("FXABE05.3/SCALAR", str(self.seed), self.counter).hex()
                value = self.group.hash("FX53-ZR-" + material, ZR)
            if not nonzero or value != 0:
                return value


class PairingOPRF:
    """Two-sided OPRF token algebra plus blind/evaluate/unblind boundaries."""

    def __init__(self, group):
        self.group = group

    def h1(self, encoded):
        return self.group.hash("FX53-H1-" + digest("FXABE05.3/H1", encoded).hex(), G1)

    def h0(self, token):
        raw = encode_group(self.group, token)
        return self.group.hash("FX53-H0-" + digest("FXABE05.3/H0", raw).hex(), G1)

    def direct(self, attribute, epoch, kappa, version="05.3"):
        return self.h1(canonical_attribute(attribute, epoch, version)) ** kappa

    def blind(self, attribute, epoch, scalar_source, version="05.3"):
        b = scalar_source.scalar(nonzero=True)
        point = self.h1(canonical_attribute(attribute, epoch, version))
        return point ** b, b

    @staticmethod
    def evaluate(blinded, kappa):
        return blinded ** kappa

    @staticmethod
    def unblind(evaluated, blind):
        return evaluated ** (1 / blind)

    def token_bytes(self, token):
        return self.group.serialize(token)


def seal(key, plaintext, aad, rng):
    nonce = bytes(rng.getrandbits(8) for _ in range(12))
    return {"nonce": nonce, "ciphertext": AESGCM(key).encrypt(nonce, plaintext, aad)}


def open_seal(key, record, aad):
    try:
        if set(record) != {"nonce", "ciphertext"} or len(record["nonce"]) != 12:
            return None
        return AESGCM(key).decrypt(record["nonce"], record["ciphertext"], aad)
    except Exception:
        return None


def ct_equal(left, right):
    return hmac.compare_digest(left, right)


def seeded_rng(seed=None):
    return random.SystemRandom() if seed is None else random.Random(seed)
