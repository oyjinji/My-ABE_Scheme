"""V1 foundation adapters and future protocol ports; no scheme algorithms."""

from typing import Protocol

from .types import G1Element, G2Element, GTElement, GroupBinding, Scalar


class PairingBackend(Protocol):
    """Strict Type-III adapter port. Python annotations do not validate points."""

    def random_scalar(self, *, binding: GroupBinding, nonzero: bool) -> Scalar:
        raise NotImplementedError

    def hash_to_g1(self, token: bytes, *, binding: GroupBinding) -> G1Element:
        """Real hash-to-curve with frozen suite/DST, not g1**public_hash."""
        raise NotImplementedError

    def import_g1(self, encoded: bytes, *, binding: GroupBinding,
                  allow_identity: bool) -> G1Element:
        raise NotImplementedError

    def import_g2(self, encoded: bytes, *, binding: GroupBinding,
                  allow_identity: bool) -> G2Element:
        raise NotImplementedError

    def import_gt(self, encoded: bytes, *, binding: GroupBinding) -> GTElement:
        raise NotImplementedError

    def pair(self, left: G1Element, right: G2Element) -> GTElement:
        """G1 x G2 order; count a pairing TERM per invocation."""
        raise NotImplementedError


class AuthEnc(Protocol):
    """Main profile MUST be AES-256-GCM-SIV, never substituted with GCM."""

    def encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, ad: bytes) -> bytes:
        raise NotImplementedError

    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, ad: bytes) -> bytes:
        """Authentication failure must reject, never return unauthenticated bytes."""
        raise NotImplementedError


class ContextualPRF(Protocol):
    def token(self, k_tok: bytes, sys_id: bytes, ctx_priv: bytes,
              canonical_attribute: bytes) -> bytes:
        """HMAC-SHA256(Encode(MYABE-TOK, SysID, ctx_priv, x)); no role/nonce."""
        raise NotImplementedError

    def revocation_handle(self, k_rev: bytes, sys_id: bytes, uid: str) -> bytes:
        """Independent key and RID domain; never emitted to host."""
        raise NotImplementedError


class KeyDerivation(Protocol):
    def row_key(self, ctx_af: bytes, token: bytes) -> bytes:
        """Domain-separated BLAKE2b-256; exact framing is an open source gap."""
        raise NotImplementedError

    def row_nonce(self, ctx_af: bytes, token: bytes) -> bytes:
        """Domain-separated deterministic 96-bit nonce, not stored in AF slots."""
        raise NotImplementedError

    def dem_key(self, ctx_ct: bytes, canonical_e: bytes) -> bytes:
        """HKDF-SHA256 salt=ctx_CT, IKM=E, info=MYABE-DEM, length=32."""
        raise NotImplementedError

# Concrete foundations use lazy third-party imports; package import stays cheap
# and no missing library can silently select a different cryptographic profile.
import hashlib
import hmac
import secrets
from dataclasses import dataclass

from .encoding import (
    encode_af_nonce_input, encode_dem_ad, encode_priv_context, encode_row_kdf_input,
    encode_token_input, require_bytes,
)
from .errors import AuthenticationError, BackendValidationError, ContractError, UnsupportedProfileError
from .profile import H0_DST, ProfileMeta, SECURITY_PROFILE_BLS12_381


def sha256_digest(data: bytes) -> bytes:
    """Hash exact bytes; callers use dedicated canonical encoders first."""
    require_bytes(data, "digest input")
    return hashlib.sha256(data).digest()


def context_hash(data: bytes) -> bytes:
    return sha256_digest(data)


def compute_ctx_priv(sys_id: bytes, policy_context_id: bytes, policy_version: int) -> bytes:
    return context_hash(encode_priv_context(sys_id, policy_context_id, policy_version))


def contextual_token(k_tok: bytes, sys_id: bytes, ctx_priv: bytes,
                     canonical_attribute: bytes) -> bytes:
    """One policy/user derivation; role/session/nonce intentionally absent."""
    require_bytes(k_tok, "K_tok", 32)
    return hmac.new(k_tok, encode_token_input(sys_id, ctx_priv, canonical_attribute),
                    hashlib.sha256).digest()


def derive_row_key(ctx_af: bytes, token: bytes) -> bytes:
    return hashlib.blake2b(encode_row_kdf_input(ctx_af, token), digest_size=32).digest()


def derive_af_nonce_material(ctx_af: bytes, token: bytes) -> bytes:
    return hashlib.blake2b(encode_af_nonce_input(ctx_af, token), digest_size=32).digest()


def derive_af_nonce(ctx_af: bytes, token: bytes) -> bytes:
    return derive_af_nonce_material(ctx_af, token)[:12]


class AES256GCMSIV:
    """Exact AES-256-GCM-SIV adapter. Never substitutes AES-GCM."""
    def __init__(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
        self._implementation = AESGCMSIV

    def _validate(self, key, nonce, payload, ad):
        require_bytes(key, "AES-256 key", 32)
        require_bytes(nonce, "GCM-SIV nonce", 12)
        require_bytes(payload, "AEAD payload")
        require_bytes(ad, "AEAD AD")

    def encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, ad: bytes) -> bytes:
        self._validate(key, nonce, plaintext, ad)
        if not plaintext:
            # cryptography 42.0.8's real API rejects zero-length input.
            # Do not invent an implementation or silently switch algorithms.
            raise ContractError("V1 adapter requires nonempty plaintext (library limitation)")
        return self._implementation(key).encrypt(nonce, plaintext, ad)

    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, ad: bytes) -> bytes:
        from cryptography.exceptions import InvalidTag
        self._validate(key, nonce, ciphertext, ad)
        if len(ciphertext) <= 16:
            raise AuthenticationError("empty or truncated GCM-SIV ciphertext/tag")
        try:
            return self._implementation(key).decrypt(nonce, ciphertext, ad)
        except InvalidTag as exc:
            raise AuthenticationError("GCM-SIV authentication failed") from exc


def derive_dem_key(ctx_ct: bytes, canonical_e: bytes) -> bytes:
    """IKM is backend-validated GT serialization, not a textual representation.

    This KDF enforces byte width; subgroup/field checks belong to the backend.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    require_bytes(ctx_ct, "ctx_CT", 32)
    require_bytes(canonical_e, "canonical GT", 576)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=ctx_ct,
                info=b"MYABE-DEM").derive(canonical_e)


@dataclass(frozen=True)
class DEMCiphertext:
    nonce: bytes
    ciphertext: bytes


def dem_encrypt(ctx_ct: bytes, canonical_e: bytes, plaintext: bytes) -> DEMCiphertext:
    """Fresh CSPRNG nonce; caller cannot supply the AF deterministic nonce."""
    key = derive_dem_key(ctx_ct, canonical_e)
    ad = encode_dem_ad(ctx_ct)
    nonce = secrets.token_bytes(12)
    return DEMCiphertext(nonce, AES256GCMSIV().encrypt(key, nonce, plaintext, ad))


def dem_decrypt(ctx_ct: bytes, canonical_e: bytes, sealed: DEMCiphertext) -> bytes:
    if type(sealed) is not DEMCiphertext:
        raise ContractError("expected DEMCiphertext")
    return AES256GCMSIV().decrypt(derive_dem_key(ctx_ct, canonical_e), sealed.nonce,
                                  sealed.ciphertext, encode_dem_ad(ctx_ct))


class BLS12381Backend:
    """Strict encoded-object adapter, mathematical public API G1 x G2 -> GT.

    All operations revalidate untrusted DTO bytes, subgroup and full binding.
    Raw serialization has the fixed mathematical width: transport MUST retain
    authenticated binding metadata separately; bytes alone cannot prove SysID.
    Pure Python/py_ecc is not constant-time and is not a production TEE backend.
    """
    def __init__(self, sys_id: bytes, *, profile_meta: ProfileMeta = None):
        import py_ecc
        from py_ecc import optimized_bls12_381 as bls
        from py_ecc.bls import point_compression
        from py_ecc.bls.hash_to_curve import hash_to_G1
        if py_ecc.__version__ != "8.0.0":
            raise UnsupportedProfileError("V1 requires py_ecc 8.0.0")
        expected = ProfileMeta(SECURITY_PROFILE_BLS12_381, "BLS12-381", "py_ecc-8.0.0")
        if profile_meta is None:
            profile_meta = expected
        if type(profile_meta) is not ProfileMeta or profile_meta != expected:
            raise UnsupportedProfileError("unsupported BLS foundation ProfileMeta")
        self._binding = GroupBinding(sys_id, profile_meta.security_profile_id,
                                     profile_meta.curve_id, profile_meta.backend_id,
                                     profile_meta.encoding_profile_id)
        self._b = bls
        self._pc = point_compression
        self._hash_to_g1 = hash_to_G1

    @property
    def binding(self) -> GroupBinding:
        return self._binding

    @property
    def scalar_order(self) -> int:
        return self._b.curve_order

    def _check_binding(self, binding):
        if type(binding) is not GroupBinding or binding != self.binding:
            raise BackendValidationError("cross-SysID/ProfileMeta object rejected")

    def _bytes(self, data, width):
        if type(data) is not bytes or len(data) != width:
            raise BackendValidationError("wrong canonical byte type/length")

    def _bound(self, value, cls):
        if type(value) is not cls:
            raise BackendValidationError("wrong mathematical group/type")
        self._check_binding(value.binding)

    def _scalar_value(self, value):
        self._bound(value, Scalar)
        self._bytes(value.encoded, 32)
        integer = int.from_bytes(value.encoded, "big")
        if integer >= self.scalar_order:
            raise BackendValidationError("scalar outside canonical field range")
        return integer

    def scalar_from_int(self, value: int) -> Scalar:
        if type(value) is not int or not 0 <= value < self.scalar_order:
            raise BackendValidationError("scalar integer out of range (no coercion)")
        return Scalar(self.binding, value.to_bytes(32, "big"))

    def scalar_random_nonzero(self) -> Scalar:
        return self.scalar_from_int(secrets.randbelow(self.scalar_order - 1) + 1)

    def random_scalar(self, *, binding: GroupBinding, nonzero: bool) -> Scalar:
        self._check_binding(binding)
        if type(nonzero) is not bool:
            raise BackendValidationError("nonzero must be bool")
        return self.scalar_random_nonzero() if nonzero else self.scalar_from_int(secrets.randbelow(self.scalar_order))

    def scalar_add(self, left: Scalar, right: Scalar) -> Scalar:
        return self.scalar_from_int((self._scalar_value(left) + self._scalar_value(right)) % self.scalar_order)

    def scalar_mul(self, left: Scalar, right: Scalar) -> Scalar:
        return self.scalar_from_int((self._scalar_value(left) * self._scalar_value(right)) % self.scalar_order)

    def scalar_inv(self, value: Scalar) -> Scalar:
        n = self._scalar_value(value)
        if n == 0:
            raise BackendValidationError("zero scalar has no inverse")
        return self.scalar_from_int(pow(n, -1, self.scalar_order))

    def serialize_scalar(self, value: Scalar) -> bytes:
        self._scalar_value(value)
        return value.encoded

    def deserialize_scalar(self, data: bytes, *, binding: GroupBinding,
                           allow_zero: bool = True) -> Scalar:
        self._check_binding(binding)
        result = Scalar(binding, data)
        value = self._scalar_value(result)
        if type(allow_zero) is not bool or (not allow_zero and value == 0):
            raise BackendValidationError("zero scalar forbidden or invalid policy")
        return result

    def _g1_bytes(self, point):
        return int(self._pc.compress_G1(point)).to_bytes(48, "big")

    def _g2_bytes(self, point):
        z1, z2 = self._pc.compress_G2(point)
        return int(z1).to_bytes(48, "big") + int(z2).to_bytes(48, "big")

    def _point(self, value, cls, allow_identity=True):
        self._bound(value, cls)
        self._bytes(value.encoded, 48 if cls is G1Element else 96)
        if type(allow_identity) is not bool:
            raise BackendValidationError("allow_identity must be bool")
        try:
            if cls is G1Element:
                point = self._pc.decompress_G1(int.from_bytes(value.encoded, "big"))
                curve_b, recode = self._b.b, self._g1_bytes
            else:
                point = self._pc.decompress_G2((int.from_bytes(value.encoded[:48], "big"),
                                               int.from_bytes(value.encoded[48:], "big")))
                curve_b, recode = self._b.b2, self._g2_bytes
            if (not self._b.is_on_curve(point, curve_b)
                    or not self._b.is_inf(self._b.multiply(point, self.scalar_order))
                    or recode(point) != value.encoded
                    or (not allow_identity and self._b.is_inf(point))):
                raise BackendValidationError("invalid curve/subgroup/canonical/identity point")
            return point
        except (ValueError, TypeError, OverflowError) as exc:
            raise BackendValidationError("invalid compressed point") from exc

    def g1_generator(self) -> G1Element:
        return G1Element(self.binding, self._g1_bytes(self._b.G1))

    def g2_generator(self) -> G2Element:
        return G2Element(self.binding, self._g2_bytes(self._b.G2))

    def g1_mul(self, point: G1Element, scalar: Scalar) -> G1Element:
        p, s = self._point(point, G1Element), self._scalar_value(scalar)
        return G1Element(self.binding, self._g1_bytes(self._b.multiply(p, s)))

    def g2_mul(self, point: G2Element, scalar: Scalar) -> G2Element:
        p, s = self._point(point, G2Element), self._scalar_value(scalar)
        return G2Element(self.binding, self._g2_bytes(self._b.multiply(p, s)))

    def g1_add(self, left: G1Element, right: G1Element) -> G1Element:
        p, q = self._point(left, G1Element), self._point(right, G1Element)
        return G1Element(self.binding, self._g1_bytes(self._b.add(p, q)))

    def g2_add(self, left: G2Element, right: G2Element) -> G2Element:
        p, q = self._point(left, G2Element), self._point(right, G2Element)
        return G2Element(self.binding, self._g2_bytes(self._b.add(p, q)))

    def serialize_g1(self, value: G1Element, *, allow_identity: bool = True) -> bytes:
        self._point(value, G1Element, allow_identity)
        return value.encoded

    def serialize_g2(self, value: G2Element, *, allow_identity: bool = True) -> bytes:
        self._point(value, G2Element, allow_identity)
        return value.encoded

    def deserialize_g1(self, data: bytes, *, binding: GroupBinding,
                       allow_identity: bool = True) -> G1Element:
        result = G1Element(binding, data)
        self._point(result, G1Element, allow_identity)
        return result

    def deserialize_g2(self, data: bytes, *, binding: GroupBinding,
                       allow_identity: bool = True) -> G2Element:
        result = G2Element(binding, data)
        self._point(result, G2Element, allow_identity)
        return result

    def import_g1(self, encoded: bytes, *, binding: GroupBinding,
                  allow_identity: bool) -> G1Element:
        return self.deserialize_g1(encoded, binding=binding, allow_identity=allow_identity)

    def import_g2(self, encoded: bytes, *, binding: GroupBinding,
                  allow_identity: bool) -> G2Element:
        return self.deserialize_g2(encoded, binding=binding, allow_identity=allow_identity)

    def _gt_bytes(self, value):
        return b"".join(int(c).to_bytes(48, "big") for c in value.coeffs)

    def _gt(self, value, allow_identity=True):
        self._bound(value, GTElement)
        self._bytes(value.encoded, 576)
        if type(allow_identity) is not bool:
            raise BackendValidationError("allow_identity must be bool")
        coeffs = tuple(int.from_bytes(value.encoded[i:i + 48], "big") for i in range(0, 576, 48))
        if any(c >= self._b.field_modulus for c in coeffs):
            raise BackendValidationError("noncanonical GT coefficient")
        gt = self._b.FQ12(coeffs)
        if (gt == self._b.FQ12.zero() or gt ** self.scalar_order != self._b.FQ12.one()
                or (not allow_identity and gt == self._b.FQ12.one())):
            raise BackendValidationError("GT outside multiplicative r subgroup or forbidden identity")
        return gt

    def serialize_gt(self, value: GTElement, *, allow_identity: bool = True) -> bytes:
        self._gt(value, allow_identity)
        return value.encoded

    def deserialize_gt(self, data: bytes, *, binding: GroupBinding,
                       allow_identity: bool = True) -> GTElement:
        result = GTElement(binding, data)
        self._gt(result, allow_identity)
        return result

    def import_gt(self, encoded: bytes, *, binding: GroupBinding) -> GTElement:
        return self.deserialize_gt(encoded, binding=binding)

    def pair(self, left: G1Element, right: G2Element) -> GTElement:
        p, q = self._point(left, G1Element), self._point(right, G2Element)
        # py_ecc is Q(G2), P(G1); ONLY this adapter reverses the public order.
        return GTElement(self.binding, self._gt_bytes(self._b.pairing(q, p, final_exponentiate=True)))

    def gt_pow(self, value: GTElement, exponent: Scalar) -> GTElement:
        return GTElement(self.binding, self._gt_bytes(self._gt(value) ** self._scalar_value(exponent)))

    def gt_mul(self, left: GTElement, right: GTElement) -> GTElement:
        return GTElement(self.binding, self._gt_bytes(self._gt(left) * self._gt(right)))

    def gt_div(self, numerator: GTElement, denominator: GTElement) -> GTElement:
        """GT field division, with strict binding/subgroup validation."""
        return GTElement(self.binding, self._gt_bytes(self._gt(numerator) / self._gt(denominator)))

    def hash_to_g1(self, token: bytes, *, binding: GroupBinding = None) -> G1Element:
        if binding is not None:
            self._check_binding(binding)
        require_bytes(token, "H0 token", 32)
        point = self._hash_to_g1(token, H0_DST, hashlib.sha256)
        result = G1Element(self.binding, self._g1_bytes(point))
        self._point(result, G1Element, allow_identity=False)
        return result
