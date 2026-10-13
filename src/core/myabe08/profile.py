"""Frozen logical names and normative primitive choices, NOT backend claims.

Library availability is deliberately not used to enable a scheme profile.
Foundation V1 is frozen separately from incomplete scheme/TEE/AF protocols.
"""

from dataclasses import dataclass
from types import MappingProxyType
from typing import Optional

from .errors import BackendNotImplementedError, UnsupportedProfileError

SECURITY_PROFILE_BLS12_381 = "SECURITY_PROFILE_BLS12_381"
FABEO_COMPAT_PROFILE = "FABEO_COMPAT_PROFILE"
EMULATED_TEE_PROFILE = "EMULATED_TEE_PROFILE"
SGX_DEBUG_GRAMINE_V1 = "SGX_DEBUG_GRAMINE_V1"
MYABE08_ENCODING_V1 = "MYABE08_ENCODING_V1"
MYABE08_ROW_ABLATION_ENCODING_V1 = "MYABE08_ROW_ABLATION_TEST_ENCODING_V1"
H0_DST = b"MYABE08-H0-BLS12381-V1"
ROW_KDF_DOMAIN = "MYABE-ROW-KDF"
AF_NONCE_DOMAIN = "MYABE-AF-NONCE"


@dataclass(frozen=True)
class PairingProfile:
    name: str
    curve_id: str
    backend_id: str
    g1_bytes: Optional[int]
    g2_bytes: Optional[int]
    scalar_bytes: Optional[int]
    gt_bytes: Optional[int]
    implementation_status: str = "NOT_IMPLEMENTED"
    backend_status: str = "NOT_IMPLEMENTED"


@dataclass(frozen=True)
class TEEProfile:
    name: str = EMULATED_TEE_PROFILE
    boundary: str = "software emulation only"
    implementation_status: str = "EMULATED_PROTOCOL_CORE_ONLY"
    hardware_isolation: bool = False


@dataclass(frozen=True)
class CryptoSuite:
    """Algorithm identifiers are frozen; wire instances are still blocked."""

    context_hash: str = "SHA-256"
    digest: str = "SHA-256"
    hash_to_group: str = "BLS12381G1_XMD:SHA-256_SSWU_RO_; MYABE08-H0-BLS12381-V1"
    token_prf: str = "HMAC-SHA-256"
    revocation_prf: str = "HMAC-SHA-256 (independent key)"
    row_kdf: str = "domain-separated BLAKE2b-256"
    dem_kdf: str = "HKDF-SHA-256; salt=ctx_CT; info=MYABE-DEM; L=32"
    row_authenc: str = "AES-256-GCM-SIV"
    dem_authenc: str = "AES-256-GCM-SIV"
    signature: str = "Ed25519 (independent credential/publication/cap keys)"
    token_bytes: int = 32
    nonce_bytes: int = 12
    tag_bytes: int = 16
    wire_status: str = "FOUNDATION_V1_FROZEN; PHASE_3C_EMULATED_CORE_ONLY"


PAIRING_PROFILES = MappingProxyType({
    SECURITY_PROFILE_BLS12_381: PairingProfile(
        SECURITY_PROFILE_BLS12_381, "BLS12-381", "py_ecc-8.0.0",
        48, 96, 32, 576,
        backend_status="FOUNDATION_V1_IMPLEMENTED",
    ),
    FABEO_COMPAT_PROFILE: PairingProfile(
        FABEO_COMPAT_PROFILE, "MNT224", "Charm-Crypto/PBC (candidate)",
        None, None, None, None,
    ),
})
TEE_PROFILES = MappingProxyType({
    EMULATED_TEE_PROFILE: TEEProfile(),
    SGX_DEBUG_GRAMINE_V1: TEEProfile(
        SGX_DEBUG_GRAMINE_V1,
        "Gramine SGX DEBUG; test-only transport and freshness are not attested",
        "DEBUG_TRUSTED_CONTROL_PLANE_CORE", True),
})
CRYPTO_SUITE = CryptoSuite()


@dataclass(frozen=True)
class ProfileMeta:
    """Crypto object profile identity; TEE identity stays on a separate axis."""
    security_profile_id: str
    curve_id: str
    backend_id: str
    encoding_profile_id: str = MYABE08_ENCODING_V1

    def __post_init__(self):
        p = pairing_profile(self.security_profile_id)
        if (self.curve_id != p.curve_id or self.backend_id != p.backend_id
                or self.encoding_profile_id != MYABE08_ENCODING_V1):
            raise UnsupportedProfileError("inconsistent or unsupported ProfileMeta")


def pairing_profile(name: str) -> PairingProfile:
    if not isinstance(name, str) or name not in PAIRING_PROFILES:
        raise UnsupportedProfileError("unknown pairing profile: %r" % (name,))
    return PAIRING_PROFILES[name]


def tee_profile(name: str) -> TEEProfile:
    if not isinstance(name, str) or name not in TEE_PROFILES:
        raise UnsupportedProfileError("unknown TEE profile: %r" % (name,))
    return TEE_PROFILES[name]


def require_pairing_backend(name: str) -> None:
    profile = pairing_profile(name)
    raise BackendNotImplementedError(
        "%s scheme backend integration is not implemented; no fallback is permitted"
        % profile.name
    )
