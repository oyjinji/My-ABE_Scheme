"""Canonical DTO shape tests ONLY: fixture bytes are NOT valid crypto objects."""

from dataclasses import FrozenInstanceError, fields, replace

import pytest

from core.myabe08.errors import ContractError
from core.myabe08.profile import (
    CRYPTO_SUITE, EMULATED_TEE_PROFILE, PAIRING_PROFILES, SECURITY_PROFILE_BLS12_381,
)
from core.myabe08.types import (
    AFParameters, Attribute, AuthorizationBundle, Ciphertext, CiphertextHeader,
    Credential, G1Element, G2Element, GroupBinding, GTElement, PolicyContext,
    ProfileMetadata, ProtectedAnonymousFilter, PublicParameters, SealedUserBlob,
    SignedCapability, TEEAuthorization, TEEState, UserBaseState, Validity,
)


def test_canonical_type_construction_is_structural_not_crypto_validation():
    p = PAIRING_PROFILES[SECURITY_PROFILE_BLS12_381]
    binding = GroupBinding(b"TEST-ONLY-SYS", p.name, p.curve_id, p.backend_id)
    meta = ProfileMetadata(p.name, EMULATED_TEE_PROFILE, "UNRESOLVED")
    af = AFParameters(8)
    # Deliberately not valid points: constructors do NOT claim subgroup checks.
    g1, g2, gt = G1Element(binding, b"test"), G2Element(binding, b"test"), GTElement(binding, b"test")
    pp = PublicParameters(binding, g1, g2, g1, g2, gt, b"pk", b"pk-cap", af, meta)
    assert pp.g2_a is g2
    assert type(pp.g1) is not type(pp.g2)
    context = PolicyContext(binding.sys_id, b"c" * 32, 1, b"h" * 32)
    assert context == PolicyContext(binding.sys_id, b"c" * 32, 1, b"h" * 32)
    with pytest.raises(FrozenInstanceError):
        context.policy_version = 2
    assert af.plaintext_bytes == 36 and af.payload_bytes == 52
    with pytest.raises(ContractError):
        AFParameters(True)
    with pytest.raises(ContractError):
        PolicyContext(binding.sys_id, b"short", 1, b"h" * 32)
    with pytest.raises(ContractError):
        replace(binding, curve_id="MNT224")
    with pytest.raises(ContractError):
        replace(meta, crypto_suite=replace(CRYPTO_SUITE, row_authenc="AES-GCM"))


def test_certified_attribute_set_shape_and_private_repr():
    a, b = Attribute("ns", "role", "a"), Attribute("ns", "role", "b")
    cred = Credential(b"sys", "PRIVATE-UID", (a, b), Validity(1, 2), 1,
                      b"auth", b"NOT-A-SIGNATURE")
    assert "PRIVATE-UID" not in repr(cred)
    assert "SECRET-BLOB" not in repr(SealedUserBlob(b"SECRET-BLOB"))
    for attributes in ((b, a), (a, a), [a, b]):
        with pytest.raises(ContractError):
            replace(cred, attributes=attributes)


def test_public_transcript_schemas_exclude_long_term_private_identifiers():
    forbidden = {
        "uid", "identity", "revocation_handle", "rh_id", "k0", "k0_q",
        "mu", "mu_q", "delta_q", "credential", "credential_digest",
        "blob", "blob_digest", "attributes", "row_labels", "recovery_key",
    }
    for cls in (CiphertextHeader, Ciphertext, ProtectedAnonymousFilter,
                SignedCapability, AuthorizationBundle, TEEAuthorization):
        assert not forbidden & {f.name for f in fields(cls)}
    assert {f.name for f in fields(ProtectedAnonymousFilter)} == {"slots", "metadata"}
    for cls in (CiphertextHeader, Ciphertext):
        assert "rev_version" not in {f.name for f in fields(cls)}
    assert "c" not in {f.name for f in fields(Ciphertext)}


def test_tee_private_schema_does_not_receive_master_or_recovery_secrets():
    forbidden = {"alpha", "a", "msk", "recovery_key", "rk", "z", "z_inverse", "message"}
    for cls in (TEEState, UserBaseState):
        assert not forbidden & {f.name for f in fields(cls)}
    assert "rev_set" in {f.name for f in fields(TEEState)}
    assert "credential_versions" in {f.name for f in fields(TEEState)}


def test_required_structured_types_exist():
    from dataclasses import is_dataclass
    from core.myabe08 import metrics, types
    for name in (
        "PublicParameters", "MasterSecretKey", "KGCState", "TEEState", "Credential",
        "SealedUserBlob", "RecoveryKey", "PolicyContext", "PolicyEncoding",
        "CiphertextHeader", "Ciphertext", "ProtectedAnonymousFilter", "TEERequest",
        "TEEAuthorization", "SignedCapability", "PartialCiphertext",
    ):
        assert is_dataclass(getattr(types, name))
    for name in ("TransformMetrics", "TEEMetrics", "AFMetrics", "OperationCounts"):
        assert is_dataclass(getattr(metrics, name))
