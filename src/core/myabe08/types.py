"""Explicit trust-domain DTOs, not cryptographically validated wire objects.

Construction checks only selected shape constraints. Signatures, canonical
group encodings, subgroup/identity checks and context/digest verification must
run at protocol boundaries in Phase 2. No generic serializer is provided.
Secret repr suppression is hygiene, NOT Python memory protection/zeroization.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import FrozenSet, Optional, Tuple

from .errors import ContractError
from .profile import (
    CRYPTO_SUITE, CryptoSuite, MYABE08_ENCODING_V1, ProfileMeta,
    pairing_profile, tee_profile,
)

Matrix = Tuple[Tuple[int, ...], ...]


def _positive(value: int, name: str) -> None:
    if type(value) is not int or value < 1:
        raise ContractError(name + " must be a positive integer")


def _bytes(value: bytes, name: str, width: Optional[int] = None) -> None:
    if type(value) is not bytes or not value or (width is not None and len(value) != width):
        raise ContractError(name + " must be nonempty bytes of the required width")


@dataclass(frozen=True)
class GroupBinding:
    sys_id: bytes
    security_profile_id: str
    curve_id: str
    backend_id: str
    encoding_profile_id: str = MYABE08_ENCODING_V1

    def __post_init__(self):
        _bytes(self.sys_id, "SysID")
        p = pairing_profile(self.security_profile_id)
        if self.curve_id != p.curve_id or self.backend_id != p.backend_id:
            raise ContractError("group binding does not match the named profile")
        self.profile_meta  # Validate the encoding axis too.

    @property
    def profile_meta(self) -> ProfileMeta:
        return ProfileMeta(self.security_profile_id, self.curve_id,
                           self.backend_id, self.encoding_profile_id)


@dataclass(frozen=True)
class G1Element:
    binding: GroupBinding
    encoded: bytes  # Unvalidated until the backend's strict import boundary.


@dataclass(frozen=True)
class G2Element:
    binding: GroupBinding
    encoded: bytes


@dataclass(frozen=True)
class GTElement:
    binding: GroupBinding
    encoded: bytes


@dataclass(frozen=True)
class Scalar:
    binding: GroupBinding
    encoded: bytes = field(repr=False)


@dataclass(frozen=True, order=True)
class Attribute:
    """Logical attribute fields; normalization/wire bytes remain unresolved."""

    namespace: str
    name: str
    value: str


@dataclass(frozen=True)
class AFParameters:
    c_max: int
    profile_id: str = field(default="MYABE05.3-SEGMENTED-XOR-V1", init=False)
    max_seed_attempts: int = field(default=32, init=False)
    row_width_bytes: int = field(default=4, init=False)
    authenc_id: str = field(default="AES-256-GCM-SIV", init=False)
    tag_bytes: int = field(default=16, init=False)

    def __post_init__(self):
        _positive(self.c_max, "c_max")
        if self.c_max > 0xFFFFFFFF:
            raise ContractError("c_max exceeds uint32 length field")

    @property
    def plaintext_bytes(self) -> int:
        return 4 * (self.c_max + 1)

    @property
    def payload_bytes(self) -> int:
        return self.plaintext_bytes + 16


@dataclass(frozen=True)
class ProfileMetadata:
    pairing_profile_id: str
    tee_profile_id: str
    encoding_version: str  # Cannot become operational until wire gap is closed.
    crypto_suite: CryptoSuite = CRYPTO_SUITE

    def __post_init__(self):
        pairing_profile(self.pairing_profile_id)
        tee_profile(self.tee_profile_id)
        if self.crypto_suite != CRYPTO_SUITE:
            raise ContractError("the main profile forbids primitive substitution")


@dataclass(frozen=True)
class PublicParameters:
    binding: GroupBinding
    g1: G1Element
    g2: G2Element
    g1_a: G1Element
    g2_a: G2Element
    gt_alpha: GTElement
    pk_kgc: bytes
    pk_cap: bytes
    af_parameters: AFParameters
    profile: ProfileMetadata
    # H0, Digest, PRF, KDF and AuthEnc identifiers live in profile.crypto_suite;
    # backend H0 suite/DST must be resolved before Setup becomes operational.


@dataclass(frozen=True)
class MasterSecretKey:
    alpha: Scalar = field(repr=False)
    a: Scalar = field(repr=False)
    sk_kgc: bytes = field(repr=False)


@dataclass(frozen=True)
class Validity:
    """API-level UTC integer seconds; no trusted-clock assertion at construction."""

    not_before: int
    not_after: int

    def __post_init__(self):
        if (type(self.not_before) is not int or type(self.not_after) is not int
                or not 0 <= self.not_before < self.not_after):
            raise ContractError("invalid validity interval")


@dataclass(frozen=True)
class Credential:
    """DU/KGC/TEE-private, NEVER a cleartext CSP RPC/log record."""

    sys_id: bytes
    uid: str = field(repr=False)
    attributes: Tuple[Attribute, ...] = field(repr=False)
    validity: Validity
    credential_version: int
    pk_auth: bytes = field(repr=False)
    signature: bytes = field(repr=False)

    def __post_init__(self):
        _positive(self.credential_version, "credential_version")
        if (type(self.attributes) is not tuple
                or any(type(a) is not Attribute for a in self.attributes)
                or self.attributes != tuple(sorted(set(self.attributes)))):
            raise ContractError("certified attributes must be a sorted unique tuple")


@dataclass(frozen=True)
class SealedUserBlob:
    """User-carried opaque record: ciphertext itself is a stable identifier.

    Only send through the confidential DU->TEE boundary, never host logs.
    """

    opaque: bytes = field(repr=False)


@dataclass(frozen=True)
class RecoveryKey:
    binding: GroupBinding
    z_inverse: Scalar = field(repr=False)  # KGC->DU only; never TEE input.


@dataclass(frozen=True)
class UserBaseState:
    """Unsealed TEE-only schema; no RK, z, alpha or a."""

    sys_id: bytes
    uid_handle: str = field(repr=False)
    mu: Scalar = field(repr=False)
    k0: G2Element = field(repr=False)
    credential_digest: bytes = field(repr=False)
    credential_version: int
    schema_version: str
    profile_id: str


@dataclass(frozen=True)
class CredentialVersionRecord:
    uid: str = field(repr=False)
    version: int
    credential_digest: bytes = field(repr=False)


@dataclass(frozen=True)
class RegistrationRecord:
    uid: str = field(repr=False)
    certified_attributes: Tuple[Attribute, ...] = field(repr=False)
    pk_auth: bytes = field(repr=False)
    revocation_handle: bytes = field(repr=False)
    credential_version: int


@dataclass(frozen=True)
class NamespaceCertificate:
    sys_id: bytes
    namespace: str
    publisher_public_key: bytes
    validity: Validity
    kgc_signature: bytes
    cert_version: int = 1


class RevocationOperation(str, Enum):
    REVOKE = "revoke"
    ACTIVATE = "activate"


@dataclass(frozen=True)
class RevocationUpdate:
    """Confidential authenticated fixed-schema delta; NOT a public KU."""

    protected_record: bytes = field(repr=False)


@dataclass(frozen=True)
class PendingRevocation:
    version: int
    previous_state_digest: bytes
    update: RevocationUpdate


@dataclass(frozen=True)
class KGCState:
    sys_id: bytes
    registrations: Tuple[RegistrationRecord, ...] = field(repr=False)
    do_namespaces: Tuple[NamespaceCertificate, ...]
    committed_rev_version: int
    committed_state_digest: bytes
    pending_updates: Tuple[PendingRevocation, ...] = field(repr=False)


@dataclass(frozen=True)
class RequestRecord:
    """Internal replay record, indexed by random request nonce, not UID."""

    request_nonce: bytes
    expiry: int


@dataclass(frozen=True)
class RevocationAck:
    version: int
    state_digest: bytes
    authenticated_record: bytes = field(repr=False)


@dataclass(frozen=True)
class TEEState:
    """Trusted-domain snapshot only; this class does not provide isolation."""

    sys_id: bytes
    profile: ProfileMetadata
    k_tok: bytes = field(repr=False)
    k_rev: bytes = field(repr=False)
    sk_cap: bytes = field(repr=False)
    sealing_key: bytes = field(repr=False)
    rev_set: FrozenSet[bytes] = field(repr=False)  # exact handles, not Bloom
    rev_version: int
    state_digest: bytes
    credential_versions: Tuple[CredentialVersionRecord, ...] = field(repr=False)
    issued_requests: Tuple[RequestRecord, ...] = field(repr=False)
    committed_acks: Tuple[RevocationAck, ...] = field(repr=False)
    # User base-state is carried in sealed blobs, not a host UID-indexed cache.

    def __post_init__(self):
        if type(self.rev_set) is not frozenset:
            raise ContractError("RevSet snapshot must be an exact frozenset")
        if type(self.rev_version) is not int or self.rev_version < 0:
            raise ContractError("rev_version must be a nonnegative integer")


@dataclass(frozen=True)
class PolicyContext:
    sys_id: bytes
    policy_context_id: bytes
    policy_version: int
    ctx_priv: bytes  # Claimed digest: recomputation is a protocol obligation.

    def __post_init__(self):
        _bytes(self.policy_context_id, "PolicyContextID")
        if len(self.policy_context_id) < 32:
            raise ContractError("PolicyContextID requires at least 256 bits")
        _positive(self.policy_version, "PolicyVersion")
        _bytes(self.ctx_priv, "ctx_priv", 32)


@dataclass(frozen=True)
class PolicyInput:
    """DO-private (A,rho). Never carried inside Ciphertext."""

    matrix: Matrix
    row_labels: Tuple[Attribute, ...] = field(repr=False)


@dataclass(frozen=True)
class EncodedPolicyRow:
    token: bytes
    q_tau: G1Element
    occurrence_rank: int  # rank in COMPLETE policy, never recomputed in J/I


@dataclass(frozen=True)
class PolicyEncoding:
    """Ephemeral DO build input; must not be retained in published AF/CT."""

    context: PolicyContext
    matrix: Matrix
    rows: Tuple[EncodedPolicyRow, ...] = field(repr=False)


@dataclass(frozen=True)
class AFHeader:
    sys_id: bytes
    ctx_priv: bytes
    matrix_digest: bytes
    ell: int
    distinct_tokens: int
    parameters: AFParameters


@dataclass(frozen=True)
class AFMetadata:
    profile_id: str
    encoding_profile_id: str
    sys_id: bytes
    ell: int
    u: int
    c_max: int
    segment_length: int
    m_af: int
    seed_af: bytes
    slot_payload_bytes: int
    # No array digest or token-dependent lookup fields.

    def __post_init__(self):
        from .af import validate_metadata
        validate_metadata(self)


@dataclass(frozen=True)
class ProtectedAnonymousFilter:
    """Only fixed slots plus metadata: no locator, PStore or token map."""

    slots: Tuple[bytes, ...]
    metadata: AFMetadata


@dataclass(frozen=True)
class TokenRows:
    """Ephemeral build input, not an AF object field."""

    token: bytes
    rows: Tuple[int, ...]


@dataclass(frozen=True)
class AFQueryResult:
    """Authenticated hit or uniform miss; no rejection reason in this contract."""

    hit: bool
    rows: Tuple[int, ...]


@dataclass(frozen=True)
class KEMDEMInfo:
    profile: ProfileMetadata
    dem_id: str = field(default="AES-256-GCM-SIV", init=False)
    kdf_id: str = field(default="HKDF-SHA-256/MYABE-DEM", init=False)
    nonce_bytes: int = field(default=12, init=False)


@dataclass(frozen=True)
class CiphertextHeader:
    af_header: AFHeader
    context: PolicyContext
    data_id: bytes
    c: G1Element  # C appears ONLY here.
    c_max: int
    core_components_digest: bytes
    af_metadata_digest: bytes
    filter_digest: bytes  # Entire slots AND metadata, not metadata alone.
    kem_dem_info: KEMDEMInfo
    # No rev_version, user identity, K0, rho, or c_star.


@dataclass(frozen=True)
class Ciphertext:
    row_components: Tuple[G1Element, ...]  # C_i
    occurrence_components: Tuple[G2Element, ...]  # D_j; canonical c_max, TEST row ablation ell
    matrix: Matrix
    anonymous_filter: ProtectedAnonymousFilter
    dem_nonce: bytes
    encrypted_message: bytes
    header: CiphertextHeader
    publication_signature: bytes
    publisher_certificate: NamespaceCertificate


@dataclass(frozen=True)
class ChannelBinding:
    """Unverified claim; no 'verified=True' shortcut exists in this schema."""

    session_id: bytes = field(repr=False)
    fresh_challenge: bytes = field(repr=False)
    transcript_digest: bytes = field(repr=False)
    peer_ephemeral_public_key: bytes = field(repr=False)


@dataclass(frozen=True)
class PossessionProof:
    challenge_signature: bytes = field(repr=False)


@dataclass(frozen=True)
class TEERequest:
    header: CiphertextHeader
    publication_signature: bytes
    publisher_certificate: NamespaceCertificate
    dem_digest: bytes
    ctx_priv: bytes
    request_nonce: bytes
    version_hint: int  # Hint is not a trusted current-state source.
    expiry: int

    def __post_init__(self):
        _bytes(self.request_nonce, "request nonce")
        if len(self.request_nonce) < 32:
            raise ContractError("request nonce requires at least 256 bits")


@dataclass(frozen=True)
class EphemeralTokenComponent:
    token: bytes
    k_tau_q: G1Element


@dataclass(frozen=True)
class AuthorizationBundle:
    items: Tuple[EphemeralTokenComponent, ...]  # deduplicated, token-sorted
    k1_q: G2Element
    t0_q: GTElement
    # k0_q, mu_q, delta_q remain inside enclave and have no wire fields.


@dataclass(frozen=True)
class SignedCapability:
    sys_id: bytes
    header_digest: bytes
    ctx_priv: bytes
    rev_version: int
    request_nonce: bytes
    expiry: int
    bundle_digest: bytes
    signature: bytes


@dataclass(frozen=True)
class TEEAuthorization:
    bundle: AuthorizationBundle
    capability: SignedCapability
    # version/nonce/expiry occur once in capability; accessors avoid copies.

    @property
    def rev_version(self) -> int:
        return self.capability.rev_version

    @property
    def request_nonce(self) -> bytes:
        return self.capability.request_nonce

    @property
    def expiry(self) -> int:
        return self.capability.expiry


@dataclass(frozen=True)
class OccurrenceWitness:
    row: int
    token: bytes
    occurrence_rank: int


@dataclass(frozen=True)
class ReconstructionTerm:
    row: int
    coefficient: Scalar


@dataclass(frozen=True)
class AuthorizedSubsetResult:
    terms: Tuple[ReconstructionTerm, ...]  # nonzero, fixed row order
    occurrence_slots: Tuple[int, ...]  # sorted unique C_I; no minimum claim


@dataclass(frozen=True)
class CSPState:
    consumed_requests: Tuple[RequestRecord, ...]


@dataclass(frozen=True)
class RequestState:
    """DU-local target binding and response replay policy; never TEE secrets."""

    header_digest: bytes
    ctx_priv: bytes
    request_nonce: bytes
    expiry: int
    response_consumed: bool


@dataclass(frozen=True)
class PartialCiphertext:
    t0_q: GTElement
    t_a: GTElement
    header: CiphertextHeader
    dem_nonce: bytes
    encrypted_message: bytes
    publication_signature: bytes
    publisher_certificate: NamespaceCertificate
    authorization: TEEAuthorization


@dataclass(frozen=True)
class SetupResult:
    public_parameters: PublicParameters
    master_secret_key: MasterSecretKey = field(repr=False)
    kgc_state: KGCState = field(repr=False)
    tee_state: TEEState = field(repr=False)


@dataclass(frozen=True)
class KeyGenerationResult:
    """Orchestration return: delivery must split RK from TEE provisioning."""

    credential: Credential = field(repr=False)
    recovery_key: RecoveryKey = field(repr=False)
    sealed_blob: SealedUserBlob = field(repr=False)
    kgc_state: KGCState = field(repr=False)
    tee_state: TEEState = field(repr=False)


@dataclass(frozen=True)
class UserProvisioningResult:
    sealed_blob: SealedUserBlob = field(repr=False)
    tee_state: TEEState = field(repr=False)


@dataclass(frozen=True)
class RevocationResult:
    update: RevocationUpdate = field(repr=False)
    pending_kgc_state: KGCState = field(repr=False)


@dataclass(frozen=True)
class RevocationStateResult:
    tee_state: TEEState = field(repr=False)
    acknowledgement: RevocationAck


@dataclass(frozen=True)
class AuthorizationResult:
    authorization: TEEAuthorization
    tee_state: TEEState = field(repr=False)  # internal orchestration, NOT RPC


@dataclass(frozen=True)
class TransformResult:
    partial_ciphertext: PartialCiphertext
    csp_state: CSPState
