"""Eight normative MYABE-08 algorithms, Phase 1 signatures only.

No method returns fake crypto, dummy capabilities, or a 'successful' miss.
No compatibility fallback to older ABE algorithms is provided.
"""

from typing import Optional, Tuple

from .credential import (
    AdministrativeAuthorization, AttestedConfidentialChannel, DOSession,
)
from .errors import unimplemented
from .metrics import OperationCounts, TEEMetrics, TransformMetrics
from .profile import (
    EMULATED_TEE_PROFILE, SECURITY_PROFILE_BLS12_381,
    pairing_profile, require_pairing_backend, tee_profile,
)
from .state import AtomicRequestStore, CurrentStateCoordinator, TrustedClock
from .types import (
    Attribute, AuthorizationResult, CSPState, Ciphertext, Credential,
    KeyGenerationResult, KGCState, MasterSecretKey, PartialCiphertext,
    PolicyContext, PolicyInput, PossessionProof, PublicParameters,
    RecoveryKey, RequestState, RevocationOperation, RevocationResult,
    RevocationStateResult, RevocationUpdate, SealedUserBlob, SetupResult,
    TEEAuthorization, TEERequest, TEEState, TransformResult, Validity,
)


class MyABE08:
    def __init__(self, *, pairing_profile_id: str = SECURITY_PROFILE_BLS12_381,
                 tee_profile_id: str = EMULATED_TEE_PROFILE):
        # Known names permit contract inspection, NOT cryptographic execution.
        self.pairing_profile = pairing_profile(pairing_profile_id)
        self.tee_profile = tee_profile(tee_profile_id)

    def setup(self, *, security_parameter: int, c_max: int,
              provisioning_channel: AttestedConfidentialChannel,
              metrics: Optional[OperationCounts] = None) -> SetupResult:
        """PP includes g2^a; independently provision token/rev/cap secrets."""
        require_pairing_backend(self.pairing_profile.name)
        unimplemented("Setup")

    def keygen(self, pp: PublicParameters, msk: MasterSecretKey, kgc_state: KGCState,
               tee_state: TEEState, uid: str, attributes: Tuple[Attribute, ...],
               auth_public_key: bytes, validity: Validity, *,
               provisioning_channel: AttestedConfidentialChannel,
               metrics: Optional[OperationCounts] = None) -> KeyGenerationResult:
        """RK=z^-1 goes to DU; mu,K0 go only through enclave provisioning."""
        unimplemented("KeyGen")

    def encrypt(self, pp: PublicParameters, message: bytes, policy: PolicyInput,
                context: PolicyContext, *, data_id: bytes, do_session: DOSession,
                metrics: Optional[OperationCounts] = None) -> Ciphertext:
        """No MSK, revocation version, KU, or user key input."""
        unimplemented("Encrypt")

    def rev(self, kgc_state: KGCState, uid: str, operation: RevocationOperation, *,
            administrative_authorization: AdministrativeAuthorization) -> RevocationResult:
        """Queue a confidential next-version delta; NOT effective before Ack."""
        unimplemented("Rev")

    def rev_state_upt(self, pp: PublicParameters, tee_state: TEEState,
                      update: RevocationUpdate, *,
                      channel: AttestedConfidentialChannel) -> RevocationStateResult:
        unimplemented("RevStateUpt")

    def tee_authorize(self, pp: PublicParameters, tee_state: TEEState,
                      credential: Credential, blob: SealedUserBlob, request: TEERequest, *,
                      channel: AttestedConfidentialChannel, possession: PossessionProof,
                      coordinator: CurrentStateCoordinator, clock: TrustedClock,
                      metrics: Optional[TEEMetrics] = None) -> AuthorizationResult:
        """Private ingress; never expose credential/blob/digest to CSP RPC."""
        unimplemented("TEEAuthorize")

    def transform(self, pp: PublicParameters, ciphertext: Ciphertext,
                  authorization: TEEAuthorization, csp_state: CSPState, *,
                  request_store: AtomicRequestStore, clock: TrustedClock,
                  metrics: Optional[TransformMetrics] = None) -> TransformResult:
        """Verify and consume cap atomically; CSP pair terms target 1+t_I."""
        unimplemented("Transform")

    def final_dec(self, pp: PublicParameters, partial: PartialCiphertext,
                  recovery_key: RecoveryKey, request_state: RequestState, *,
                  request_store: AtomicRequestStore, clock: TrustedClock,
                  metrics: Optional[OperationCounts] = None) -> bytes:
        """Verify request/cap/publish/T0; (T0/TA)^RK and DEM; 0 pairings."""
        unimplemented("FinalDec")
