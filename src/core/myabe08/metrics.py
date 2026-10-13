"""Unobserved counters are None, never fabricated zero/positive measurements.

Pairing terms count mathematical pair terms, not multi-pairing API calls.
Future hooks must count executed operations including failed requests.
"""

from dataclasses import dataclass, field
from typing import Optional

AUTH_STAGE_TIMING_FIELDS = (
    'enclave_total_ns', 'credential_verify_ns', 'state_coordination_ns',
    'revset_lookup_ns',
    'tokenization_ns', 'rerandomization_ns', 't0_pairing_ns', 'cap_sign_ns',
)


@dataclass
class OperationCounts:
    g1_exponentiations: Optional[int] = None
    g2_exponentiations: Optional[int] = None
    gt_exponentiations: Optional[int] = None
    pairing_terms: Optional[int] = None
    prf_calls: Optional[int] = None
    hash_to_group_calls: Optional[int] = None
    signature_signs: Optional[int] = None
    signature_verifications: Optional[int] = None


@dataclass
class TEEMetrics:
    status: str = field(default="NOT_EXECUTED", init=False)
    profile: str = field(default="EMULATED_TEE_PROFILE", init=False)
    credential_verification_ns: Optional[int] = None
    unseal_ns: Optional[int] = None
    contextual_tokenization_ns: Optional[int] = None
    revocation_lookup_ns: Optional[int] = None
    state_synchronization_ns: Optional[int] = None
    coordination_wait_ns: Optional[int] = None
    rerandomization_ns: Optional[int] = None
    t0_pairing_ns: Optional[int] = None
    capability_signing_ns: Optional[int] = None
    total_ns: Optional[int] = None
    network_bytes: Optional[int] = None
    enclave_transitions: Optional[int] = None  # N/A for software emulation
    revset_bytes: Optional[int] = None
    registration_bytes: Optional[int] = None
    replay_state_bytes: Optional[int] = None
    ops: OperationCounts = field(default_factory=OperationCounts)


@dataclass
class AFMetrics:
    status: str = field(default="NOT_EXECUTED", init=False)
    build_ns: Optional[int] = None
    query_ns: Optional[int] = None
    peeling_ns: Optional[int] = None
    payload_authenc_ns: Optional[int] = None
    seed_attempts: Optional[int] = None
    decoded_payloads: Optional[int] = None
    slot_bytes: Optional[int] = None
    metadata_bytes: Optional[int] = None
    queries: int = 0
    hits: int = 0
    misses: int = 0
    auth_failures: int = 0
    parse_failures: int = 0
    u: Optional[int] = None
    segment_length: Optional[int] = None
    m_af: Optional[int] = None
    slot_payload_bytes: Optional[int] = None
    attempts: int = 0
    peel_failures: int = 0
    build_success: bool = False


@dataclass
class TransformMetrics:
    status: str = field(default="NOT_EXECUTED", init=False)
    verification_ns: Optional[int] = None
    af_query_ns: Optional[int] = None
    authorized_subset_ns: Optional[int] = None
    csp_attribute_transform_ns: Optional[int] = None
    total_ns: Optional[int] = None
    query_tokens: Optional[int] = None  # N
    candidate_rows: Optional[int] = None  # |J|
    reconstruction_rows: Optional[int] = None  # k
    occurrence_slots: Optional[int] = None  # t_I
    csp_ops: OperationCounts = field(default_factory=OperationCounts)


@dataclass
class ProtocolOperationCounts:
    """Only explicitly observed software protocol operations; no timing claim."""
    credential_verifications: int = 0
    possession_verifications: int = 0
    publication_verifications: int = 0
    blob_unseals: int = 0
    policy_token_prf_count: int = 0
    user_token_prf_count: int = 0
    h0_count: int = 0
    t0_pairings: int = 0
    cap_signatures: int = 0
    cap_verifications: int = 0
    request_issue_rejections: int = 0
    request_consumptions: int = 0
    channel_records: int = 0
    sealed_blob_bytes: int = 0
    auth_canonical_bytes: int = 0
    network_logical_bytes: Optional[int] = None
    rev_lookup_count: int = 0
    revoked_rejections: int = 0
    state_digest_checks: int = 0
    # DEBUG/TEST instrumentation only; never enters Auth or cap semantics.
    stage_timings_ns: dict = field(default_factory=dict, repr=False)


@dataclass
class RevocationOperationCounts:
    """Operation/state counts for the single-process emulated subsystem."""
    n_registered: int = 0
    credential_registry_entries: int = 0
    rev_operations: int = 0
    activate_operations: int = 0
    delta_bytes: int = 0
    rev_state_updates: int = 0
    rev_lookup_count: int = 0
    revoked_rejections: int = 0
    rev_version: int = 0
    revset_size: int = 0
    state_snapshot_bytes: int = 0
    state_digest_checks: int = 0
    sync_requests: int = 0
    sync_applied_updates: int = 0
    sync_failures: int = 0
    authorization_txn_begin: int = 0
    authorization_txn_commit: int = 0
    authorization_txn_abort: int = 0
    coordinator_conflicts: int = 0
    rollback_detections: int = 0
    freeze_detections: int = 0
    stale_local_detections: int = 0
