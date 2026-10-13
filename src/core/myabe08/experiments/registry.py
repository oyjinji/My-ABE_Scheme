"""Frozen Exp1–Exp7 map to ABE-Scheme-08 experimental questions."""
from __future__ import annotations
from dataclasses import asdict, dataclass

from ..profile import EMULATED_TEE_PROFILE, SGX_DEBUG_GRAMINE_V1

SMOKE_ONLY = 'SMOKE_ONLY'
BLOCKED = 'BLOCKED'
READY = 'READY'
NOT_APPLICABLE = 'NOT_APPLICABLE'
SUPPORTED_BACKENDS = (EMULATED_TEE_PROFILE, SGX_DEBUG_GRAMINE_V1)


@dataclass(frozen=True)
class Experiment:
    experiment_id: str
    name: str
    contribution: str
    research_question: str
    status: str
    supported_backends: tuple[str, ...]
    independent_variables: tuple[str, ...]
    metrics: tuple[str, ...]
    correctness_gates: tuple[str, ...]
    security_boundary: str
    blocked_reason: str | None = None

    def public(self):
        return asdict(self)


REGISTRY = {
    'Exp1': Experiment('Exp1', 'Occurrence optimization', 'C1',
        'Do full-row occurrence ranks preserve cancellation while pairing terms track tI?',
        SMOKE_ONLY, SUPPORTED_BACKENDS,
        ('ell','cmax','k','tI'), ('g1_exp_count','g2_exp_count','tee_pairing_count',
        'csp_pairing_count','occurrence_ranks'),
        ('FinalDec==M','ranks_from_complete_rows','TEE=1','CSP=1+tI'),
        'TEST correctness and instrumentation; no performance conclusion'),
    'Exp2': Experiment('Exp2', 'FABEO comparison', 'C1',
        'How do eight-algorithm costs compare on one audited common backend?',
        BLOCKED, (), ('policy_size','policy_shape'),
        ('setup_ns','keygen_ns','encrypt_core_ns','transform_ns'),
        ('same_curve','common_audited_backend'),
        'Charm/MNT224 and py_ecc/BLS12-381 timings must not be compared',
        'BLOCKED_COMMON_BACKEND'),
    'Exp3': Experiment('Exp3', 'Storage', 'C1–C3',
        'What canonical bytes are held by CT, AF, credential, Blob and request artifacts?',
        SMOKE_ONLY, SUPPORTED_BACKENDS, ('ell','cmax','policy_shape'),
        ('ct_total_bytes','ct_core_bytes','af_slot_bytes','af_metadata_bytes',
         'header_bytes','dem_bytes','publication_bytes','credential_bytes',
         'sealed_blob_bytes','auth_bytes','ctprime_bytes'),
        ('canonical_roundtrip','storage_reconciles','no_revocation_CT_component'),
        'Do not serialize or publish internal secret state'),
    'Exp4': Experiment('Exp4', 'Contextual anonymous tokenization and AF', 'C2',
        'How do contextual token equality and AF candidate work vary by public shape?',
        SMOKE_ONLY, SUPPORTED_BACKENDS,
        ('u','ell','N','cmax','L_hit','policy_batch_size','user_batch_size'),
        ('policy_token_ns','user_token_ns','af_build_ns','af_query_ns',
         'same_context_equal','cross_context_equal_observed','af_hit_count'),
        ('same_context_equal','FinalDec==M','AF_candidate_not_authorization'),
        'Observed non-equality is not an unlinkability proof'),
    'Exp5': Experiment('Exp5', 'Transform scaling', 'C1–C3',
        'How do candidate and reconstruction sizes map to host and SGX operation spans?',
        SMOKE_ONLY, SUPPORTED_BACKENDS, ('J','k','tI','N'),
        ('tee_authorize_ns','af_query_ns','authorized_subset_ns','t_a_ns',
         't0_pairing_ns','cap_sign_ns','request_e2e_ns'),
        ('FinalDec==M','requested_vs_actual_J_tI','TEE=1','CSP=1+tI'),
        'Success and rejection classes remain separate distributions'),
    'Exp6': Experiment('Exp6', 'Privacy-preserving revocation', 'C3',
        'Can exact RevSet updates reject revoked users without CT/token/RK updates?',
        SMOKE_ONLY, SUPPORTED_BACKENDS, ('RL_size','n_reg','request_rate'),
        ('revstateupt_ns','revset_lookup_ns','rejection_ns','revset_logical_bytes'),
        ('revoked_reject','activate_restores','CT_unchanged','RK_unchanged'),
        'State-only microbenchmarks are not full TEEAuthorize'),
    'Exp7': Experiment('Exp7', 'Revocation-layer transcript audit', 'C2–C3',
        'What is observable in public artifacts and which known linkages remain?',
        SMOKE_ONLY, SUPPORTED_BACKENDS, ('policy_shape','revocation_state'),
        ('audit_status','known_w_stable','af_hit_count'),
        ('secret_canaries_absent','known_W_linkability_recorded'),
        'No full unlinkability or formal privacy claim'),
}


def get_experiment(experiment_id: str) -> Experiment:
    try:
        return REGISTRY[experiment_id]
    except KeyError as exc:
        raise ValueError('unknown experiment ID') from exc
