"""Versioned plan, raw-row and measurement-unit contracts."""
from __future__ import annotations
import math

from . import SCHEMA_VERSION
from .registry import REGISTRY, BLOCKED, SUPPORTED_BACKENDS
from .workloads import FAMILIES, sha256_json

NOT_OBSERVED = 'NOT_OBSERVED'
SCOPES = ('MICRO', 'ALGORITHM', 'REQUEST_E2E', 'STATE_ONLY',
          'STORAGE', 'TRANSCRIPT_AUDIT')
SAMPLE_STATUSES = ('OK', 'EXPECTED_REJECT', 'FAILED', 'TIMEOUT')
REQUIRED_ROW = ('schema_version','run_id','experiment_id','sample_id','backend',
    'measurement_scope','workload_id','workload_seed','warmup_or_measured',
    'sample_status','error_class','expected_outcome','actual_outcome',
    'correctness_verified','variables','metrics','counters','trust_metadata',
    'implementation_module','code_manifest_sha256','service_state')
METRIC_UNITS = {
    'sample_attempt_ns':'ns',
    'encrypt_core_ns':'ns', 'policy_token_ops_per_s':'ops/s',
    'user_token_ops_per_s':'ops/s',
    'request_e2e_ns':'ns', 'setup_ns':'ns', 'keygen_ns':'ns',
    'encrypt_ns':'ns', 'rev_ns':'ns', 'revstateupt_ns':'ns',
    'tee_authorize_ns':'ns', 'transform_ns':'ns', 'finaldec_ns':'ns',
    'host_pre_rpc_ns':'ns', 'rpc_send_ns':'ns', 'rpc_receive_ns':'ns',
    'host_post_rpc_ns':'ns', 'enclave_total_ns':'ns',
    'credential_verify_ns':'ns', 'revset_lookup_ns':'ns',
    'tokenization_ns':'ns', 'rerandomization_ns':'ns',
    't0_pairing_ns':'ns', 'cap_sign_ns':'ns',
    'af_build_ns':'ns', 'af_query_ns':'ns',
    'policy_token_ns':'ns', 'user_token_ns':'ns',
    'state_coordination_ns':'ns', 'rpc_roundtrip_ns':'ns',
    'state_only_insert_ns':'ns', 'state_only_lookup_ns':'ns',
    'state_only_delete_ns':'ns',
    'authorized_subset_ns':'ns', 't_a_ns':'ns',
    'attestation_preflight_ns':'ns', 'keygen_crypto_ns':'ns',
    'credential_ns':'ns', 'blob_provisioning_ns':'ns',
    'total_keygen_ns':'ns', 'rejection_ns':'ns',
    'ct_total_bytes':'bytes', 'ct_core_bytes':'bytes',
    'header_bytes':'bytes', 'af_total_bytes':'bytes',
    'af_slot_bytes':'bytes', 'af_metadata_bytes':'bytes',
    'dem_bytes':'bytes', 'publication_bytes':'bytes',
    'credential_bytes':'bytes', 'sealed_blob_bytes':'bytes',
    'auth_bytes':'bytes', 'ctprime_bytes':'bytes',
    'request_state_bytes':'bytes', 'revset_logical_bytes':'bytes',
    'state_only_revset_logical_bytes':'bytes',
    'host_to_tee_bytes':'bytes', 'tee_to_host_bytes':'bytes',
    'publication_wire_bytes':'bytes', 'ct_wire_bytes':'bytes',
    'auth_wire_bytes':'bytes', 'ctprime_wire_bytes':'bytes',
    'tee_pairing_count':'count', 'csp_pairing_count':'count',
    'system_pairing_count':'count', 'finaldec_pairing_count':'count',
    'g1_exp_count':'count', 'g2_exp_count':'count', 'gt_exp_count':'count',
    'prf_count':'count', 'hash_to_group_count':'count',
    'signature_sign_count':'count', 'signature_verify_count':'count',
    'af_decoded_payload_count':'count', 'af_hit_count':'count',
    'candidate_row_count':'count', 'reconstruction_row_count':'count',
    'occurrence_slot_count':'count', 'seed_retry_count':'count',
    'same_context_equal':'boolean',
    'cross_context_equal_observed':'boolean', 'known_w_stable':'boolean',
    'audit_status':'enum', 'token_updated':'boolean',
    'ct_updated':'boolean', 'rk_updated':'boolean',
}
DEFAULT_FAMILIES = {
    'Exp1': ('W-SINGLE','W-REPEAT-ABACA'),
    'Exp3': ('W-SINGLE','W-REPEAT-ABACA'),
    'Exp4': ('W-SINGLE',),
    'Exp5': ('W-SINGLE','W-REPEAT-ABACA'),
    'Exp6': ('W-SINGLE','W-OR'),
    'Exp7': ('W-SINGLE',),
}
DEFAULT_SCOPES = {
    'Exp1':'ALGORITHM', 'Exp3':'STORAGE', 'Exp4':'MICRO',
    'Exp5':'REQUEST_E2E', 'Exp6':'STATE_ONLY', 'Exp7':'TRANSCRIPT_AUDIT',
}


def build_plan(experiment_ids, backend, *, seeds=(17,), warmups=0,
               repetitions=1, max_samples=32, allow_large_run=False):
    if backend not in SUPPORTED_BACKENDS:
        raise ValueError('explicit supported backend required')
    if not experiment_ids or len(set(experiment_ids)) != len(experiment_ids):
        raise ValueError('unique experiment IDs required')
    for experiment_id in experiment_ids:
        if experiment_id not in REGISTRY:
            raise ValueError('unknown experiment ID')
    if (type(warmups) is not int or warmups < 0 or
        type(repetitions) is not int or repetitions < 1 or
        type(max_samples) is not int or max_samples < 1 or
        not seeds or any(type(seed) is not int or seed < 0 for seed in seeds)):
        raise ValueError('invalid plan sampling parameters')
    entries = []
    for experiment_id in experiment_ids:
        experiment = REGISTRY[experiment_id]
        if experiment.status == BLOCKED:
            entries.append(dict(experiment_id=experiment_id, status='BLOCKED_COMMON_BACKEND',
                                families=[], measurement_scope=None))
            continue
        if backend not in experiment.supported_backends:
            raise ValueError('backend unsupported for experiment')
        entries.append(dict(experiment_id=experiment_id, status='SMOKE_ONLY',
            families=list(DEFAULT_FAMILIES[experiment_id]),
            measurement_scope=DEFAULT_SCOPES[experiment_id],
            correctness_gates=list(experiment.correctness_gates)))
    estimate = sum(len(entry['families']) for entry in entries) * len(seeds) * repetitions
    if estimate > max_samples and not allow_large_run:
        raise ValueError('estimated measured samples exceed max_samples')
    return dict(schema_version=SCHEMA_VERSION, experiment_ids=list(experiment_ids),
        backend=backend, entries=entries, workload_families=sorted(set(
            family for entry in entries for family in entry['families'])),
        variable_grid={'workload_seed':list(seeds)}, seeds=list(seeds),
        warmups=warmups, repetitions=repetitions, measurement_scopes={
            entry['experiment_id']:entry['measurement_scope'] for entry in entries},
        expected_correctness_gates={entry['experiment_id']:entry.get('correctness_gates',[])
                                    for entry in entries},
        estimated_measured_samples=estimate, max_samples=max_samples,
        allow_large_run=bool(allow_large_run), benchmark_eligible=False,
        plan_sha256=None)


def finalize_plan_hash(plan):
    result = dict(plan)
    result['plan_sha256'] = sha256_json({k:v for k,v in result.items()
                                        if k != 'plan_sha256'})
    return result


def validate_plan(plan):
    if plan.get('schema_version') != SCHEMA_VERSION:
        raise ValueError('plan schema mismatch')
    if finalize_plan_hash(plan)['plan_sha256'] != plan.get('plan_sha256'):
        raise ValueError('plan hash mismatch')
    if plan.get('estimated_measured_samples',0) > plan.get('max_samples',0) and not plan.get('allow_large_run'):
        raise ValueError('plan exceeds sample limit')
    return True


def validate_raw_row(row, manifest, plan):
    if type(row) is not dict or any(name not in row for name in REQUIRED_ROW):
        raise ValueError('raw row missing required field')
    if (row['schema_version'] != SCHEMA_VERSION or
        row['run_id'] != manifest['run_id'] or
        row['experiment_id'] not in plan['experiment_ids'] or
        row['backend'] != plan['backend'] or
        row['measurement_scope'] not in SCOPES or
        row['warmup_or_measured'] != 'MEASURED' or
        row['sample_status'] not in SAMPLE_STATUSES or
        row['trust_metadata'] != manifest.get('trust_metadata') or
        row['implementation_module'] != 'core.myabe08.public.PublicMyABE08' or
        row['code_manifest_sha256'] != manifest['code_manifest_sha256']):
        raise ValueError('raw row identity/scope/status mismatch')
    if row['sample_status'] in ('OK','EXPECTED_REJECT') and (
        row['expected_outcome'] != row['actual_outcome'] or
        row['correctness_verified'] is not True):
        raise ValueError('incorrect success/rejection sample')
    if row['sample_status'] in ('FAILED','TIMEOUT') and (
        row['correctness_verified'] is not False or
        type(row['error_class']) is not str or not row['error_class']):
        raise ValueError('failed sample requires explicit error class')
    if type(row['metrics']) is not dict or type(row['variables']) is not dict:
        raise ValueError('raw metric/variable shape mismatch')
    for name, value in row['metrics'].items():
        unit = METRIC_UNITS.get(name)
        if unit is None:
            raise ValueError('unregistered metric unit: ' + name)
        if value == NOT_OBSERVED:
            continue
        if unit in ('ns','bytes','count') and (type(value) is not int or value < 0):
            raise ValueError('numeric metric unit/value mismatch')
        if unit == 'ops/s' and (type(value) not in (int,float) or
            value < 0 or not math.isfinite(value)):
            raise ValueError('throughput metric mismatch')
        if unit == 'boolean' and type(value) is not bool:
            raise ValueError('boolean metric mismatch')
        if unit == 'enum' and type(value) is not str:
            raise ValueError('enum metric mismatch')
    return True
