'''
Dataset experiment scaffold for DACP.

This package treats datasets as opaque bytes. It does not parse CSV, Parquet,
MIMIC, TLC, Kaggle, Lending Club, or any other real dataset schema.
'''

from .audit import AuditLog
from .experiment import run_dataset_file_experiment
from .file_crypto import (
    decrypt_file_bytes,
    derive_file_key,
    encrypt_file_bytes,
    generate_dataset_key,
)
from .manifest import (
    ChunkRecord,
    DatasetManifest,
    load_manifest,
    make_dataset_id,
    manifest_from_dict,
    manifest_to_dict,
    save_manifest,
    sha256_bytes,
    sha256_file,
)
from .policies import DEFAULT_POLICIES, get_policy, list_policies, to_charm_policy
from .summary import append_summary_csv, normalize_summary, save_summary_json

__all__ = [
    'AuditLog',
    'ChunkRecord',
    'DatasetManifest',
    'DEFAULT_POLICIES',
    'decrypt_file_bytes',
    'derive_file_key',
    'encrypt_file_bytes',
    'generate_dataset_key',
    'get_policy',
    'list_policies',
    'load_manifest',
    'make_dataset_id',
    'manifest_from_dict',
    'manifest_to_dict',
    'run_dataset_file_experiment',
    'save_manifest',
    'append_summary_csv',
    'normalize_summary',
    'save_summary_json',
    'sha256_bytes',
    'sha256_file',
    'to_charm_policy',
]
