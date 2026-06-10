'''
Stable summary helpers for DACP dataset experiments.
'''

import csv
import json
from datetime import datetime
from pathlib import Path


SUMMARY_FIELDS = [
    'dataset_id',
    'dataset_name',
    'domain',
    'source_path',
    'policy_str',
    'file_size',
    'plaintext_sha256',
    'recovered_sha256',
    'dataset_encrypt_success',
    'dacp_key_recover_success',
    'dataset_recover_success',
    'chunk_mode',
    'chunk_size',
    'num_chunks',
    'encrypted_size',
    'manifest_path',
    'audit_log_path',
    'summary_path',
    'total_time',
    'dataset_encrypt_time',
    'dataset_decrypt_time',
    'dacp_encrypt_time',
    'csp_transform_time',
    'du_final_decrypt_time',
    'wire_total_bytes',
    'created_at',
    'skipped',
    'skip_reason',
]


def normalize_summary(summary):
    normalized = {field: summary.get(field) for field in SUMMARY_FIELDS}
    normalized.setdefault('created_at', _utc_now_iso())
    for key, value in summary.items():
        if key not in normalized:
            normalized[key] = value
    return normalized


def save_summary_json(summary, path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    normalized = normalize_summary(summary)
    normalized['summary_path'] = str(path)
    with open(path, 'w', encoding='utf-8') as handle:
        json.dump(normalized, handle, sort_keys=True, indent=2)
        handle.write('\n')
    return normalized


def append_summary_csv(summary, csv_path):
    csv_path = Path(csv_path)
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    normalized = normalize_summary(summary)
    fieldnames = list(SUMMARY_FIELDS)
    extras = sorted(key for key in normalized.keys() if key not in fieldnames)
    fieldnames.extend(extras)
    write_header = not csv_path.exists() or csv_path.stat().st_size == 0
    with open(csv_path, 'a', encoding='utf-8', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        if write_header:
            writer.writeheader()
        writer.writerow({key: _csv_value(normalized.get(key)) for key in fieldnames})


def _csv_value(value):
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, sort_keys=True, separators=(',', ':'))
    if value is None:
        return ''
    return value


def _utc_now_iso():
    return datetime.utcnow().replace(microsecond=0).isoformat() + 'Z'
