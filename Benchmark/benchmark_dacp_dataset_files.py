'''
Batch runner for local DACP dataset file experiments.

The files are treated as opaque bytes; no dataset schemas are parsed.
'''

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Code.dacp.data import append_summary_csv, run_dataset_file_experiment
from Code.dacp.data.policies import get_policy
from Code.dacp.data.summary import normalize_summary


def main():
    parser = argparse.ArgumentParser(description='Batch DACP dataset file experiments.')
    parser.add_argument('--config', required=True)
    parser.add_argument('--summary-csv', required=True)
    args = parser.parse_args()

    config_path = Path(args.config)
    with open(config_path, 'r', encoding='utf-8') as handle:
        config = json.load(handle)

    results = []
    for entry in config.get('experiments', []):
        dataset_path = Path(entry['dataset_path'])
        output_dir = Path(entry.get('output_dir', 'results/dacp_data/' + entry['dataset_name']))
        if not dataset_path.exists():
            summary = normalize_summary({
                'dataset_id': None,
                'dataset_name': entry.get('dataset_name'),
                'domain': entry.get('domain'),
                'source_path': str(dataset_path),
                'policy_str': _entry_policy(entry),
                'file_size': None,
                'plaintext_sha256': None,
                'recovered_sha256': None,
                'dataset_encrypt_success': False,
                'dacp_key_recover_success': False,
                'dataset_recover_success': False,
                'chunk_mode': bool(entry.get('chunk_mode', False)),
                'chunk_size': int(entry.get('chunk_size', 16777216)),
                'num_chunks': 0,
                'encrypted_size': 0,
                'manifest_path': None,
                'audit_log_path': None,
                'summary_path': None,
                'total_time': None,
                'dataset_encrypt_time': None,
                'dataset_decrypt_time': None,
                'dacp_encrypt_time': None,
                'csp_transform_time': None,
                'du_final_decrypt_time': None,
                'wire_total_bytes': 0,
                'skipped': True,
                'skip_reason': 'missing dataset file',
            })
            append_summary_csv(summary, args.summary_csv)
            results.append(summary)
            print('SKIPPED {0}: missing dataset file {1}'.format(
                entry.get('dataset_name'),
                dataset_path,
            ))
            continue

        summary = run_dataset_file_experiment(
            dataset_path=dataset_path,
            dataset_name=entry['dataset_name'],
            domain=entry['domain'],
            policy_str=_entry_policy(entry),
            output_dir=output_dir,
            chunk_mode=bool(entry.get('chunk_mode', False)),
            chunk_size=int(entry.get('chunk_size', 16777216)),
        )
        append_summary_csv(summary, args.summary_csv)
        results.append(summary)
        print('DONE {0}: dataset_recover_success={1}'.format(
            entry.get('dataset_name'),
            summary['dataset_recover_success'],
        ))

    print('batch_summary_csv={0}'.format(args.summary_csv))
    print('num_experiments={0}'.format(len(results)))
    print('num_skipped={0}'.format(sum(1 for item in results if item.get('skipped'))))


def _entry_policy(entry):
    if entry.get('policy'):
        return entry['policy']
    return get_policy(entry.get('policy_template', 'teaching'))


if __name__ == '__main__':
    main()
