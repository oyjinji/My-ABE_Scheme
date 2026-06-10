'''
Run a DACP dataset experiment against a tiny synthetic local CSV file.
'''

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Code.dacp.data import run_dataset_file_experiment
from Code.dacp.data.policies import get_policy


def write_synthetic_file(path, template):
    path.parent.mkdir(parents=True, exist_ok=True)
    if template == 'nyc_tlc':
        content = (
            'trip_id,pickup_zone,dropoff_zone,fare_amount\n'
            '1,zone_a,zone_b,14.25\n'
            '2,zone_c,zone_d,23.40\n'
        )
    else:
        content = (
            'tx_id,amount,merchant_category,label\n'
            '1,12.50,grocery,0\n'
            '2,980.00,electronics,1\n'
            '3,43.20,transport,0\n'
        )
    path.write_text(content, encoding='utf-8')
    return path


def main():
    parser = argparse.ArgumentParser(description='Run synthetic DACP dataset experiment.')
    parser.add_argument('--policy-template', default='credit_fraud')
    parser.add_argument('--chunk-mode', action='store_true')
    parser.add_argument('--chunk-size', type=int, default=4096)
    args = parser.parse_args()

    policy = get_policy(args.policy_template)
    dataset_path = ROOT / 'data' / 'work' / ('synthetic_{0}_like.csv'.format(args.policy_template))
    write_synthetic_file(dataset_path, args.policy_template)
    output_dir = ROOT / 'results' / 'dacp_data' / ('synthetic_{0}'.format(args.policy_template))

    summary = run_dataset_file_experiment(
        dataset_path=dataset_path,
        dataset_name='Synthetic {0}'.format(args.policy_template),
        domain='synthetic',
        policy_str=policy,
        output_dir=output_dir,
        chunk_mode=args.chunk_mode,
        chunk_size=args.chunk_size,
    )

    print('DACP synthetic dataset experiment')
    print('=' * 72)
    for key in (
            'dataset_encrypt_success',
            'dacp_key_recover_success',
            'dataset_recover_success',
            'plaintext_sha256',
            'recovered_sha256',
            'manifest_path',
            'summary_path',
            'total_time',
            'encrypted_size',
            'num_chunks',
            'chunk_mode'):
        print('{0}: {1}'.format(key, summary[key]))


if __name__ == '__main__':
    main()
