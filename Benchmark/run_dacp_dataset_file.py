'''
Run a DACP dataset experiment for an arbitrary local file.

The file is treated as opaque bytes; no dataset-specific fields are parsed.
'''

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Code.dacp.data import append_summary_csv, run_dataset_file_experiment
from Code.dacp.data.policies import get_policy, list_policies


def main():
    parser = argparse.ArgumentParser(description='Run DACP experiment for a local dataset file.')
    parser.add_argument('--dataset-path', required=True)
    parser.add_argument('--dataset-name', required=True)
    parser.add_argument('--domain', required=True)
    parser.add_argument('--policy')
    parser.add_argument('--policy-template')
    parser.add_argument('--output-dir', required=True)
    parser.add_argument('--chunk-mode', action='store_true')
    parser.add_argument('--chunk-size', type=int, default=16777216)
    parser.add_argument('--summary-csv')
    args = parser.parse_args()

    dataset_path = Path(args.dataset_path)
    if not dataset_path.exists():
        raise SystemExit('dataset file does not exist: {0}'.format(dataset_path))
    if args.policy:
        policy = args.policy
    elif args.policy_template:
        policy = get_policy(args.policy_template)
    else:
        raise SystemExit(
            'provide --policy or --policy-template. Available templates: {0}'.format(
                ', '.join(sorted(list_policies().keys()))
            )
        )

    summary = run_dataset_file_experiment(
        dataset_path=dataset_path,
        dataset_name=args.dataset_name,
        domain=args.domain,
        policy_str=policy,
        output_dir=Path(args.output_dir),
        chunk_mode=args.chunk_mode,
        chunk_size=args.chunk_size,
    )
    if args.summary_csv:
        append_summary_csv(summary, args.summary_csv)

    print('DACP dataset file experiment')
    print('=' * 72)
    print(json.dumps(summary, sort_keys=True, indent=2))
    print('dataset_recover_success={0}'.format(summary['dataset_recover_success']))
    print('summary_path={0}'.format(summary['summary_path']))
    print('manifest_path={0}'.format(summary['manifest_path']))
    print('audit_log_path={0}'.format(summary['audit_log_path']))
    print('recovered_path={0}'.format(summary['recovered_path']))


if __name__ == '__main__':
    main()
