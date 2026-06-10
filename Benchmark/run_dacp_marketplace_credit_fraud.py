'''
Run DACP marketplace experiment for Kaggle Credit Card Fraud Detection CSV.

The script does not download data and does not train fraud models. It treats
the CSV as local bytes plus lightweight slicing fields.
'''

import argparse
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Code.dacp.marketplace import simulate_purchase_and_access
from Code.dacp.marketplace.adapters import CreditFraudCSVAdapter


def main():
    parser = argparse.ArgumentParser(description='Run CreditFraud DACP marketplace experiment.')
    parser.add_argument('--dataset-path', default='data/raw/creditcard.csv')
    parser.add_argument('--output-dir', default='results/dacp_marketplace/credit_fraud')
    parser.add_argument('--products-dir', default='data/products/credit_fraud')
    parser.add_argument('--chunk-mode', action='store_true')
    parser.add_argument('--chunk-size', type=int, default=4096)
    parser.add_argument('--high-amount-threshold', type=float, default=100.0)
    args = parser.parse_args()

    dataset_path = Path(args.dataset_path)
    output_dir = Path(args.output_dir)
    products_dir = Path(args.products_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    products_dir.mkdir(parents=True, exist_ok=True)

    adapter = CreditFraudCSVAdapter(high_amount_threshold=args.high_amount_threshold)
    if not adapter.exists(dataset_path):
        summary = {
            'skipped': True,
            'skip_reason': 'missing dataset file',
            'dataset_path': str(dataset_path),
        }
        _save_json(summary, output_dir / 'marketplace_summary.json')
        print('CreditFraud marketplace experiment skipped')
        print('skipped=True')
        print('reason=missing dataset file')
        print('dataset_path={0}'.format(dataset_path))
        return

    schema = adapter.inspect_schema(dataset_path)
    valid, missing = adapter.validate_schema(dataset_path)
    if not valid:
        summary = {
            'skipped': True,
            'skip_reason': 'missing required columns: ' + ', '.join(missing),
            'dataset_path': str(dataset_path),
            'schema': schema,
        }
        _save_json(summary, output_dir / 'marketplace_summary.json')
        print('CreditFraud marketplace experiment skipped')
        print('skipped=True')
        print('reason={0}'.format(summary['skip_reason']))
        return

    products, catalog = adapter.create_products(dataset_path, products_dir)
    catalog_path = output_dir / 'catalog.json'
    catalog.save_json(catalog_path)

    rows = []
    print('DACP CreditFraud marketplace experiment')
    print('=' * 132)
    print('catalog_path: {0}'.format(catalog_path))
    print('{:<34} {:<34} {:>8} {:<54} {:<8} {:<8} {}'.format(
        'product_id',
        'product_name',
        'rows',
        'policy_str',
        'auth',
        'denied',
        'summary_path',
    ))
    for product in products:
        authorized = simulate_purchase_and_access(
            product,
            adapter.authorized_attrs_for(product),
            output_dir=output_dir / product.product_id / 'authorized',
            chunk_mode=args.chunk_mode,
            chunk_size=args.chunk_size,
        )
        unauthorized = simulate_purchase_and_access(
            product,
            adapter.unauthorized_attrs_for(product),
            output_dir=output_dir / product.product_id / 'unauthorized',
            chunk_mode=args.chunk_mode,
            chunk_size=args.chunk_size,
        )
        row = {
            'product_id': product.product_id,
            'product_name': product.product_name,
            'row_count': product.row_count,
            'package_path': product.package_path,
            'manifest_path': product.manifest_path,
            'policy_str': product.policy_str,
            'authorized_success': authorized['authorized_success'],
            'unauthorized_denied': not unauthorized['authorized_success'],
            'summary_path': authorized['summary']['summary_path'],
            'unauthorized_summary_path': unauthorized['summary']['summary_path'],
        }
        rows.append(row)
        print('{:<34} {:<34} {:>8} {:<54} {:<8} {:<8} {}'.format(
            row['product_id'],
            row['product_name'][:34],
            row['row_count'],
            row['policy_str'][:54],
            str(row['authorized_success']),
            str(row['unauthorized_denied']),
            row['summary_path'],
        ))

    summary = {
        'skipped': False,
        'dataset_path': str(dataset_path),
        'schema': schema,
        'catalog_path': str(catalog_path),
        'products': rows,
    }
    _save_json(summary, output_dir / 'marketplace_summary.json')
    _save_csv(rows, output_dir / 'marketplace_summary.csv')
    print('marketplace_summary_json={0}'.format(output_dir / 'marketplace_summary.json'))
    print('marketplace_summary_csv={0}'.format(output_dir / 'marketplace_summary.csv'))


def _save_json(obj, path):
    with open(path, 'w', encoding='utf-8') as handle:
        json.dump(obj, handle, sort_keys=True, indent=2)
        handle.write('\n')


def _save_csv(rows, path):
    fields = [
        'product_id',
        'product_name',
        'row_count',
        'package_path',
        'manifest_path',
        'policy_str',
        'authorized_success',
        'unauthorized_denied',
        'summary_path',
        'unauthorized_summary_path',
    ]
    with open(path, 'w', encoding='utf-8', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


if __name__ == '__main__':
    main()
