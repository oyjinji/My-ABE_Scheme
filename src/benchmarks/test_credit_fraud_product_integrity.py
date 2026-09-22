'''
Integrity checks for CreditFraud marketplace product packages.
'''

import csv
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


PRODUCTS_DIR = ROOT / 'data' / 'products' / 'credit_fraud'
RAW_DATASET = ROOT / 'data' / 'raw' / 'creditcard.csv'
OUTPUT_JSON = ROOT / 'results' / 'dacp_marketplace' / 'credit_fraud' / 'product_integrity_summary.json'


PRODUCT_FILES = {
    'Fraud Positive Samples': PRODUCTS_DIR / 'credit_fraud_positive_samples.csv',
    'High Amount Transactions': PRODUCTS_DIR / 'credit_fraud_high_amount_transactions.csv',
    'Teaching Sample': PRODUCTS_DIR / 'credit_fraud_teaching_sample.csv',
    'Normal Low Amount Baseline': PRODUCTS_DIR / 'credit_fraud_normal_low_amount_baseline.csv',
}


def main():
    if not all(path.exists() for path in PRODUCT_FILES.values()):
        if not RAW_DATASET.exists():
            _save({
                'skipped': True,
                'skip_reason': 'missing raw dataset and product packages',
                'dataset_path': str(RAW_DATASET),
            })
            print('CreditFraud product integrity skipped')
            print('skipped=True')
            print('reason=missing raw dataset and product packages')
            return
        subprocess.check_call([
            sys.executable,
            str(ROOT / 'Benchmark' / 'run_dacp_marketplace_credit_fraud.py'),
            '--dataset-path',
            str(RAW_DATASET),
            '--output-dir',
            str(ROOT / 'results' / 'dacp_marketplace' / 'credit_fraud'),
            '--products-dir',
            str(PRODUCTS_DIR),
            '--high-amount-threshold',
            '100',
        ], cwd=str(ROOT))

    raw_columns = _columns(RAW_DATASET) if RAW_DATASET.exists() else _columns(next(iter(PRODUCT_FILES.values())))
    summary = {
        'skipped': False,
        'raw_column_count': len(raw_columns),
        'products': {},
    }

    for name, path in PRODUCT_FILES.items():
        rows, columns = _read_rows(path)
        ok = len(columns) == len(raw_columns)
        if name == 'Fraud Positive Samples':
            ok = ok and all(_float(row.get('Class')) == 1.0 for row in rows)
        elif name == 'High Amount Transactions':
            ok = ok and all(_float(row.get('Amount')) >= 100.0 for row in rows)
        elif name == 'Teaching Sample':
            ok = ok and all(_float(row.get('Class')) in (0.0, 1.0) for row in rows)
            ok = ok and len(rows) <= 5000
        elif name == 'Normal Low Amount Baseline':
            ok = ok and all(_float(row.get('Class')) == 0.0 for row in rows)
            ok = ok and all(_float(row.get('Amount')) <= 50.0 for row in rows)
        summary['products'][name] = {
            'path': str(path),
            'row_count': len(rows),
            'column_count': len(columns),
            'integrity_ok': ok,
        }

    _save(summary)
    for name, item in summary['products'].items():
        print('{0}: rows={1} integrity_ok={2}'.format(name, item['row_count'], item['integrity_ok']))
    if not all(item['integrity_ok'] for item in summary['products'].values()):
        raise AssertionError('CreditFraud product integrity check failed')
    print('product_integrity_summary={0}'.format(OUTPUT_JSON))


def _columns(path):
    with open(path, 'r', encoding='utf-8', newline='') as handle:
        return list(csv.DictReader(handle).fieldnames or [])


def _read_rows(path):
    with open(path, 'r', encoding='utf-8', newline='') as handle:
        reader = csv.DictReader(handle)
        return list(reader), list(reader.fieldnames or [])


def _float(value):
    return float(value)


def _save(obj):
    OUTPUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_JSON, 'w', encoding='utf-8') as handle:
        json.dump(obj, handle, sort_keys=True, indent=2)
        handle.write('\n')


if __name__ == '__main__':
    main()
