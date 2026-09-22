'''
Smoke tests for CreditFraud CSV marketplace adapter.
'''

import csv
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Code.dacp.marketplace import simulate_purchase_and_access
from Code.dacp.marketplace.adapters import CreditFraudCSVAdapter


def assert_true(name, condition):
    if not condition:
        raise AssertionError(name)
    print('{:<56} OK'.format(name))


def write_credit_csv(path, include_amount=True, include_class=True):
    fields = ['Time', 'V1', 'V2']
    if include_amount:
        fields.append('Amount')
    if include_class:
        fields.append('Class')
    rows = [
        {'Time': '0', 'V1': '0.1', 'V2': '0.2', 'Amount': '10.0', 'Class': '0'},
        {'Time': '1', 'V1': '0.3', 'V2': '0.4', 'Amount': '150.0', 'Class': '0'},
        {'Time': '2', 'V1': '0.5', 'V2': '0.6', 'Amount': '220.0', 'Class': '1'},
        {'Time': '3', 'V1': '0.7', 'V2': '0.8', 'Amount': '1.0', 'Class': '1.0'},
        {'Time': '4', 'V1': '0.9', 'V2': '1.0', 'Amount': '75.0', 'Class': '0'},
    ]
    with open(path, 'w', encoding='utf-8', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row[key] for key in fields})


def read_rows(path):
    with open(path, 'r', encoding='utf-8', newline='') as handle:
        return list(csv.DictReader(handle))


def test_adapter(tmp):
    dataset = tmp / 'creditcard.csv'
    write_credit_csv(dataset)
    adapter = CreditFraudCSVAdapter(high_amount_threshold=100, teaching_limit=3)
    schema = adapter.inspect_schema(dataset)
    assert_true('inspect_schema columns', 'Amount' in schema['columns'] and 'Class' in schema['columns'])
    assert_true('inspect_schema optional V columns', 'V1' in schema['present_v_columns'] and 'V2' in schema['present_v_columns'])
    valid, missing = adapter.validate_schema(dataset)
    assert_true('validate_schema complete', valid and missing == [])

    missing_amount = tmp / 'missing_amount.csv'
    write_credit_csv(missing_amount, include_amount=False)
    valid, missing = adapter.validate_schema(missing_amount)
    assert_true('validate_schema missing Amount', not valid and 'Amount' in missing)

    missing_class = tmp / 'missing_class.csv'
    write_credit_csv(missing_class, include_class=False)
    valid, missing = adapter.validate_schema(missing_class)
    assert_true('validate_schema missing Class', not valid and 'Class' in missing)

    rules = adapter.build_slice_rules()
    assert_true('build_slice_rules count', len(rules) >= 3)
    products, catalog = adapter.create_products(dataset, tmp / 'products')
    assert_true('create_products count', len(products) >= 3 and len(catalog.list_products()) >= 3)

    fraud = [item for item in products if item.product_name == 'Fraud Positive Samples'][0]
    fraud_rows = read_rows(fraud.package_path)
    assert_true('fraud product Class=1', all(float(row['Class']) == 1.0 for row in fraud_rows))

    high = [item for item in products if item.product_name == 'High Amount Transactions'][0]
    high_rows = read_rows(high.package_path)
    assert_true('high amount product threshold', all(float(row['Amount']) >= 100.0 for row in high_rows))

    teaching = [item for item in products if item.product_name == 'Teaching Sample'][0]
    teaching_rows = read_rows(teaching.package_path)
    assert_true('teaching sample limit', len(teaching_rows) <= 3)

    authorized = simulate_purchase_and_access(
        fraud,
        adapter.authorized_attrs_for(fraud),
        output_dir=tmp / 'authorized',
        chunk_mode=False,
    )
    assert_true('authorized buyer succeeds', authorized['authorized_success'])
    unauthorized = simulate_purchase_and_access(
        fraud,
        adapter.unauthorized_attrs_for(fraud),
        output_dir=tmp / 'unauthorized',
        chunk_mode=False,
    )
    assert_true('unauthorized buyer denied', not unauthorized['authorized_success'])


def test_missing_real_file_skips(tmp):
    missing = tmp / 'missing_creditcard.csv'
    output = subprocess.check_output(
        [
            sys.executable,
            str(ROOT / 'Benchmark' / 'run_dacp_marketplace_credit_fraud.py'),
            '--dataset-path',
            str(missing),
            '--output-dir',
            str(tmp / 'out'),
            '--products-dir',
            str(tmp / 'products_out'),
        ],
        cwd=str(ROOT),
        universal_newlines=True,
    )
    assert_true('missing real file skipped', 'skipped=True' in output and 'missing dataset file' in output)


def main():
    with tempfile.TemporaryDirectory() as work:
        tmp = Path(work)
        test_adapter(tmp)
        test_missing_real_file_skips(tmp)
    print('=' * 72)
    print('DACP CreditFraud adapter tests passed.')


if __name__ == '__main__':
    main()
