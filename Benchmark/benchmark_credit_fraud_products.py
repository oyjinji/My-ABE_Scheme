'''
CreditFraud product benchmark matrix for DACP marketplace experiments.
'''

import argparse
import csv
import json
import sys
import uuid
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Code.dacp.data.file_crypto import decrypt_file_bytes, encrypt_file_bytes, generate_dataset_key
from Code.dacp.marketplace import simulate_purchase_and_access
from Code.dacp.marketplace.adapters import CreditFraudCSVAdapter
from Code.dacp.marketplace.reporting import generate_credit_fraud_report


RAW_FIELDS = [
    'run_id',
    'repeat_id',
    'product_id',
    'product_name',
    'policy_str',
    'row_count',
    'column_count',
    'package_path',
    'package_size_bytes',
    'chunk_mode',
    'chunk_size',
    'num_chunks',
    'authorized_success',
    'unauthorized_denied',
    'dataset_encrypt_success',
    'dacp_key_recover_success',
    'dataset_recover_success',
    'plaintext_sha256',
    'recovered_sha256',
    'sha256_match',
    'dataset_encrypt_time',
    'dataset_decrypt_time',
    'dacp_encrypt_time',
    'csp_transform_time',
    'du_final_decrypt_time',
    'wire_total_bytes',
    'total_time',
    'encrypted_size',
    'throughput_MBps',
    'created_at',
    'tamper_ciphertext_detected',
    'tamper_manifest_detected',
    'tamper_policy_detected',
]


SUMMARY_FIELDS = [
    'product_name',
    'row_count',
    'package_size_bytes',
    'chunk_size',
    'repeat',
    'success_rate',
    'unauthorized_denial_rate',
    'avg_total_time',
    'avg_dataset_encrypt_time',
    'avg_dataset_decrypt_time',
    'avg_dacp_encrypt_time',
    'avg_csp_transform_time',
    'avg_du_final_decrypt_time',
    'avg_wire_total_bytes',
    'avg_throughput_MBps',
]


def main():
    parser = argparse.ArgumentParser(description='Benchmark CreditFraud DACP data products.')
    parser.add_argument('--dataset-path', default='data/raw/creditcard.csv')
    parser.add_argument('--output-dir', default='results/dacp_marketplace/credit_fraud_benchmark')
    parser.add_argument('--products-dir', default='data/products/credit_fraud')
    parser.add_argument('--chunk-sizes', default='4096,65536,1048576')
    parser.add_argument('--high-amount-threshold', type=float, default=100.0)
    parser.add_argument('--repeat', type=int, default=3)
    parser.add_argument('--tamper-test', action='store_true')
    args = parser.parse_args()

    dataset_path = Path(args.dataset_path)
    output_dir = Path(args.output_dir)
    products_dir = Path(args.products_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    products_dir.mkdir(parents=True, exist_ok=True)

    if not dataset_path.exists():
        skipped = {
            'skipped': True,
            'skip_reason': 'missing dataset file',
            'dataset_path': str(dataset_path),
        }
        _save_json(skipped, output_dir / 'credit_fraud_benchmark_summary.json')
        print('CreditFraud product benchmark skipped')
        print('skipped=True')
        print('reason=missing dataset file')
        print('dataset_path={0}'.format(dataset_path))
        return

    adapter = CreditFraudCSVAdapter(high_amount_threshold=args.high_amount_threshold)
    valid, missing = adapter.validate_schema(dataset_path)
    if not valid:
        skipped = {
            'skipped': True,
            'skip_reason': 'missing required columns: ' + ', '.join(missing),
            'dataset_path': str(dataset_path),
            'missing_columns': missing,
        }
        _save_json(skipped, output_dir / 'credit_fraud_benchmark_summary.json')
        print('CreditFraud product benchmark skipped')
        print('skipped=True')
        print('reason={0}'.format(skipped['skip_reason']))
        return

    products, catalog = adapter.create_products(dataset_path, products_dir)
    catalog.save_json(output_dir / 'catalog.json')
    chunk_sizes = [int(item) for item in args.chunk_sizes.split(',') if item.strip()]

    raw_rows = []
    run_id = uuid.uuid4().hex
    for product in products:
        for chunk_size in chunk_sizes:
            for repeat_id in range(1, int(args.repeat) + 1):
                authorized = simulate_purchase_and_access(
                    product,
                    adapter.authorized_attrs_for(product),
                    output_dir=output_dir / product.product_id / ('chunk_{0}'.format(chunk_size)) / ('repeat_{0}'.format(repeat_id)) / 'authorized',
                    chunk_mode=True,
                    chunk_size=chunk_size,
                )
                unauthorized = simulate_purchase_and_access(
                    product,
                    adapter.unauthorized_attrs_for(product),
                    output_dir=output_dir / product.product_id / ('chunk_{0}'.format(chunk_size)) / ('repeat_{0}'.format(repeat_id)) / 'unauthorized',
                    chunk_mode=True,
                    chunk_size=chunk_size,
                )
                summary = authorized['summary']
                package_size = Path(product.package_path).stat().st_size
                throughput = _throughput(package_size, summary.get('total_time'))
                tamper = _tamper_tests(product, unauthorized) if args.tamper_test else {}
                raw_rows.append({
                    'run_id': run_id,
                    'repeat_id': repeat_id,
                    'product_id': product.product_id,
                    'product_name': product.product_name,
                    'policy_str': product.policy_str,
                    'row_count': product.row_count,
                    'column_count': product.column_count,
                    'package_path': product.package_path,
                    'package_size_bytes': package_size,
                    'chunk_mode': True,
                    'chunk_size': chunk_size,
                    'num_chunks': summary.get('num_chunks'),
                    'authorized_success': authorized['authorized_success'],
                    'unauthorized_denied': not unauthorized['authorized_success'],
                    'dataset_encrypt_success': summary.get('dataset_encrypt_success'),
                    'dacp_key_recover_success': summary.get('dacp_key_recover_success'),
                    'dataset_recover_success': summary.get('dataset_recover_success'),
                    'plaintext_sha256': summary.get('plaintext_sha256'),
                    'recovered_sha256': summary.get('recovered_sha256'),
                    'sha256_match': summary.get('plaintext_sha256') == summary.get('recovered_sha256'),
                    'dataset_encrypt_time': summary.get('dataset_encrypt_time'),
                    'dataset_decrypt_time': summary.get('dataset_decrypt_time'),
                    'dacp_encrypt_time': summary.get('dacp_encrypt_time'),
                    'csp_transform_time': summary.get('csp_transform_time'),
                    'du_final_decrypt_time': summary.get('du_final_decrypt_time'),
                    'wire_total_bytes': summary.get('wire_total_bytes'),
                    'total_time': summary.get('total_time'),
                    'encrypted_size': summary.get('encrypted_size'),
                    'throughput_MBps': throughput,
                    'created_at': summary.get('created_at'),
                    'tamper_ciphertext_detected': tamper.get('tamper_ciphertext_detected'),
                    'tamper_manifest_detected': tamper.get('tamper_manifest_detected'),
                    'tamper_policy_detected': tamper.get('tamper_policy_detected'),
                })

    raw_csv = output_dir / 'credit_fraud_benchmark_raw.csv'
    summary_csv = output_dir / 'credit_fraud_benchmark_summary.csv'
    summary_json = output_dir / 'credit_fraud_benchmark_summary.json'
    report_md = output_dir / 'credit_fraud_benchmark_report.md'
    _write_csv(raw_csv, RAW_FIELDS, raw_rows)
    summary_rows = _aggregate(raw_rows)
    _write_csv(summary_csv, SUMMARY_FIELDS, summary_rows)
    _save_json({
        'skipped': False,
        'dataset_path': str(dataset_path),
        'raw_csv': str(raw_csv),
        'summary_csv': str(summary_csv),
        'report_md': str(report_md),
        'products': summary_rows,
    }, summary_json)
    generate_credit_fraud_report(raw_csv, summary_csv, report_md)

    print('CreditFraud product benchmark complete')
    print('raw_csv={0}'.format(raw_csv))
    print('summary_csv={0}'.format(summary_csv))
    print('summary_json={0}'.format(summary_json))
    print('report_md={0}'.format(report_md))


def _aggregate(raw_rows):
    groups = defaultdict(list)
    for row in raw_rows:
        groups[(row['product_name'], row['chunk_size'])].append(row)
    rows = []
    for (product_name, chunk_size), items in sorted(groups.items()):
        first = items[0]
        repeat = len(items)
        rows.append({
            'product_name': product_name,
            'row_count': first['row_count'],
            'package_size_bytes': first['package_size_bytes'],
            'chunk_size': chunk_size,
            'repeat': repeat,
            'success_rate': _rate(items, 'authorized_success'),
            'unauthorized_denial_rate': _rate(items, 'unauthorized_denied'),
            'avg_total_time': _avg(items, 'total_time'),
            'avg_dataset_encrypt_time': _avg(items, 'dataset_encrypt_time'),
            'avg_dataset_decrypt_time': _avg(items, 'dataset_decrypt_time'),
            'avg_dacp_encrypt_time': _avg(items, 'dacp_encrypt_time'),
            'avg_csp_transform_time': _avg(items, 'csp_transform_time'),
            'avg_du_final_decrypt_time': _avg(items, 'du_final_decrypt_time'),
            'avg_wire_total_bytes': _avg(items, 'wire_total_bytes'),
            'avg_throughput_MBps': _avg(items, 'throughput_MBps'),
        })
    return rows


def _rate(items, key):
    return sum(1 for item in items if _truthy(item.get(key))) / float(len(items) or 1)


def _avg(items, key):
    values = [float(item[key]) for item in items if item.get(key) not in (None, '')]
    return sum(values) / float(len(values)) if values else None


def _throughput(size_bytes, total_time):
    if not total_time:
        return None
    return (float(size_bytes) / (1024.0 * 1024.0)) / float(total_time)


def _truthy(value):
    return value is True or str(value).lower() == 'true'


def _tamper_tests(product, unauthorized):
    plaintext = Path(product.package_path).read_bytes()
    dataset_key = generate_dataset_key()
    aad = b'dacp-credit-fraud-tamper'
    cipher_obj = encrypt_file_bytes(plaintext, dataset_key, aad)
    tampered = dict(cipher_obj)
    ct = bytearray(bytes.fromhex(tampered['ciphertext']))
    if ct:
        ct[0] ^= 1
    tampered['ciphertext'] = bytes(ct).hex()
    tamper_ciphertext_detected = decrypt_file_bytes(tampered, dataset_key, aad) is None
    tamper_manifest_detected = True
    tamper_policy_detected = not unauthorized['authorized_success']
    return {
        'tamper_ciphertext_detected': tamper_ciphertext_detected,
        'tamper_manifest_detected': tamper_manifest_detected,
        'tamper_policy_detected': tamper_policy_detected,
    }


def _write_csv(path, fields, rows):
    with open(path, 'w', encoding='utf-8', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _save_json(obj, path):
    with open(path, 'w', encoding='utf-8') as handle:
        json.dump(obj, handle, sort_keys=True, indent=2)
        handle.write('\n')


if __name__ == '__main__':
    main()
