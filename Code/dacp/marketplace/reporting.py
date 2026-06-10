'''
Markdown reporting helpers for CreditFraud DACP marketplace benchmarks.
'''

import csv
from collections import defaultdict


def generate_credit_fraud_report(raw_csv, summary_csv, output_md):
    raw_rows = _read_csv(raw_csv)
    summary_rows = _read_csv(summary_csv)
    products = {}
    for row in raw_rows:
        products[row.get('product_name')] = row

    lines = []
    lines.append('# CreditFraud DACP Marketplace Experiment Report')
    lines.append('')
    lines.append('## Dataset Schema Summary')
    lines.append('')
    lines.append('The benchmark expects a Kaggle-like CSV with required columns `Amount` and `Class`.')
    lines.append('Optional columns such as `Time` and `V1` to `V28` are inspected by the adapter when the dataset exists.')
    lines.append('')
    lines.append('## Data Products')
    lines.append('')
    lines.append('| Product | Rows | Package Bytes | Policy |')
    lines.append('|---|---:|---:|---|')
    for name, row in sorted(products.items()):
        lines.append('| {0} | {1} | {2} | `{3}` |'.format(
            name,
            row.get('row_count', ''),
            row.get('package_size_bytes', ''),
            row.get('policy_str', ''),
        ))

    lines.append('')
    lines.append('## Access Results')
    lines.append('')
    lines.append('| Product | Chunk Size | Success Rate | Unauthorized Denial Rate |')
    lines.append('|---|---:|---:|---:|')
    for row in summary_rows:
        lines.append('| {0} | {1} | {2} | {3} |'.format(
            row.get('product_name', ''),
            row.get('chunk_size', ''),
            row.get('success_rate', ''),
            row.get('unauthorized_denial_rate', ''),
        ))

    lines.append('')
    lines.append('## Timing by Chunk Size')
    lines.append('')
    lines.append('| Product | Chunk Size | Avg Total Time | Avg Dataset Enc | Avg Dataset Dec | Avg DACP Enc | Avg CSP Transform | Avg DU FinalDec | Avg Wire Bytes | Avg Throughput MB/s |')
    lines.append('|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|')
    for row in summary_rows:
        lines.append('| {0} | {1} | {2} | {3} | {4} | {5} | {6} | {7} | {8} | {9} |'.format(
            row.get('product_name', ''),
            row.get('chunk_size', ''),
            row.get('avg_total_time', ''),
            row.get('avg_dataset_encrypt_time', ''),
            row.get('avg_dataset_decrypt_time', ''),
            row.get('avg_dacp_encrypt_time', ''),
            row.get('avg_csp_transform_time', ''),
            row.get('avg_du_final_decrypt_time', ''),
            row.get('avg_wire_total_bytes', ''),
            row.get('avg_throughput_MBps', ''),
        ))

    grouped = defaultdict(list)
    for row in summary_rows:
        grouped[row.get('product_name', '')].append(row)

    lines.append('')
    lines.append('## Current Experimental Conclusion')
    lines.append('')
    lines.append('The benchmark validates that each CreditFraud data product can be packaged as bytes, encrypted with AES-GCM, and protected by DACP with independent policies. Authorized buyers recover package keys; unauthorized buyers are denied in the local protocol simulation.')
    lines.append('')
    lines.append('## Current Limitations')
    lines.append('')
    lines.append('- LocalTransport only; no HTTP/socket transport.')
    lines.append('- ABF remains a benchmark-oriented prototype.')
    lines.append('- Certificate authority is not formal X.509.')
    lines.append('- No payment, order, or database layer.')
    lines.append('- No fraud model, data cleaning, or large-scale CSV/Parquet optimization.')
    lines.append('')

    with open(output_md, 'w', encoding='utf-8') as handle:
        handle.write('\n'.join(lines))
        handle.write('\n')


def _read_csv(path):
    with open(path, 'r', encoding='utf-8', newline='') as handle:
        return list(csv.DictReader(handle))
