'''
Smoke tests for DACP dataset summary and batch CLI helpers.
'''

import csv
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Code.dacp.data.summary import append_summary_csv, normalize_summary, save_summary_json


def assert_true(name, condition):
    if not condition:
        raise AssertionError(name)
    print('{:<48} OK'.format(name))


def test_summary_helpers(tmp):
    summary = normalize_summary({
        'dataset_id': 'd1',
        'dataset_name': 'Dataset',
        'domain': 'test',
        'dataset_recover_success': True,
    })
    assert_true('normalize_summary stable fields', 'wire_total_bytes' in summary and summary['dataset_id'] == 'd1')

    json_path = tmp / 'summary.json'
    saved = save_summary_json(summary, json_path)
    loaded = json.loads(json_path.read_text(encoding='utf-8'))
    assert_true('save_summary_json', loaded['summary_path'] == str(json_path) and saved['summary_path'] == str(json_path))

    csv_path = tmp / 'summary.csv'
    append_summary_csv(saved, csv_path)
    rows = list(csv.DictReader(open(csv_path, 'r', encoding='utf-8')))
    assert_true('append_summary_csv', rows[0]['dataset_id'] == 'd1')


def test_batch_missing_file(tmp):
    config_path = tmp / 'missing.json'
    csv_path = tmp / 'batch.csv'
    config = {
        'experiments': [{
            'dataset_path': str(tmp / 'missing.csv'),
            'dataset_name': 'missing_dataset',
            'domain': 'test',
            'policy_template': 'credit_fraud',
            'output_dir': str(tmp / 'missing_output'),
            'chunk_mode': True,
            'chunk_size': 64,
        }]
    }
    config_path.write_text(json.dumps(config), encoding='utf-8')
    output = subprocess.check_output(
        [
            sys.executable,
            str(ROOT / 'Benchmark' / 'benchmark_dacp_dataset_files.py'),
            '--config',
            str(config_path),
            '--summary-csv',
            str(csv_path),
        ],
        cwd=str(ROOT),
        universal_newlines=True,
    )
    rows = list(csv.DictReader(open(csv_path, 'r', encoding='utf-8')))
    assert_true('batch missing file skipped', 'SKIPPED' in output and rows[0]['skipped'] == 'True')


def test_file_cli_summary(tmp):
    dataset_path = tmp / 'synthetic.csv'
    dataset_path.write_text('id,value\n1,alpha\n2,beta\n', encoding='utf-8')
    output_dir = tmp / 'experiment'
    csv_path = tmp / 'summary.csv'
    output = subprocess.check_output(
        [
            sys.executable,
            str(ROOT / 'Benchmark' / 'run_dacp_dataset_file.py'),
            '--dataset-path',
            str(dataset_path),
            '--dataset-name',
            'summary_cli',
            '--domain',
            'test',
            '--policy-template',
            'credit_fraud',
            '--output-dir',
            str(output_dir),
            '--chunk-mode',
            '--chunk-size',
            '16',
            '--summary-csv',
            str(csv_path),
        ],
        cwd=str(ROOT),
        universal_newlines=True,
    )
    rows = list(csv.DictReader(open(csv_path, 'r', encoding='utf-8')))
    assert_true('file CLI prints final paths', 'dataset_recover_success=True' in output and 'summary_path=' in output)
    assert_true('file CLI summary CSV', rows[0]['dataset_recover_success'] == 'True')
    summary_path = Path(rows[0]['summary_path'])
    assert_true('file CLI summary JSON exists', summary_path.exists())


def main():
    with tempfile.TemporaryDirectory() as work:
        tmp = Path(work)
        test_summary_helpers(tmp)
        test_batch_missing_file(tmp)
        test_file_cli_summary(tmp)
    print('=' * 72)
    print('DACP data summary tests passed.')


if __name__ == '__main__':
    main()
