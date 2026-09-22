'''
Path helpers for DACP dataset experiments.
'''

from pathlib import Path


def repo_root():
    return Path(__file__).resolve().parents[4]


def ensure_dir(path):
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def default_results_dir():
    return repo_root() / 'shared' / 'results' / 'dacp_data'


def default_data_dir(name):
    return repo_root() / 'shared' / 'data' / name
