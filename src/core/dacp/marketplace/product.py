'''
Data product manifests for local DACP marketplace experiments.
'''

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime


@dataclass
class DataProduct:
    product_id: str
    dataset_id: str
    product_name: str
    domain: str
    description: str
    policy_str: str
    source_dataset_path: str
    package_path: str
    manifest_path: str
    row_count: int
    column_count: int
    filters: dict
    sensitivity_level: str
    created_at: str


def utc_now_iso():
    return datetime.utcnow().replace(microsecond=0).isoformat() + 'Z'


def make_product_id(dataset_id, product_name, filters):
    payload = json.dumps({
        'dataset_id': dataset_id,
        'product_name': product_name,
        'filters': filters or {},
    }, sort_keys=True, separators=(',', ':')).encode('utf-8')
    return hashlib.sha256(b'dacp::product::' + payload).hexdigest()[:32]


def product_to_dict(product):
    return asdict(product)


def product_from_dict(obj):
    return DataProduct(**obj)


def save_product(product, path):
    with open(path, 'w', encoding='utf-8') as handle:
        json.dump(product_to_dict(product), handle, sort_keys=True, indent=2)
        handle.write('\n')


def load_product(path):
    with open(path, 'r', encoding='utf-8') as handle:
        return product_from_dict(json.load(handle))
