'''
Dataset slicing interfaces for local DACP marketplace experiments.

SimpleCSVSlicer is intentionally small and standard-library only. It is meant
for synthetic CSVs and small local samples, not high-performance production
Parquet slicing.
'''

import csv
import hashlib
from dataclasses import dataclass
from pathlib import Path

from .policy_templates import get_marketplace_policy
from .product import DataProduct, make_product_id, save_product, utc_now_iso


@dataclass
class SliceRule:
    rule_id: str
    product_name: str
    domain: str
    description: str
    policy_template: str
    policy_str: str
    filters: dict
    output_file_name: str
    sensitivity_level: str = "normal"


class DatasetSlicer:
    def slice(self, dataset_path, rules, output_dir):
        raise NotImplementedError


class SimpleCSVSlicer(DatasetSlicer):
    def slice(self, dataset_path, rules, output_dir):
        dataset_path = Path(dataset_path)
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        dataset_id = _dataset_id(dataset_path)
        products = []
        for rule in rules:
            products.append(self._slice_one(dataset_path, dataset_id, rule, output_dir))
        return products

    def _slice_one(self, dataset_path, dataset_id, rule, output_dir):
        package_path = output_dir / rule.output_file_name
        product_id = make_product_id(dataset_id, rule.product_name, rule.filters)
        product_manifest_path = output_dir / (product_id + '.product.json')
        row_count = 0
        column_count = None
        error = None

        try:
            limit = _extract_limit(rule.filters)
            with open(dataset_path, 'r', encoding='utf-8', newline='') as source:
                reader = csv.DictReader(source)
                fieldnames = reader.fieldnames or []
                column_count = len(fieldnames)
                _validate_filter_columns(rule.filters, fieldnames)
                with open(package_path, 'w', encoding='utf-8', newline='') as out:
                    writer = csv.DictWriter(out, fieldnames=fieldnames)
                    writer.writeheader()
                    for row in reader:
                        if _matches_filters(row, rule.filters):
                            writer.writerow(row)
                            row_count += 1
                            if limit is not None and row_count >= limit:
                                break
        except Exception as exc:
            error = str(exc)
            package_path.write_text('', encoding='utf-8')

        filters = dict(rule.filters or {})
        if error is not None:
            filters['error'] = error

        policy_str = rule.policy_str or get_marketplace_policy(rule.policy_template)
        product = DataProduct(
            product_id=product_id,
            dataset_id=dataset_id,
            product_name=rule.product_name,
            domain=rule.domain,
            description=rule.description,
            policy_str=policy_str,
            source_dataset_path=str(dataset_path),
            package_path=str(package_path),
            manifest_path=str(product_manifest_path),
            row_count=row_count,
            column_count=column_count,
            filters=filters,
            sensitivity_level=rule.sensitivity_level,
            created_at=utc_now_iso(),
        )
        save_product(product, product_manifest_path)
        return product


def _dataset_id(path):
    digest = hashlib.sha256()
    digest.update(str(path).encode('utf-8'))
    try:
        with open(path, 'rb') as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b''):
                digest.update(chunk)
    except FileNotFoundError:
        pass
    return digest.hexdigest()[:32]


def _validate_filter_columns(filters, fieldnames):
    for key, value in (filters or {}).items():
        if key == '__limit__':
            continue
        rule = _normalize_filter_rule(key, value)
        column = rule.get('column')
        if column and column not in fieldnames:
            raise ValueError('filter column does not exist: {0}'.format(column))


def _matches_filters(row, filters):
    for key, value in (filters or {}).items():
        if key == '__limit__':
            continue
        rule = _normalize_filter_rule(key, value)
        op = rule.get('op')
        column = rule.get('column')
        value = row.get(column, '')
        if op == 'equals':
            if not _values_equal(value, rule.get('value')):
                return False
        elif op == 'in':
            values = rule.get('values', [])
            if not any(_values_equal(value, item) for item in values):
                return False
        elif op == 'range':
            try:
                numeric = float(value)
            except ValueError:
                return False
            if 'min' in rule and numeric < float(rule['min']):
                return False
            if 'max' in rule and numeric > float(rule['max']):
                return False
        elif op == 'time_range':
            start = str(rule.get('start', ''))
            end = str(rule.get('end', ''))
            if start and value < start:
                return False
            if end and value > end:
                return False
        elif op == 'contains':
            if str(rule.get('value', '')) not in value:
                return False
        else:
            raise ValueError('unsupported filter op: {0}'.format(op))
    return True


def _extract_limit(filters):
    if not filters or '__limit__' not in filters:
        return None
    return int(filters['__limit__'])


def _normalize_filter_rule(key, value):
    if 'op' in value:
        return value
    if 'equals' in value:
        return {'op': 'equals', 'column': key, 'value': value['equals']}
    if 'in' in value:
        return {'op': 'in', 'column': key, 'values': value['in']}
    if 'range' in value:
        range_rule = dict(value['range'])
        range_rule.update({'op': 'range', 'column': key})
        return range_rule
    if 'time_range' in value:
        time_rule = dict(value['time_range'])
        time_rule.update({'op': 'time_range', 'column': key})
        return time_rule
    if 'contains' in value:
        return {'op': 'contains', 'column': key, 'value': value['contains']}
    raise ValueError('unsupported filter rule for {0}: {1}'.format(key, value))


def _values_equal(left, right):
    if str(left) == str(right):
        return True
    try:
        return float(left) == float(right)
    except (TypeError, ValueError):
        return False
