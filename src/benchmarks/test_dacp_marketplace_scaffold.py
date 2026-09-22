'''
Smoke tests for DACP marketplace scaffold.
'''

import csv
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Code.dacp.marketplace import (
    ProductCatalog,
    SimpleCSVSlicer,
    SliceRule,
    get_marketplace_policy,
    load_product,
    save_product,
    simulate_purchase_and_access,
    to_parser_safe_policy,
)


def assert_true(name, condition):
    if not condition:
        raise AssertionError(name)
    print('{:<52} OK'.format(name))


def write_csv(path):
    rows = [
        {
            'trip_id': '1',
            'pickup_zone': 'Manhattan',
            'dropoff_zone': 'Airport',
            'pickup_time': '2024-01-01T08:10:00',
            'hour': '8',
            'vehicle_type': 'taxi',
            'precision_level': 'high',
            'purpose_tag': 'traffic_model_training',
            'fare_amount': '42.50',
        },
        {
            'trip_id': '2',
            'pickup_zone': 'Queens',
            'dropoff_zone': 'Manhattan',
            'pickup_time': '2024-01-01T23:30:00',
            'hour': '23',
            'vehicle_type': 'taxi',
            'precision_level': 'normal',
            'purpose_tag': 'night_planning',
            'fare_amount': '22.00',
        },
        {
            'trip_id': '3',
            'pickup_zone': 'Manhattan',
            'dropoff_zone': 'Brooklyn',
            'pickup_time': '2024-01-01T09:30:00',
            'hour': '9',
            'vehicle_type': 'rideshare',
            'precision_level': 'high',
            'purpose_tag': 'public_research',
            'fare_amount': '16.00',
        },
    ]
    with open(path, 'w', encoding='utf-8', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def test_product_catalog_policy(tmp):
    dataset = tmp / 'nyc.csv'
    write_csv(dataset)
    rules = [SliceRule(
        rule_id='equals',
        product_name='Manhattan Morning',
        domain='transportation',
        description='Synthetic Manhattan morning rows',
        policy_template='nyc_autonomous_training',
        policy_str=None,
        filters={
            'zone': {'op': 'equals', 'column': 'pickup_zone', 'value': 'Manhattan'},
            'hour': {'op': 'range', 'column': 'hour', 'min': 8, 'max': 10},
            'purpose': {'op': 'contains', 'column': 'purpose_tag', 'value': 'traffic'},
        },
        output_file_name='manhattan_morning.csv',
        sensitivity_level='high',
    )]
    products = SimpleCSVSlicer().slice(dataset, rules, tmp / 'products')
    product = products[0]
    save_product(product, tmp / 'product.json')
    loaded = load_product(tmp / 'product.json')
    assert_true('DataProduct save/load', loaded.product_id == product.product_id)
    assert_true('SliceRule produced rows', product.row_count == 1)
    assert_true('parser-safe policy', '_' not in to_parser_safe_policy(product.policy_str))

    catalog = ProductCatalog()
    catalog.add_product(product)
    catalog_path = tmp / 'catalog.json'
    catalog.save_json(catalog_path)
    loaded_catalog = ProductCatalog.load_json(catalog_path)
    assert_true('ProductCatalog save/load', loaded_catalog.find_by_id(product.product_id).product_name == product.product_name)
    assert_true('ProductCatalog find_by_domain', len(loaded_catalog.find_by_domain('transportation')) == 1)
    return product


def test_filters(tmp):
    dataset = tmp / 'nyc_filters.csv'
    write_csv(dataset)
    rules = [
        SliceRule('in', 'Airport Trips', 'transportation', 'airport', 'nyc_public_research', None,
                  {'airport': {'op': 'in', 'column': 'dropoff_zone', 'values': ['Airport']}},
                  'airport.csv'),
        SliceRule('time', 'Morning Time', 'transportation', 'time', 'teaching_open', None,
                  {'time': {'op': 'time_range', 'column': 'pickup_time', 'start': '2024-01-01T08:00:00', 'end': '2024-01-01T10:00:00'}},
                  'time.csv'),
        SliceRule('bad', 'Bad Rule', 'transportation', 'bad', 'teaching_open', None,
                  {'bad': {'op': 'equals', 'column': 'missing_column', 'value': 'x'}},
                  'bad.csv'),
    ]
    products = SimpleCSVSlicer().slice(dataset, rules, tmp / 'filter_products')
    assert_true('SimpleCSVSlicer in filter', products[0].row_count == 1)
    assert_true('SimpleCSVSlicer time_range filter', products[1].row_count == 2)
    assert_true('SimpleCSVSlicer missing field isolated', 'error' in products[2].filters)


def test_purchase(tmp, product):
    authorized = simulate_purchase_and_access(
        product,
        buyer_attrs=['survey_grade_b_or_above', 'traffic_model_training'],
        output_dir=tmp / 'authorized',
        chunk_mode=False,
    )
    assert_true('purchase authorized succeeds', authorized['authorized_success'])
    unauthorized = simulate_purchase_and_access(
        product,
        buyer_attrs=['student_research'],
        output_dir=tmp / 'unauthorized',
        chunk_mode=False,
    )
    assert_true('purchase unauthorized denied', not unauthorized['authorized_success'])


def main():
    with tempfile.TemporaryDirectory() as work:
        tmp = Path(work)
        product = test_product_catalog_policy(tmp)
        test_filters(tmp)
        test_purchase(tmp, product)
        assert_true('marketplace policy template', get_marketplace_policy('teaching_open') == 'teaching_use or student_research')
    print('=' * 72)
    print('DACP marketplace scaffold tests passed.')


if __name__ == '__main__':
    main()
