'''
Synthetic marketplace demo for DACP data products.
'''

import argparse
import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Code.dacp.marketplace import (
    ProductCatalog,
    SimpleCSVSlicer,
    SliceRule,
    get_marketplace_policy,
    simulate_purchase_and_access,
)


def write_synthetic_nyc(path, num_rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    zones = ['Manhattan', 'Queens', 'Brooklyn', 'Airport']
    with open(path, 'w', encoding='utf-8', newline='') as handle:
        fieldnames = [
            'trip_id',
            'pickup_zone',
            'dropoff_zone',
            'pickup_time',
            'hour',
            'vehicle_type',
            'precision_level',
            'purpose_tag',
            'fare_amount',
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for index in range(int(num_rows)):
            hour = index % 24
            pickup = zones[index % len(zones)]
            dropoff = zones[(index + 1) % len(zones)]
            precision = 'high' if index % 3 == 0 else 'normal'
            purpose = 'traffic_model_training' if index % 5 == 0 else (
                'night_planning' if hour >= 22 or hour <= 5 else 'public_research'
            )
            if index % 100 == 0:
                hour = 8
                pickup = 'Manhattan'
                precision = 'high'
                purpose = 'traffic_model_training'
            if index % 11 == 0:
                dropoff = 'Airport'
            writer.writerow({
                'trip_id': str(index + 1),
                'pickup_zone': pickup,
                'dropoff_zone': dropoff,
                'pickup_time': '2024-01-01T{0:02d}:15:00'.format(hour),
                'hour': str(hour),
                'vehicle_type': 'taxi' if index % 2 == 0 else 'rideshare',
                'precision_level': precision,
                'purpose_tag': purpose,
                'fare_amount': '{0:.2f}'.format(10.0 + (index % 40) * 1.25),
            })


def make_rules():
    return [
        SliceRule(
            rule_id='manhattan_morning_high_precision',
            product_name='Manhattan Morning High Precision',
            domain='transportation',
            description='Manhattan morning peak trips with high precision telemetry.',
            policy_template='nyc_autonomous_training',
            policy_str=get_marketplace_policy('nyc_autonomous_training'),
            filters={
                'pickup_zone': {'op': 'equals', 'column': 'pickup_zone', 'value': 'Manhattan'},
                'hour': {'op': 'range', 'column': 'hour', 'min': 7, 'max': 10},
                'precision': {'op': 'equals', 'column': 'precision_level', 'value': 'high'},
            },
            output_file_name='product_manhattan_morning_high_precision.csv',
            sensitivity_level='restricted',
        ),
        SliceRule(
            rule_id='airport_trips',
            product_name='Airport Trips Public Research',
            domain='transportation',
            description='Synthetic airport-related trips for public research.',
            policy_template='nyc_public_research',
            policy_str=get_marketplace_policy('nyc_public_research'),
            filters={
                'airport': {'op': 'in', 'column': 'dropoff_zone', 'values': ['Airport']},
            },
            output_file_name='product_airport_trips.csv',
            sensitivity_level='normal',
        ),
        SliceRule(
            rule_id='night_trips',
            product_name='Night Trips Planning',
            domain='transportation',
            description='Synthetic late-night trips for planning labs and agencies.',
            policy_template=None,
            policy_str='urban_planning_lab or government_agency',
            filters={
                'night': {'op': 'range', 'column': 'hour', 'min': 22, 'max': 23},
            },
            output_file_name='product_night_trips.csv',
            sensitivity_level='normal',
        ),
    ]


def buyer_attrs_for(product_name, authorized):
    if not authorized:
        return ['student_research']
    if 'Manhattan' in product_name:
        return ['survey_grade_b_or_above', 'traffic_model_training']
    if 'Airport' in product_name:
        return ['transport_researcher', 'nyc_public_data_license']
    return ['urban_planning_lab']


def main():
    parser = argparse.ArgumentParser(description='Run synthetic DACP marketplace demo.')
    parser.add_argument('--output-dir', default='results/dacp_marketplace/synthetic_nyc')
    parser.add_argument('--num-rows', type=int, default=1000)
    parser.add_argument('--chunk-mode', action='store_true')
    parser.add_argument('--chunk-size', type=int, default=4096)
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    product_dir = ROOT / 'data' / 'products' / 'synthetic_nyc'
    dataset_path = ROOT / 'data' / 'work' / 'synthetic_nyc_marketplace.csv'
    write_synthetic_nyc(dataset_path, args.num_rows)

    products = SimpleCSVSlicer().slice(dataset_path, make_rules(), product_dir)
    catalog = ProductCatalog(products)
    output_dir.mkdir(parents=True, exist_ok=True)
    catalog_path = output_dir / 'catalog.json'
    catalog.save_json(catalog_path)

    print('DACP synthetic marketplace demo')
    print('=' * 120)
    print('catalog_path: {0}'.format(catalog_path))
    print('{:<34} {:<38} {:>9} {:<72} {:<8} {:<8} {}'.format(
        'product_id',
        'product_name',
        'rows',
        'policy_str',
        'auth',
        'unauth',
        'summary_path',
    ))
    for product in products:
        authorized = simulate_purchase_and_access(
            product,
            buyer_attrs_for(product.product_name, authorized=True),
            output_dir=output_dir / product.product_id / 'authorized',
            chunk_mode=args.chunk_mode,
            chunk_size=args.chunk_size,
        )
        unauthorized = simulate_purchase_and_access(
            product,
            buyer_attrs_for(product.product_name, authorized=False),
            output_dir=output_dir / product.product_id / 'unauthorized',
            chunk_mode=args.chunk_mode,
            chunk_size=args.chunk_size,
        )
        print('{:<34} {:<38} {:>9} {:<72} {:<8} {:<8} {}'.format(
            product.product_id,
            product.product_name[:38],
            product.row_count,
            product.policy_str[:72],
            str(authorized['authorized_success']),
            str(unauthorized['authorized_success']),
            authorized['summary']['summary_path'],
        ))


if __name__ == '__main__':
    main()
