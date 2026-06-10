'''
Base dataset adapter for local DACP marketplace experiments.
'''

import csv
from pathlib import Path

from ..catalog import ProductCatalog
from ..slicing import SimpleCSVSlicer


class DatasetAdapter:
    dataset_name = ''
    domain = ''
    required_columns = []

    def exists(self, dataset_path):
        return Path(dataset_path).exists()

    def inspect_schema(self, dataset_path, sample_rows=5):
        dataset_path = Path(dataset_path)
        if not dataset_path.exists():
            return {
                'exists': False,
                'path': str(dataset_path),
                'columns': [],
                'sample_rows': [],
            }
        with open(dataset_path, 'r', encoding='utf-8', newline='') as handle:
            reader = csv.DictReader(handle)
            columns = list(reader.fieldnames or [])
            samples = []
            for index, row in enumerate(reader):
                if index >= sample_rows:
                    break
                samples.append(row)
        return {
            'exists': True,
            'path': str(dataset_path),
            'columns': columns,
            'num_columns': len(columns),
            'sample_rows': samples,
        }

    def validate_schema(self, dataset_path):
        schema = self.inspect_schema(dataset_path, sample_rows=0)
        columns = set(schema.get('columns', []))
        missing = [column for column in self.required_columns if column not in columns]
        return len(missing) == 0, missing

    def build_slice_rules(self, output_dir=None):
        raise NotImplementedError

    def create_products(self, dataset_path, output_dir):
        rules = self.build_slice_rules(output_dir=output_dir)
        products = SimpleCSVSlicer().slice(dataset_path, rules, output_dir)
        return products, ProductCatalog(products)
