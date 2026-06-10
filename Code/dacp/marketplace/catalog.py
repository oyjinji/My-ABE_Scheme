'''
Local JSON product catalog for DACP marketplace experiments.
'''

import json

from .product import product_from_dict, product_to_dict


class ProductCatalog:
    def __init__(self, products=None):
        self.products = list(products or [])

    def add_product(self, product):
        self.products.append(product)
        return product

    def list_products(self):
        return list(self.products)

    def find_by_id(self, product_id):
        for product in self.products:
            if product.product_id == product_id:
                return product
        return None

    def find_by_domain(self, domain):
        return [product for product in self.products if product.domain == domain]

    def save_json(self, path):
        with open(path, 'w', encoding='utf-8') as handle:
            json.dump(
                {'products': [product_to_dict(product) for product in self.products]},
                handle,
                sort_keys=True,
                indent=2,
            )
            handle.write('\n')

    @classmethod
    def load_json(cls, path):
        with open(path, 'r', encoding='utf-8') as handle:
            obj = json.load(handle)
        return cls([product_from_dict(item) for item in obj.get('products', [])])
