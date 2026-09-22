'''
Local data-product marketplace scaffold for DACP.

This layer models dataset-to-product slicing and local purchase/access tests.
It does not implement payment, HTTP, sockets, databases, or production
compliance workflows.
'''

from .catalog import ProductCatalog
from .policy_templates import (
    MARKETPLACE_POLICY_TEMPLATES,
    get_marketplace_policy,
    to_parser_safe_policy,
)
from .product import (
    DataProduct,
    load_product,
    make_product_id,
    product_from_dict,
    product_to_dict,
    save_product,
)
from .purchase import PurchaseRequest, simulate_purchase_and_access
from .slicing import DatasetSlicer, SimpleCSVSlicer, SliceRule

__all__ = [
    'DataProduct',
    'DatasetSlicer',
    'MARKETPLACE_POLICY_TEMPLATES',
    'ProductCatalog',
    'PurchaseRequest',
    'SimpleCSVSlicer',
    'SliceRule',
    'get_marketplace_policy',
    'load_product',
    'make_product_id',
    'product_from_dict',
    'product_to_dict',
    'save_product',
    'simulate_purchase_and_access',
    'to_parser_safe_policy',
]
