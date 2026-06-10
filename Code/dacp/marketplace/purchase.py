'''
Local purchase/access simulation for DACP data products.

No payment, HTTP, sockets, or database are implemented here.
'''

import json
import uuid
from dataclasses import asdict, dataclass

from Code.dacp.data import run_dataset_file_experiment

from .policy_templates import to_parser_safe_policy
from .product import utc_now_iso


@dataclass
class PurchaseRequest:
    request_id: str
    du_id: str
    product_id: str
    buyer_attrs: list
    created_at: str


def simulate_purchase_and_access(product, buyer_attrs, output_dir,
                                 chunk_mode=False, chunk_size=16 * 1024 * 1024):
    request = PurchaseRequest(
        request_id=uuid.uuid4().hex,
        du_id='DU_MARKETPLACE',
        product_id=product.product_id,
        buyer_attrs=list(buyer_attrs),
        created_at=utc_now_iso(),
    )
    safe_attrs = [
        attr.replace('_', '').upper()
        for attr in request.buyer_attrs
    ]
    summary = run_dataset_file_experiment(
        dataset_path=product.package_path,
        dataset_name=product.product_name,
        domain=product.domain,
        policy_str=product.policy_str,
        output_dir=output_dir,
        chunk_mode=chunk_mode,
        chunk_size=chunk_size,
        buyer_attrs=safe_attrs,
    )
    purchase_summary = {
        'request': asdict(request),
        'product_id': product.product_id,
        'product_name': product.product_name,
        'policy_str': product.policy_str,
        'parser_safe_policy': to_parser_safe_policy(product.policy_str),
        'authorized_success': bool(summary.get('dataset_recover_success')),
        'summary': summary,
    }
    path = str(output_dir) + '/purchase_' + request.request_id + '.json'
    with open(path, 'w', encoding='utf-8') as handle:
        json.dump(purchase_summary, handle, sort_keys=True, indent=2)
        handle.write('\n')
    purchase_summary['purchase_summary_path'] = path
    return purchase_summary
