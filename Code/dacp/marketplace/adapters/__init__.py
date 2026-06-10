'''
Dataset-specific adapter registry for DACP marketplace experiments.
'''

from .base import DatasetAdapter
from .credit_fraud import CreditFraudCSVAdapter

__all__ = [
    'DatasetAdapter',
    'CreditFraudCSVAdapter',
]
