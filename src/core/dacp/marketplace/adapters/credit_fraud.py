'''
Kaggle Credit Card Fraud Detection CSV adapter.

This adapter only checks minimal CSV schema and slices rows into data products.
It does not train fraud models or perform statistical analysis.
'''

from .base import DatasetAdapter
from ..slicing import SliceRule


class CreditFraudCSVAdapter(DatasetAdapter):
    dataset_name = 'Credit Card Fraud Detection'
    domain = 'financial'
    required_columns = ['Amount', 'Class']

    def __init__(self, high_amount_threshold=100.0, teaching_limit=5000):
        self.high_amount_threshold = float(high_amount_threshold)
        self.teaching_limit = int(teaching_limit)

    def inspect_schema(self, dataset_path, sample_rows=5):
        schema = super().inspect_schema(dataset_path, sample_rows=sample_rows)
        columns = set(schema.get('columns', []))
        schema['has_time'] = 'Time' in columns
        schema['present_v_columns'] = [
            'V{0}'.format(index)
            for index in range(1, 29)
            if 'V{0}'.format(index) in columns
        ]
        schema['missing_optional_v_columns'] = [
            'V{0}'.format(index)
            for index in range(1, 29)
            if 'V{0}'.format(index) not in columns
        ]
        return schema

    def build_slice_rules(self, output_dir=None):
        return [
            SliceRule(
                rule_id='fraud_positive_samples',
                product_name='Fraud Positive Samples',
                domain=self.domain,
                description='Transactions labeled as fraud positive samples.',
                policy_template=None,
                policy_str='fintech_researcher and fraud_detection_project and restricted_access',
                filters={
                    'Class': {'equals': '1'},
                },
                output_file_name='credit_fraud_positive_samples.csv',
                sensitivity_level='restricted',
            ),
            SliceRule(
                rule_id='high_amount_transactions',
                product_name='High Amount Transactions',
                domain=self.domain,
                description='Transactions with Amount greater than or equal to threshold.',
                policy_template=None,
                policy_str='credit_risk_analyst and compliance_training',
                filters={
                    'Amount': {'range': {'min': self.high_amount_threshold}},
                },
                output_file_name='credit_fraud_high_amount_transactions.csv',
                sensitivity_level='normal',
            ),
            SliceRule(
                rule_id='teaching_sample',
                product_name='Teaching Sample',
                domain=self.domain,
                description='Bounded teaching sample containing normal and fraud labels.',
                policy_template=None,
                policy_str='teaching_use or student_research',
                filters={
                    'Class': {'in': ['0', '1']},
                    '__limit__': self.teaching_limit,
                },
                output_file_name='credit_fraud_teaching_sample.csv',
                sensitivity_level='teaching',
            ),
            SliceRule(
                rule_id='normal_low_amount_baseline',
                product_name='Normal Low Amount Baseline',
                domain=self.domain,
                description='Optional normal low-amount baseline sample.',
                policy_template=None,
                policy_str='teaching_use or student_research',
                filters={
                    'Class': {'equals': '0'},
                    'Amount': {'range': {'max': 50}},
                },
                output_file_name='credit_fraud_normal_low_amount_baseline.csv',
                sensitivity_level='teaching',
            ),
        ]

    def authorized_attrs_for(self, product):
        if product.product_name == 'Fraud Positive Samples':
            return ['fintech_researcher', 'fraud_detection_project', 'restricted_access']
        if product.product_name == 'High Amount Transactions':
            return ['credit_risk_analyst', 'compliance_training']
        return ['teaching_use']

    def unauthorized_attrs_for(self, product):
        if product.product_name == 'Fraud Positive Samples':
            return ['teaching_use', 'student_research']
        if product.product_name == 'High Amount Transactions':
            return ['fintech_researcher']
        return ['commercial_buyer']
