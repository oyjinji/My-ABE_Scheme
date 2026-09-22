'''
Policy templates for local DACP data products.

The readable templates are not real legal license terms. They are local
benchmark access-control templates for data-product experiments.
'''

MARKETPLACE_POLICY_TEMPLATES = {
    "nyc_autonomous_training": "(survey_grade_b_or_above or autonomous_driving_industry) and traffic_model_training",
    "nyc_public_research": "transport_researcher and nyc_public_data_license",
    "credit_fraud_research": "fintech_researcher and fraud_detection_project",
    "credit_risk_restricted": "credit_risk_analyst and compliance_training and restricted_access",
    "mimic_research": "medical_researcher and irb_approved and mimic_dua_signed",
    "teaching_open": "teaching_use or student_research",
}


def get_marketplace_policy(name):
    if name not in MARKETPLACE_POLICY_TEMPLATES:
        raise KeyError('unknown marketplace policy template: {0}'.format(name))
    return MARKETPLACE_POLICY_TEMPLATES[name]


def to_parser_safe_policy(policy_str):
    tokens = []
    current = []
    for char in policy_str:
        if char.isalnum() or char == '_':
            current.append(char)
        else:
            if current:
                tokens.append(_normalize_token(''.join(current)))
                current = []
            tokens.append(char)
    if current:
        tokens.append(_normalize_token(''.join(current)))
    return ''.join(tokens)


def _normalize_token(token):
    if token.lower() in ('and', 'or'):
        return token
    return token.replace('_', '')
