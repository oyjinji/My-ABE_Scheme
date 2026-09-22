'''
Experimental access-control policy templates for dataset experiments.

These are not real license terms for any dataset. They are local benchmark
attribute templates for DACP access-control experiments.
'''

DEFAULT_POLICIES = {
    "credit_fraud": "fintech_researcher and fraud_detection_project",
    "nyc_tlc": "transport_researcher and nyc_public_data_license",
    "lending_club": "credit_risk_analyst and compliance_training",
    "mimic_like": "medical_researcher and irb_approved and mimic_dua_signed",
    "teaching": "teaching_use or student_research",
}


def get_policy(name):
    if name not in DEFAULT_POLICIES:
        raise KeyError('unknown policy template: {0}'.format(name))
    return DEFAULT_POLICIES[name]


def list_policies():
    return dict(DEFAULT_POLICIES)


def to_charm_policy(policy_str):
    """
    Convert readable dataset-policy attributes to Charm parser-safe names.

    Charm-Crypto's policy parser treats underscores as index separators, so the
    dataset scaffold keeps readable manifest policies but removes underscores
    before passing the policy into DACP's MSP parser.
    """

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
