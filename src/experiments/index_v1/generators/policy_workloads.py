def fixed_match_or_policy(ell, r):
    if ell < r or r < 1:
        raise ValueError("require ell >= r >= 1")
    attributes = ["MATCH_{0}".format(index) for index in range(r)]
    attributes += ["POLICY_ONLY_{0}".format(index) for index in range(ell - r)]
    policy = {"matrix": [[1] for _ in range(ell)], "rho": attributes}
    return policy, attributes[:r]


def user_attributes(n, matching_attributes):
    if n < len(matching_attributes):
        raise ValueError("N must be at least r")
    return list(matching_attributes) + [
        "USER_ONLY_{0}".format(index) for index in range(n - len(matching_attributes))
    ]
