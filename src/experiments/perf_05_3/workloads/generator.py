"""Shared deterministic policy/LSSS workloads."""

from dataclasses import dataclass

from core.fxabe_05_3_exp.encoding import encode
from core.fxabe_05_3_exp.lsss import policy_rows


@dataclass(frozen=True)
class Workload:
    name: str
    policy_string: str
    policy: dict
    user_attributes: tuple
    ell: int
    k: int

    def fingerprint(self):
        import hashlib
        return hashlib.sha256(encode([self.policy["A"], self.policy["rho"]])).hexdigest()


def _label(i):
    return "P%04d" % int(i)


def or_workload(group, ell, matched=None):
    ell = int(ell)
    text = "(" + " or ".join(_label(i) for i in range(ell)) + ")"
    matrix, rho = policy_rows(group, text)
    matched = ell if matched is None else min(ell, int(matched))
    return Workload("OR", text, {"A": matrix, "rho": rho},
                    tuple(rho[:matched]), ell, 1)


def and_workload(group, ell, labels=None):
    ell = int(ell)
    text = "(" + " and ".join(_label(i) for i in range(ell)) + ")"
    matrix, rho = policy_rows(group, text)
    if labels is not None:
        rho = list(labels)
    return Workload("AND", text, {"A": matrix, "rho": rho}, tuple(dict.fromkeys(rho)), ell, ell)


def threshold_workload(_group, n, k, chosen=None):
    n, k = int(n), int(k)
    rho = ["T%04d" % i for i in range(1, n + 1)]
    matrix = [[pow(x, degree) for degree in range(k)] for x in range(1, n + 1)]
    chosen = tuple(rho[:k] if chosen is None else chosen)
    return Workload("Threshold", "N/A-explicit-LSSS", {"A": matrix, "rho": rho}, chosen, n, k)


def duplicate_workload(group, ell, t_i):
    """AND matrix with fixed k=ell and labels arranged for t_I slots."""
    ell, t_i = int(ell), int(t_i)
    if ell % t_i:
        raise ValueError("ell must be divisible by t_I")
    distinct = ell // t_i
    labels = ["D%04d" % label for label in range(distinct) for _ in range(t_i)]
    return and_workload(group, ell, labels)


def distinct_token_workload(_group, ell, u):
    """OR LSSS with exactly ``u`` balanced distinct policy labels.

    Repetition is real: each equal label receives occurrence ranks 1..h in
    row order.  The caller must enforce ``ceil(ell/u) <= c_max``.
    """
    ell, u = int(ell), int(u)
    if ell < 1 or u < 1 or u > ell:
        raise ValueError("require 1 <= u <= ell")
    base, remainder = divmod(ell, u)
    rho = []
    for index in range(u):
        rho.extend(["U%04d" % index] * (base + int(index < remainder)))
    if len(rho) != ell or len(set(rho)) != u:
        raise AssertionError("distinct-token workload construction failed")
    return Workload(
        "OR-Duplicate", "N/A-explicit-OR-LSSS",
        {"A": [[1] for _ in range(ell)], "rho": rho},
        tuple(dict.fromkeys(rho)), ell, 1,
    )
