"""Deterministic shared workloads consumed identically by every scheme.

A workload fixes (once, before any scheme runs):

* the LSSS policy (``policy`` string plus canonical ``matrix`` / ``rho``),
* the user attribute set ``S`` (with a controlled satisfaction ratio),
* the plaintext / KEM message,
* a per-workload random ``seed``.

All three scheme adapters consume the *same* workload object, so the policy
fingerprint, matrix fingerprint, rho fingerprint, user-set fingerprint and
message fingerprint are identical across FABEO22 / FXABE-Base / FXABE-Full
for every experimental point.

Policy size is defined by ``l = number of LSSS policy rows`` (requirement
5.2).  We use a monotone OR policy over ``l`` distinct attributes, which the
repository's MSP conversion maps to exactly ``l`` unit rows (verified against
``Code/msp`` and ``Code/fxabe_rev/lsss.py``).
"""

import hashlib
import math
from dataclasses import dataclass, field

from .common import derive_seed, fingerprint


def or_policy(l):
    """Boolean OR policy string whose MSP conversion has exactly ``l`` rows."""
    return "(" + " or ".join("P%04d" % index for index in range(int(l))) + ")"


def policy_rho(l):
    """Canonical rho for an OR policy over ``l`` attributes."""
    return ["P%04d" % index for index in range(int(l))]


def policy_matrix(l):
    """Canonical LSSS matrix: ``l`` unit rows (the OR-policy span program)."""
    return [[1] for _ in range(int(l))]


def user_set_for(l, user_attrs, satisfied_rows):
    """Deterministic user attribute list.

    The first ``satisfied_rows`` attributes are policy attributes (satisfying),
    the remaining ones are non-policy ``U`` attributes so that
    ``satisfied_rows / l`` matches the configured satisfaction ratio.
    """
    if satisfied_rows < 0 or satisfied_rows > user_attrs:
        raise ValueError("satisfied_rows must be in [0, user_attrs]")
    satisfying = ["P%04d" % index for index in range(int(satisfied_rows))]
    extras = ["U%04d" % index for index in range(int(user_attrs) - int(satisfied_rows))]
    return satisfying + extras


@dataclass
class Workload:
    experiment: str
    master_seed: int
    seed: int
    policy_rows_l: int
    policy_cols: int
    user_attrs: int
    satisfied_rows: int
    universe_size: int
    policy: str
    matrix: list
    rho: list
    user_set: list
    message_seed: int
    message_bytes: bytes
    message_gt_int: int
    fingerprints: dict = field(default_factory=dict)

    @property
    def satisfaction_ratio(self):
        return self.satisfied_rows / float(self.policy_rows_l)


def compute_fingerprints(workload):
    return {
        "policy_hash": fingerprint(workload.policy),
        "matrix_hash": fingerprint(workload.matrix),
        "rho_hash": fingerprint(workload.rho),
        "user_set_hash": fingerprint(workload.user_set),
        "message_hash": fingerprint(workload.message_seed),
    }


def build_workload(master_seed, experiment, seed, policy_rows_l, user_attrs,
                   satisfaction_ratio=0.5):
    """Build a fully deterministic workload object."""
    l = int(policy_rows_l)
    user_attrs = int(user_attrs)
    if l < 1:
        raise ValueError("policy_rows_l must be >= 1")
    if user_attrs < 1:
        raise ValueError("user_attrs must be >= 1")
    satisfied = min(user_attrs, max(1, int(math.ceil(l * satisfaction_ratio))))
    policy = or_policy(l)
    rho = policy_rho(l)
    matrix = policy_matrix(l)
    user_set = user_set_for(l, user_attrs, satisfied)
    message_seed = derive_seed(master_seed, experiment, seed, "message")
    message_bytes = hashlib.sha256(
        derive_seed(master_seed, experiment, seed, "message-bytes").to_bytes(8, "big")
    ).digest()[:32]
    workload = Workload(
        experiment=experiment,
        master_seed=int(master_seed),
        seed=int(seed),
        policy_rows_l=l,
        policy_cols=len(matrix[0]),
        user_attrs=user_attrs,
        satisfied_rows=satisfied,
        universe_size=l + max(0, user_attrs - satisfied),
        policy=policy,
        matrix=matrix,
        rho=rho,
        user_set=user_set,
        message_seed=message_seed,
        message_bytes=message_bytes,
        message_gt_int=message_seed % (2 ** 31),
    )
    workload.fingerprints = compute_fingerprints(workload)
    return workload
