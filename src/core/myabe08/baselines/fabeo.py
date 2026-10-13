"""FABEO Figure 1 CP-ABE common BLS12-381 performance port.

The τ=1 profile is cross-checkable against released source. The multi-use
profile follows the paper, and is separately gated by correctness tests.
No security proof transfers from the paper to this Python implementation.
"""
from dataclasses import dataclass
import hashlib

from ..crypto import BLS12381Backend
from ..errors import ContractError, Unauthorized
from ..lsss import LSSSMatrix, authorized_subset


def _digest(label: str) -> bytes:
    if type(label) is not str or not label:
        raise ContractError('nonempty attribute label required')
    return hashlib.sha256(b'FABEO22-BLS12381-HASH-V1\x00' +
                          label.encode('utf-8')).digest()


def _s(backend, value):
    return backend.scalar_from_int(value % backend.scalar_order)


def _integer(backend, value):
    return int.from_bytes(backend.serialize_scalar(value), 'big')


def _add_many(backend, points):
    result = None
    for point in points:
        result = point if result is None else backend.g1_add(result, point)
    if result is None:
        raise ContractError('empty G1 aggregation')
    return result


@dataclass(frozen=True)
class PublicParameters:
    backend: BLS12381Backend
    g1: object
    g2: object
    target_alpha: object
    boundary: object


@dataclass(frozen=True)
class SecretKey:
    labels: tuple
    sk2: object
    sk_by_label: dict
    g2_r: object


@dataclass(frozen=True)
class Ciphertext:
    matrix: LSSSMatrix
    labels: tuple
    ranks: tuple
    g2_s: object
    g2_sprime: tuple
    rows: tuple
    masked: object


def setup(backend: BLS12381Backend):
    """Figure 1 Setup with independently sampled generator multiples."""
    if type(backend) is not BLS12381Backend:
        raise ContractError('common BLS12-381 backend required')
    x = backend.random_scalar(binding=backend.binding, nonzero=True)
    y = backend.random_scalar(binding=backend.binding, nonzero=True)
    alpha = backend.random_scalar(binding=backend.binding, nonzero=True)
    g1 = backend.g1_mul(backend.g1_generator(), x)
    g2 = backend.g2_mul(backend.g2_generator(), y)
    target = backend.gt_pow(backend.pair(g1, g2), alpha)
    boundary = backend.hash_to_g1(_digest('BOUNDARY:' + str(backend.scalar_order)))
    return PublicParameters(backend, g1, g2, target, boundary), alpha


def keygen(pp: PublicParameters, alpha, labels: tuple):
    backend = pp.backend
    if type(labels) is not tuple or not labels or len(set(labels)) != len(labels):
        raise ContractError('unique nonempty user attributes required')
    r = backend.random_scalar(binding=backend.binding, nonzero=True)
    sk2 = backend.g1_add(backend.g1_mul(pp.g1, alpha),
                         backend.g1_mul(pp.boundary, r))
    parts = {label: backend.g1_mul(backend.hash_to_g1(_digest(label)), r)
             for label in labels}
    return SecretKey(labels, sk2, parts, backend.g2_mul(pp.g2, r))


def encrypt(pp: PublicParameters, matrix: LSSSMatrix, labels: tuple, message):
    backend = pp.backend
    if (type(matrix) is not LSSSMatrix or matrix.field_order != backend.scalar_order
            or type(labels) is not tuple or len(labels) != matrix.ell):
        raise ContractError('FABEO matrix/labels mismatch')
    backend.serialize_gt(message)
    seen = {}
    ranks = []
    for label in labels:
        _digest(label)
        seen[label] = seen.get(label, 0) + 1
        ranks.append(seen[label])
    tau = max(ranks)
    s = backend.random_scalar(binding=backend.binding, nonzero=True)
    vector = (s,) + tuple(backend.random_scalar(binding=backend.binding,
                                                nonzero=False)
                          for _ in range(matrix.d - 1))
    sprime = tuple(backend.random_scalar(binding=backend.binding, nonzero=True)
                   for _ in range(tau))
    g2_s = backend.g2_mul(pp.g2, s)
    g2_sprime = tuple(backend.g2_mul(pp.g2, x) for x in sprime)
    rows = []
    for row, label, rank in zip(matrix.rows, labels, ranks):
        lam = sum(value * _integer(backend, scalar)
                  for value, scalar in zip(row, vector))
        rows.append(backend.g1_add(
            backend.g1_mul(pp.boundary, _s(backend, lam)),
            backend.g1_mul(backend.hash_to_g1(_digest(label)),
                           sprime[rank - 1])))
    masked = backend.gt_mul(message, backend.gt_pow(pp.target_alpha, s))
    return Ciphertext(matrix, labels, tuple(ranks), g2_s, g2_sprime,
                      tuple(rows), masked)


def decrypt(pp: PublicParameters, ct: Ciphertext, key: SecretKey):
    backend = pp.backend
    if type(ct) is not Ciphertext or type(key) is not SecretKey:
        raise ContractError('FABEO CT and SK required')
    candidates = tuple(i for i, label in enumerate(ct.labels, 1)
                       if label in key.sk_by_label)
    solution = authorized_subset(ct.matrix, candidates, backend)
    weighted_ct = []
    weighted_keys = {}
    for term in solution.terms:
        i = term.row - 1
        coeff = term.coefficient
        weighted_ct.append(backend.g1_mul(ct.rows[i], coeff))
        weighted_keys.setdefault(ct.ranks[i], []).append(
            backend.g1_mul(key.sk_by_label[ct.labels[i]], coeff))
    kem = backend.pair(key.sk2, ct.g2_s)
    for rank, items in sorted(weighted_keys.items()):
        kem = backend.gt_mul(kem, backend.pair(
            _add_many(backend, items), ct.g2_sprime[rank - 1]))
    kem = backend.gt_div(kem, backend.pair(_add_many(backend, weighted_ct),
                                         key.g2_r))
    return backend.gt_div(ct.masked, kem)
