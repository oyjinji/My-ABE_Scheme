"""Structural workload generation; seed never reaches a cryptographic RNG."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

from ..types import Attribute, PolicyInput
from . import GENERATOR_VERSION


FAMILIES = {
    'W-SINGLE': ('single', ((1,),), (1,), (1,)),
    'W-OR': ('OR', ((1,), (1,)), (1, 2), (1, 2)),
    'W-AND': ('AND', ((1, 1), (0, -1)), (1, 2), (1, 2)),
    'W-2OF3': ('threshold', ((1, 1), (1, 2), (1, 3)), (1, 2, 3), (1, 2, 3)),
    'W-3OF5': ('threshold', ((1, 1, 1), (1, 2, 4), (1, 3, 9),
                           (1, 4, 16), (1, 5, 25)), (1, 2, 3, 4, 5), (1, 2, 3, 4, 5)),
    'W-REPEAT-ABACA': ('repeated', ((0, 0), (0, 0), (1, 1), (0, 0), (0, -1)),
                       (1, 2, 1, 3, 1), (1, 2, 3)),
}
OUTCOMES = ('SUCCESS', 'UNAUTHORIZED', 'REVOKED', 'STATE_UNAVAILABLE')


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def sha256_json(value):
    return hashlib.sha256(canonical_json(value)).hexdigest()


def occurrence_ranks(codes):
    seen = {}
    result = []
    for code in codes:
        seen[code] = seen.get(code, 0) + 1
        result.append(seen[code])
    return tuple(result)


@dataclass(frozen=True)
class WorkloadSpec:
    workload_id: str
    family: str
    workload_seed: int
    policy_shape: str
    matrix: tuple
    row_codes: tuple
    user_codes: tuple
    cmax: int
    message_length: int
    expected_outcome: str
    requested: dict
    occurrence_ranks: tuple
    workload_spec_sha256: str

    @property
    def ell(self): return len(self.matrix)

    @property
    def d(self): return len(self.matrix[0])

    @property
    def u(self): return len(set(self.row_codes))

    @property
    def N(self): return len(self.user_codes)

    def artifact(self):
        # Numeric structural IDs only; plaintext synthetic labels stay in memory.
        return dict(generator_version=GENERATOR_VERSION,
            workload_id=self.workload_id, family=self.family,
            workload_seed=self.workload_seed, policy_shape=self.policy_shape,
            matrix=self.matrix, row_codes=self.row_codes,
            user_codes=self.user_codes, cmax=self.cmax,
            message_length=self.message_length, expected_outcome=self.expected_outcome,
            requested=self.requested, occurrence_ranks=self.occurrence_ranks,
            ell=self.ell, d=self.d, u=self.u, N=self.N,
            workload_spec_sha256=self.workload_spec_sha256)

    def attribute(self, code):
        digest = hashlib.sha256(canonical_json((GENERATOR_VERSION,
            self.workload_seed, self.family, code))).hexdigest()[:24]
        return Attribute('synthetic', 'attribute', 'SYN-' + digest)

    def policy(self):
        return PolicyInput(self.matrix, tuple(self.attribute(x) for x in self.row_codes))

    def user_attributes(self):
        return tuple(sorted(self.attribute(x) for x in self.user_codes))


def generate_workload(family: str, seed: int, *, cmax: int = 3,
                      N: int | None = None, expected_outcome: str = 'SUCCESS',
                      message_length: int = 32, requested: dict | None = None) -> WorkloadSpec:
    if family not in FAMILIES or type(seed) is not int or seed < 0:
        raise ValueError('known family and nonnegative workload seed required')
    if expected_outcome not in OUTCOMES or type(message_length) is not int or message_length < 1:
        raise ValueError('unsupported workload outcome/message length')
    shape, matrix, row_codes, default_user = FAMILIES[family]
    ranks = occurrence_ranks(row_codes)
    if type(cmax) is not int or cmax < max(ranks):
        raise ValueError('occurrence rank exceeds cmax; no automatic increase')
    if expected_outcome == 'UNAUTHORIZED':
        user_codes = (max(row_codes) + 1,)
    else:
        user_codes = default_user
    if N is not None:
        if type(N) is not int or N < len(user_codes):
            raise ValueError('N cannot remove required structural attributes')
        user_codes = user_codes + tuple(range(max(row_codes) + 10,
                                            max(row_codes) + 10 + N - len(user_codes)))
    requested = dict(requested or {})
    actual = {'ell': len(matrix), 'd': len(matrix[0]),
              'u': len(set(row_codes)), 'N': len(user_codes), 'cmax': cmax}
    for key, value in requested.items():
        if key in actual and value != actual[key]:
            raise ValueError('requested structural variable is incompatible with family: ' + key)
    structural = dict(generator_version=GENERATOR_VERSION, family=family, seed=seed,
        matrix=matrix, row_codes=row_codes, user_codes=user_codes, cmax=cmax,
        message_length=message_length, expected_outcome=expected_outcome,
        requested=requested, occurrence_ranks=ranks)
    digest = sha256_json(structural)
    if family == 'W-REPEAT-ABACA' and ranks != (1, 1, 2, 1, 3):
        raise AssertionError('frozen ABACA occurrence ranks changed')
    return WorkloadSpec('WL-' + digest[:16], family, seed, shape, matrix,
                        row_codes, user_codes, cmax, message_length,
                        expected_outcome, requested, ranks, digest)


def generate_benchmark_workload(*, shape: str, ell: int, cmax: int,
                                N: int, hit_codes: int, seed: int,
                                threshold: int = 2,
                                requested: dict | None = None) -> WorkloadSpec:
    """Construct a real public-policy workload; seed affects labels only.

    Repeated row codes are grouped in complete-row order.  The matrix is an
    OR, a genuine two-row AND, or a Vandermonde threshold policy; no ABE
    formula is implemented in the experiment harness.
    """
    if (shape not in ('OR', 'AND', 'threshold', 'repeated') or
        any(type(x) is not int for x in (ell,cmax,N,hit_codes,seed,threshold)) or
        ell < 2 or cmax < 1 or N < 1 or hit_codes < 1 or seed < 0 or
        threshold < 1 or threshold > ell):
        raise ValueError('invalid benchmark structure')
    if shape == 'AND':
        if ell != 2 or cmax != 1 or threshold != 2:
            raise ValueError('AND benchmark is exactly two essential rows')
        row_codes = (1,2)
        matrix = ((1,1),(0,-1))
    else:
        row_codes = tuple(1 + i // cmax for i in range(ell))
        if shape == 'OR':
            matrix = tuple((1,) for _ in range(ell))
        else:
            matrix = tuple(tuple(i**power for power in range(threshold))
                           for i in range(1,ell+1))
    u = len(set(row_codes))
    if hit_codes > u or N < hit_codes:
        raise ValueError('candidate hit count exceeds policy or user batch')
    user_codes = tuple(range(1,hit_codes+1)) + tuple(range(u+1,u+1+N-hit_codes))
    ranks = occurrence_ranks(row_codes)
    actual_cmax = max(ranks)
    if actual_cmax != cmax:
        raise ValueError('unrealizable requested cmax')
    # Require a sufficient candidate span for a successful correctness gate.
    if shape == 'AND' and hit_codes != 2:
        raise ValueError('AND requires both attributes')
    if shape in ('threshold','repeated') and hit_codes*cmax < threshold:
        raise ValueError('threshold cannot be met by selected hits')
    requested = dict(requested or {})
    structural = dict(generator_version=GENERATOR_VERSION,
        family='B-'+shape,seed=seed,matrix=matrix,row_codes=row_codes,
        user_codes=user_codes,cmax=cmax,message_length=32,
        expected_outcome='SUCCESS',requested=requested,
        occurrence_ranks=ranks)
    digest=sha256_json(structural)
    return WorkloadSpec('WL-'+digest[:16], 'B-'+shape, seed, shape,
        matrix,row_codes,user_codes,cmax,32,'SUCCESS',requested,ranks,digest)
