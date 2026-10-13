"""Pure structural policy preparation and deterministic field reconstruction.

Full PolicyEncode retains its authenticated DO/TEE boundary and is unavailable.
External policy row numbers are always 1-based. No pairing occurs here.
"""
from dataclasses import dataclass
from typing import Tuple

from .credential import DOSession
from .encoding import require_bytes, require_uint
from .errors import ContractError, Unauthorized, UnsupportedPolicy, unimplemented
from .types import (AuthorizedSubsetResult, OccurrenceWitness, PolicyContext,
                    PolicyEncoding, PolicyInput, PublicParameters, ReconstructionTerm,
                    TokenRows)


@dataclass(frozen=True)
class LSSSMatrix:
    rows: Tuple[Tuple[int, ...], ...]
    field_order: int
    ell: int
    d: int
    row_numbering: str = '1-based'

    def __post_init__(self):
        if type(self.rows) is not tuple or not self.rows or any(type(r) is not tuple for r in self.rows):
            raise ContractError('nonempty tuple of tuple matrix required')
        if type(self.field_order) is not int or self.field_order < 3:
            raise ContractError('field order required')
        if type(self.ell) is not int or type(self.d) is not int or self.ell != len(self.rows) or self.ell > 0xffffffff or self.d < 1 or self.d > 0xffffffff:
            raise ContractError('matrix shape mismatch')
        if self.row_numbering != '1-based':
            raise ContractError('external rows must be 1-based')
        for row in self.rows:
            if len(row) != self.d or any(type(x) is not int for x in row):
                raise ContractError('rectangular integer matrix required')


def policy_encode(pp: PublicParameters, policy: PolicyInput,
                  context: PolicyContext, *, do_session: DOSession) -> PolicyEncoding:
    unimplemented('PolicyEncode')


def assign_occurrence_ranks(tokens, c_max):
    require_uint(c_max, 32, 'c_max')
    if c_max == 0 or type(tokens) not in (tuple, list) or not tokens:
        raise ContractError('nonempty tokens and positive c_max required')
    counts, ranks = {}, []
    for token in tokens:
        require_bytes(token, 'token', 32)
        rank = counts.get(token, 0) + 1
        if rank > c_max:
            raise UnsupportedPolicy('occurrence count exceeds c_max')
        counts[token] = rank
        ranks.append(rank)
    return tuple(ranks)


def prepare_policy_rows(matrix: LSSSMatrix, tokens, c_max):
    """Pure row grouping, with no DO authorization or TEE tokenization."""
    if type(matrix) is not LSSSMatrix or type(tokens) not in (tuple, list) or len(tokens) != matrix.ell:
        raise ContractError('complete policy tokens must match matrix rows')
    ranks = assign_occurrence_ranks(tokens, c_max)
    groups = {}
    for row, token in enumerate(tokens, 1):
        groups.setdefault(token, []).append(row)
    return tuple(TokenRows(token, tuple(rows)) for token, rows in sorted(groups.items())), ranks


def merge_af_hits(hits):
    """Recover J and phi from complete hit lists; phi rank never renumbered."""
    if type(hits) not in (tuple, list):
        raise ContractError('ordered hits required')
    phi = {}
    for item in hits:
        if type(item) is not tuple or len(item) != 2:
            raise ContractError('hit must be (token, complete rows)')
        token, rows = item
        require_bytes(token, 'token', 32)
        if type(rows) not in (tuple, list) or not rows:
            raise ContractError('complete nonempty row list required')
        last = 0
        for rank, row in enumerate(rows, 1):
            require_uint(row, 32, 'row')
            if row <= last:
                raise ContractError('hit rows must be strictly increasing')
            if row in phi and phi[row].token != token:
                raise ContractError('conflicting token ownership for row')
            if row in phi:
                raise ContractError('duplicate hit')
            phi[row] = OccurrenceWitness(row, token, rank)
            last = row
    return tuple(sorted(phi)), tuple(phi[row] for row in sorted(phi))


def _validate_candidates(matrix, candidate_rows):
    if type(candidate_rows) not in (tuple, list):
        raise ContractError('candidate rows must be ordered sequence')
    for row in candidate_rows:
        require_uint(row, 32, 'row')
        if row < 1 or row > matrix.ell:
            raise ContractError('candidate row out of range')
    if len(candidate_rows) != len(set(candidate_rows)):
        raise ContractError('duplicate candidate row')
    return tuple(sorted(candidate_rows))


def authorized_subset(matrix: LSSSMatrix, candidate_rows, backend, *,
                      witnesses=()) -> AuthorizedSubsetResult:
    """Fixed row order Gaussian elimination; free variables set to zero.

    Returns one feasible nonzero reconstruction. No minimum support or slot
    optimum is claimed. Backend validates the BLS scalar/profile binding.
    """
    from .crypto import BLS12381Backend
    if type(backend) is not BLS12381Backend or type(matrix) is not LSSSMatrix or matrix.field_order != backend.scalar_order:
        raise ContractError('matrix/backend field mismatch')
    ordered = _validate_candidates(matrix, candidate_rows)
    if not ordered:
        raise Unauthorized('empty candidate span')
    if type(witnesses) not in (tuple, list):
        raise ContractError('witnesses must be ordered sequence')
    witness_by_row = {}
    for witness in witnesses:
        if type(witness) is not OccurrenceWitness or witness.row in witness_by_row:
            raise ContractError('invalid or duplicate witness')
        require_bytes(witness.token, 'token', 32)
        require_uint(witness.occurrence_rank, 32, 'occurrence rank')
        if witness.occurrence_rank < 1:
            raise ContractError('occurrence rank must be positive')
        witness_by_row[witness.row] = witness
    if witnesses and set(witness_by_row) != set(ordered):
        raise ContractError('witness rows must exactly match J')
    modulus = matrix.field_order
    n = len(ordered)
    equations = [[matrix.rows[row-1][coord] % modulus for row in ordered] +
                 [1 if coord == 0 else 0] for coord in range(matrix.d)]
    pivot_row = 0
    pivots = []
    for col in range(n):
        chosen = next((r for r in range(pivot_row, matrix.d)
                       if equations[r][col] != 0), None)
        if chosen is None:
            continue
        equations[pivot_row], equations[chosen] = equations[chosen], equations[pivot_row]
        inv = pow(equations[pivot_row][col], -1, modulus)
        equations[pivot_row] = [(x*inv) % modulus for x in equations[pivot_row]]
        for row in range(matrix.d):
            if row == pivot_row or equations[row][col] == 0:
                continue
            factor = equations[row][col]
            equations[row] = [(x-factor*y) % modulus
                              for x, y in zip(equations[row], equations[pivot_row])]
        pivots.append((col, pivot_row))
        pivot_row += 1
        if pivot_row == matrix.d:
            break
    if any(all(value == 0 for value in row[:n]) and row[n] != 0
           for row in equations):
        raise Unauthorized('e1 outside candidate span')
    coeffs = [0]*n
    for col, row in pivots:
        coeffs[col] = equations[row][n]
    # Canonical scalar serialization, rather than Python truthiness, defines zero.
    zero = backend.serialize_scalar(backend.scalar_from_int(0))
    terms = tuple(ReconstructionTerm(row, backend.scalar_from_int(coeff))
                  for row, coeff in zip(ordered, coeffs)
                  if backend.serialize_scalar(backend.scalar_from_int(coeff)) != zero)
    if not terms or any(row not in ordered for row in (term.row for term in terms)):
        raise Unauthorized('empty or out-of-set reconstruction')
    # Independent direct linear combination check after zero cleanup.
    lhs = tuple(sum(int.from_bytes(backend.serialize_scalar(term.coefficient), 'big') *
                    matrix.rows[term.row-1][col] for term in terms) % modulus
                for col in range(matrix.d))
    if lhs != (1,) + (0,)*(matrix.d-1):
        raise ContractError('reconstruction verification failed')
    slots = tuple(sorted({witness_by_row[term.row].occurrence_rank for term in terms})) if witnesses else ()
    if witnesses and not 1 <= len(slots) <= min(len(terms), max(w.occurrence_rank for w in witnesses)):
        raise ContractError('invalid occurrence slot count')
    return AuthorizedSubsetResult(terms, slots)
