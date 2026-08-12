"""LSSS policy conversion and reconstruction over Charm ZR."""

from charm.toolbox.pairinggroup import ZR

from ..msp import MSP


def policy_rows(group, policy):
    if isinstance(policy, dict):
        matrix = policy.get("matrix", policy.get("A"))
        rho = policy.get("rho")
        if not matrix or not isinstance(rho, list) or len(matrix) != len(rho):
            raise ValueError("matrix policy requires equally sized matrix/A and rho")
        rows = [[int(x) for x in row] for row in matrix]
        if not all(rows):
            raise ValueError("empty LSSS row")
        return rows, list(rho)
    util = MSP(group, False)
    tree = util.createPolicy(policy)
    msp = util.convert_policy_to_msp(tree)
    return ([list(map(int, row)) for row in msp.values()],
            [util.strip_index(label) for label in msp])


def pad_matrix(matrix):
    width = max(map(len, matrix))
    return [row + [0] * (width - len(row)) for row in matrix]


def solve_reconstruction(group, matrix, row_ids):
    if not row_ids:
        return None
    matrix = pad_matrix(matrix)
    selected = [matrix[row - 1] for row in row_ids]
    width, variables = len(matrix[0]), len(row_ids)
    eqs = [[group.init(ZR, selected[v][c]) for v in range(variables)] +
           [group.init(ZR, int(c == 0))] for c in range(width)]
    pivot_row, pivots = 0, {}
    for col in range(variables):
        candidate = next((r for r in range(pivot_row, width) if eqs[r][col] != 0), None)
        if candidate is None:
            continue
        eqs[pivot_row], eqs[candidate] = eqs[candidate], eqs[pivot_row]
        inv = 1 / eqs[pivot_row][col]
        eqs[pivot_row] = [x * inv for x in eqs[pivot_row]]
        for r in range(width):
            if r == pivot_row or eqs[r][col] == 0:
                continue
            factor = eqs[r][col]
            eqs[r] = [x - factor*y for x, y in zip(eqs[r], eqs[pivot_row])]
        pivots[col] = pivot_row
        pivot_row += 1
        if pivot_row == width:
            break
    if any(all(x == 0 for x in row[:variables]) and row[-1] != 0 for row in eqs):
        return None
    coeffs = [group.init(ZR, 0) for _ in range(variables)]
    for col, row in pivots.items():
        coeffs[col] = eqs[row][-1]
    result = {row_id: coeff for row_id, coeff in zip(row_ids, coeffs) if coeff != 0}
    return result or None
