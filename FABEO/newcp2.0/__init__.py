'''
FABEO-inspired outsourced CP-ABE upgrade based on /home/jinji_o/ABE-Test/FABEO.md.

| Notes: Keeps the repository's CP-ABE interface and the outsourced
|        transform/final_decrypt flow used by mynewcp.
| Notes: Applies the main engineering ideas from FABEO.md: attributes and
|        row-sized terms are kept in G1, while only constant-size public
|        ciphertext/key terms live in G2.
| Notes: The anonymous token layer, ABF encoding, and row authentication tags
|        are structural placeholders. They are NOT cryptographically verified
|        OPRF/ABF/signature implementations.
|
| type:           ciphertext-policy attribute-based encryption
| setting:        Pairing
'''

import hashlib
from itertools import combinations

from charm.toolbox.pairinggroup import ZR, G1, G2, pair
from charm.toolbox.ABEnc import ABEnc

from ..msp import MSP

debug = False


class NewCP20CPABE(ABEnc):
    def __init__(self, group_obj, dummy_factor=1, verbose=False):
        ABEnc.__init__(self)
        self.name = "NewCP2.0 CP-ABE"
        self.group = group_obj
        self.dummy_factor = max(1, int(dummy_factor))
        self.util = MSP(self.group, verbose)

    def setup(self):
        """
        Generates public parameters and a master secret key.
        """

        if debug:
            print('\nSetup algorithm:\n')

        g1 = self.group.random(G1)
        g2 = self.group.random(G2)
        alpha = self._random_nonzero_zr()

        pk = {
            'g1': g1,
            'g2': g2,
            'e_g1g2_alpha': pair(g1, g2) ** alpha,
            'sig_vk': 'placeholder-verification-key',
        }

        msk = {
            'alpha': alpha,
        }

        return pk, msk

    def keygen(self, pk, msk, attr_list):
        """
        Generates a blinded transform key and a local recovery key.
        """

        if debug:
            print('\nKey generation algorithm:\n')

        r = self._random_nonzero_zr()
        z = self._random_nonzero_zr()
        b_hash = self._base_hash()

        dummy_attr_list = self._make_dummy_attributes(attr_list)
        mixed_attr_list = list(attr_list) + dummy_attr_list

        # FABEO-style placement: the linearly growing attribute components are
        # G1 elements. Only this constant-size blinded randomizer is in G2.
        K_0 = (pk['g1'] ** msk['alpha'] * (b_hash ** r)) ** (1 / z)
        K_1 = pk['g2'] ** (r / z)

        TK = []
        token_map = {}
        for attr in mixed_attr_list:
            token = self._compute_token(attr)
            token_id = self._token_id(token)
            K_x = self._row_hash(token) ** (r / z)

            TK.append({'token_id': token_id, 'token': token, 'K_x': K_x})
            if attr in attr_list:
                token_map[token_id] = attr

        return {
            'attr_list': list(attr_list),
            'dummy_attr_list': dummy_attr_list,
            'mixed_attr_list': mixed_attr_list,
            'RK': z,
            'Map': token_map,
            'K_0': K_0,
            'K_1': K_1,
            'TK': TK,
        }

    def encrypt(self, pk, msg, policy_str):
        """
        Encrypts a GT message under a policy string.
        """

        if debug:
            print('\nEncryption algorithm:\n')

        policy = self.util.createPolicy(policy_str)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row

        share_vector = [self._random_nonzero_zr()]
        for _ in range(num_cols - 1):
            share_vector.append(self.group.random(ZR))
        s = share_vector[0]
        sprime = self._random_nonzero_zr()

        g2_s1 = pk['g2'] ** s
        g2_sprime = pk['g2'] ** sprime
        C_msg = msg * (pk['e_g1g2_alpha'] ** s)

        b_hash = self._base_hash()
        rows = []
        anonymous_rows = []
        token_rows = {}
        row_token_ids = []

        for index, (attr, row) in enumerate(mono_span_prog.items()):
            attr_stripped = self.util.strip_index(attr)
            token = self._compute_token(attr_stripped)
            token_id = self._token_id(token)
            lambda_i = self._dot_product(row, share_vector)

            # This is the FABEO-shaped row term:
            #   B^lambda_i * H(token)^sprime in G1.
            # The token is currently deterministic and public, which is a
            # placeholder for the OPRF-based tokenization described in FABEO.md.
            C_1 = (b_hash ** lambda_i) * (self._row_hash(token) ** sprime)

            rows.append({'C_1': C_1})
            anonymous_rows.append(self._pad_row(row, num_cols))
            row_token_ids.append(token_id)
            token_rows.setdefault(token_id, []).append(index)

        abf = self._build_abf(token_rows, len(anonymous_rows))
        cid = self._compute_cid(g2_s1, g2_sprime, C_msg, anonymous_rows, abf)

        for index, token_id in enumerate(row_token_ids):
            rows[index]['sigma'] = self._compute_row_tag(cid, index, token_id)

        return {
            'g2_s1': g2_s1,
            'g2_sprime': g2_sprime,
            'C_msg': C_msg,
            'A_star': anonymous_rows,
            'rows': rows,
            'abf': abf,
            'cid': cid,
            'pk_do_sig': pk['sig_vk'],
            'cert_do': 'placeholder-cert',
        }

    def transform(self, pk, ctxt, key):
        """
        Computes the outsourced transform step using the transform key portion.
        """

        if debug:
            print('\nTransform algorithm:\n')

        T_0 = pair(key['K_0'], ctxt['g2_s1'])
        candidates = []
        abf_queries = 0

        for tk_entry in key['TK']:
            abf_queries += 1
            candidate_rows = self._query_abf(ctxt['abf'], tk_entry['token'])
            if not candidate_rows:
                continue

            for row_index in candidate_rows:
                row_ct = ctxt['rows'][row_index]
                numerator = pair(tk_entry['K_x'], ctxt['g2_sprime'])
                denominator = pair(row_ct['C_1'], key['K_1'])
                candidates.append({
                    'row_index': row_index,
                    'token_id': tk_entry['token_id'],
                    'T': numerator / denominator,
                    'sigma': row_ct['sigma'],
                })

        return {
            'T_0': T_0,
            'A_star': ctxt['A_star'],
            'C_msg': ctxt['C_msg'],
            'cid': ctxt['cid'],
            'pk_do_sig': ctxt['pk_do_sig'],
            'cert_do': ctxt['cert_do'],
            'candidates': candidates,
            'stats': {
                'abf_queries': abf_queries,
                'matched_candidates': len(candidates),
            },
        }

    def final_decrypt(self, pk, partial_ctxt, key):
        """
        Filters candidate rows, reconstructs the shared secret, and unmasks msg.
        """

        if debug:
            print('\nFinal decryption algorithm:\n')

        valid_rows = {}
        for item in partial_ctxt['candidates']:
            token_id = item['token_id']
            if token_id not in key['Map']:
                continue

            expected_sigma = self._compute_row_tag(
                partial_ctxt['cid'],
                item['row_index'],
                token_id,
            )
            if item['sigma'] != expected_sigma:
                continue

            valid_rows[item['row_index']] = item

        if not valid_rows:
            print("Policy not satisfied.")
            return None

        row_indices = sorted(valid_rows.keys())
        coeffs = self._find_reconstruction_coefficients(partial_ctxt['A_star'], row_indices)
        if coeffs is None:
            print("Policy not satisfied.")
            return None

        E_blinded = partial_ctxt['T_0']
        for row_index, coeff in coeffs.items():
            E_blinded *= valid_rows[row_index]['T'] ** coeff

        E = E_blinded ** key['RK']
        return partial_ctxt['C_msg'] / E

    def decrypt(self, pk, ctxt, key):
        """
        Compatibility wrapper for the repository's four-step CP-ABE interface.
        """

        if debug:
            print('\nDecryption algorithm:\n')

        partial_ctxt = self.transform(pk, ctxt, key)
        return self.final_decrypt(pk, partial_ctxt, key)

    def _random_nonzero_zr(self):
        value = self.group.random(ZR)
        while value == 0:
            value = self.group.random(ZR)
        return value

    def _base_hash(self):
        return self.group.hash('newcp20::base', G1)

    def _compute_token(self, attr):
        # PLACEHOLDER/UNVERIFIED: FABEO.md calls for blinded OPRF tokenization.
        # This deterministic public token keeps the runner-compatible flow but
        # does not provide full cryptographic attribute hiding.
        return self.group.hash('newcp20::token::' + str(attr), G1)

    def _row_hash(self, token):
        return self.group.hash('newcp20::row::' + self._token_id(token), G1)

    def _token_id(self, token):
        return hashlib.sha256(self.group.serialize(token)).hexdigest()

    def _make_dummy_attributes(self, attr_list):
        dummy_attr_list = []
        count = max(1, len(attr_list) * self.dummy_factor)
        for index in range(count):
            dummy_attr_list.append('dummy::{0}'.format(index))
        return dummy_attr_list

    def _pad_row(self, row, width):
        return list(row) + [0] * (width - len(row))

    def _dot_product(self, row, vector):
        total = self.group.init(ZR, 0)
        for index, value in enumerate(row):
            total += value * vector[index]
        return total

    def _build_abf(self, token_rows, row_count):
        # PLACEHOLDER/UNVERIFIED: this is a direct token_id -> bitmap map, not a
        # real XOR-shared Garbled Bloom Filter / ABF construction.
        entries = {}
        for token_id, rows in token_rows.items():
            bitmap = [0] * row_count
            for row_index in rows:
                bitmap[row_index] = 1

            entries[token_id] = {
                'bitmap': bitmap,
                'check': self._check_tag(token_id),
            }

        return {'entries': entries}

    def _query_abf(self, abf, token):
        token_id = self._token_id(token)
        entry = abf['entries'].get(token_id)
        if entry is None:
            return []

        if entry['check'] != self._check_tag(token_id):
            return []

        rows = []
        for row_index, bit in enumerate(entry['bitmap']):
            if bit == 1:
                rows.append(row_index)
        return rows

    def _check_tag(self, token_id):
        return hashlib.sha256(('newcp20::chk::' + token_id).encode('utf-8')).hexdigest()

    def _compute_cid(self, g2_s1, g2_sprime, C_msg, anonymous_rows, abf):
        digest = hashlib.sha256()
        digest.update(self.group.serialize(g2_s1))
        digest.update(self.group.serialize(g2_sprime))
        digest.update(self.group.serialize(C_msg))
        digest.update(repr(anonymous_rows).encode('utf-8'))
        digest.update(repr(abf).encode('utf-8'))
        return digest.hexdigest()

    def _compute_row_tag(self, cid, row_index, token_id):
        # PLACEHOLDER/UNVERIFIED: this public hash is only a runner-friendly
        # substitute for the DO signature in the design note.
        payload = '{0}|{1}|{2}'.format(cid, row_index, token_id)
        return hashlib.sha256(payload.encode('utf-8')).hexdigest()

    def _find_reconstruction_coefficients(self, anonymous_rows, row_indices):
        if not anonymous_rows:
            return None

        width = len(anonymous_rows[0])
        modulus = self.group.order()

        for size in range(1, len(row_indices) + 1):
            for subset in combinations(row_indices, size):
                chosen_rows = [anonymous_rows[index] for index in subset]
                coeffs = self._solve_subset(chosen_rows, width, modulus)
                if coeffs is None:
                    continue

                result = {}
                for position, row_index in enumerate(subset):
                    result[row_index] = self.group.init(ZR, coeffs[position] % modulus)
                return result

        return None

    def _solve_subset(self, rows, width, modulus):
        column_count = len(rows)
        target = [0] * width
        target[0] = 1

        matrix = []
        for row_index in range(width):
            equation = []
            for column in range(column_count):
                equation.append(rows[column][row_index] % modulus)
            equation.append(target[row_index] % modulus)
            matrix.append(equation)

        pivot_row = 0
        pivot_cols = []
        for col in range(column_count):
            pivot = None
            for row in range(pivot_row, width):
                if matrix[row][col] % modulus != 0:
                    pivot = row
                    break

            if pivot is None:
                continue

            matrix[pivot_row], matrix[pivot] = matrix[pivot], matrix[pivot_row]
            inv = pow(matrix[pivot_row][col] % modulus, -1, modulus)
            for j in range(col, column_count + 1):
                matrix[pivot_row][j] = (matrix[pivot_row][j] * inv) % modulus

            for row in range(width):
                if row == pivot_row:
                    continue
                factor = matrix[row][col] % modulus
                if factor == 0:
                    continue
                for j in range(col, column_count + 1):
                    matrix[row][j] = (matrix[row][j] - factor * matrix[pivot_row][j]) % modulus

            pivot_cols.append(col)
            pivot_row += 1
            if pivot_row == width:
                break

        for row in range(width):
            if all(matrix[row][col] % modulus == 0 for col in range(column_count)):
                if matrix[row][column_count] % modulus != 0:
                    return None

        solution = [0] * column_count
        for row, col in enumerate(pivot_cols):
            solution[col] = matrix[row][column_count] % modulus
        return solution


__all__ = ['NewCP20CPABE']
