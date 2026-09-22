'''
Control-variable IPE-style outsourced CP-ABE skeleton based on /home/jinji_o/ABE-Test/IPE-Compare.md.

| Notes: Minimal runnable implementation for the current FABEO-style repository.
| Notes: Keeps the standard CP-ABE interface used by Benchmark/run_cp_schemes.py
|        and exposes transform/final_decrypt as explicit helper methods.
| Notes: The anonymous IPE layer below is only a structural placeholder for
|        performance comparison. It is not a faithful secure IPE construction.
|
| type:           ciphertext-policy attribute-based encryption
| setting:        Pairing
'''

import hashlib
from itertools import combinations

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc

from ..msp import MSP

debug = False


class IPECPABE(ABEnc):
    def __init__(self, group_obj, dummy_factor=1, ipe_dim=4, verbose=False):
        ABEnc.__init__(self)
        self.name = "IPE CP-ABE"
        self.group = group_obj
        self.dummy_factor = max(1, int(dummy_factor))
        self.ipe_dim = max(1, int(ipe_dim))
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
        a = self._random_nonzero_zr()

        pk = {
            'g1': g1,
            'g2': g2,
            'g1_a': g1 ** a,
            'e_gg_alpha': pair(g1, g2) ** alpha,
            'sig_vk': 'placeholder-verification-key',
            'ipe_dim': self.ipe_dim,
        }

        msk = {
            'alpha': alpha,
            'a': a,
        }

        return pk, msk

    def keygen(self, pk, msk, attr_list):
        """
        Generates a local recovery key and a transform key bundle.
        """

        if debug:
            print('\nKey generation algorithm:\n')

        t = self._random_nonzero_zr()
        z = self._random_nonzero_zr()

        dummy_attr_list = self._make_dummy_attributes(attr_list)
        mixed_attr_list = list(attr_list) + dummy_attr_list

        K_0 = pk['g2'] ** ((msk['alpha'] + (msk['a'] * t)) / z)
        K_1 = pk['g2'] ** (t / z)

        TK = []
        token_map = {}
        for attr in mixed_attr_list:
            token = self._compute_token(attr)
            token_id = self._token_id(token)
            q_attr = self._token_scalar(token)
            K_x = pk['g2'] ** ((q_attr * t) / z)

            # Placeholder: these vectors only model the linear-in-d IPE key size.
            ipe_key = self._build_ipe_key(pk, attr, z)
            ipe_label = self._ipe_label_id(attr)

            TK.append({
                'token_id': token_id,
                'token': token,
                'K_x': K_x,
                'ipe_key': ipe_key,
                'ipe_label': ipe_label,
            })
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

        C = pk['g1'] ** s
        payload_mask = pk['e_gg_alpha'] ** s

        # Placeholder: the design note compares matching mechanisms, while the
        # repository runner expects a GT plaintext round-trip.
        C_msg = msg * payload_mask

        row_components = []
        anonymous_rows = []

        for attr, row in mono_span_prog.items():
            attr_stripped = self.util.strip_index(attr)
            token = self._compute_token(attr_stripped)
            token_id = self._token_id(token)
            q_attr = self._token_scalar(token)
            r_i = self.group.random(ZR)
            lambda_i = self._dot_product(row, share_vector)

            Q_i = pk['g1'] ** q_attr
            C_i1 = (pk['g1_a'] ** lambda_i) / (Q_i ** r_i)
            C_i2 = pk['g1'] ** r_i

            row_components.append({
                'C_1': C_i1,
                'C_2': C_i2,
                'ipe_ct': self._build_ipe_capsule(pk, attr_stripped),
                'token_id': token_id,
            })
            anonymous_rows.append(self._pad_row(row, num_cols))

        cid = self._compute_cid(C, C_msg, anonymous_rows, row_components)

        for index, row_ct in enumerate(row_components):
            row_ct['sigma'] = self._compute_row_tag(cid, index, row_ct['token_id'])
            row_ct['ipe_ct']['tag'] = self._compute_ipe_tag(cid, index, row_ct['ipe_ct']['ipe_label'])

        return {
            'C': C,
            'C_msg': C_msg,
            'A_star': anonymous_rows,
            'rows': row_components,
            'cid': cid,
            'pk_do_sig': pk['sig_vk'],
            'cert_do': 'placeholder-cert',
        }

    def transform(self, pk, ctxt, key):
        """
        Computes the outsourced transform step using per-row IPE tests.
        """

        if debug:
            print('\nTransform algorithm:\n')

        T_0 = pair(ctxt['C'], key['K_0'])
        candidates = []
        ipe_tests = 0

        for tk_entry in key['TK']:
            for row_index, row_ct in enumerate(ctxt['rows']):
                ipe_tests += 1
                if not self._ipe_match(ctxt['cid'], row_index, tk_entry, row_ct):
                    continue

                T_ix = pair(row_ct['C_1'], key['K_1']) * pair(row_ct['C_2'], tk_entry['K_x'])
                candidates.append({
                    'row_index': row_index,
                    'token_id': tk_entry['token_id'],
                    'T': T_ix,
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
                'ipe_tests': ipe_tests,
                'matched_candidates': len(candidates),
            },
        }

    def final_decrypt(self, pk, partial_ctxt, key):
        """
        Filters candidate rows, reconstructs the secret share, and unmasks the message.
        """

        if debug:
            print('\nFinal decryption algorithm:\n')

        valid_rows = {}
        for item in partial_ctxt['candidates']:
            token_id = item['token_id']
            if token_id not in key['Map']:
                continue

            expected_sigma = self._compute_row_tag(partial_ctxt['cid'], item['row_index'], token_id)
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

        denominator = 1
        for row_index, coeff in coeffs.items():
            denominator *= valid_rows[row_index]['T'] ** coeff

        E_blinded = partial_ctxt['T_0'] / denominator
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

    def _compute_token(self, attr):
        return self.group.hash('token::' + str(attr), G1)

    def _token_scalar(self, token):
        digest = hashlib.sha256(self.group.serialize(token)).digest()
        order = self.group.order()
        scalar = int.from_bytes(digest, byteorder='big') % order
        if scalar == 0:
            scalar = 1
        return self.group.init(ZR, scalar)

    def _token_id(self, token):
        return hashlib.sha256(self.group.serialize(token)).hexdigest()

    def _make_dummy_attributes(self, attr_list):
        dummy_attr_list = []
        count = max(1, len(attr_list) * self.dummy_factor)
        for index in range(count):
            dummy_attr_list.append('dummy::{0}'.format(index))
        return dummy_attr_list

    def _build_ipe_key(self, pk, attr, z):
        coords = self._ipe_coords(attr)
        return [pk['g2'] ** (coord / z) for coord in coords]

    def _build_ipe_capsule(self, pk, attr):
        coords = self._ipe_coords(attr)
        return {
            'vector': [pk['g1'] ** coord for coord in coords],
            'ipe_label': self._ipe_label_id(attr),
            'tag': None,
        }

    def _ipe_coords(self, attr):
        coords = []
        for index in range(self.ipe_dim):
            digest = hashlib.sha256(
                ('ipe::{0}::{1}'.format(attr, index)).encode('utf-8')
            ).digest()
            scalar = int.from_bytes(digest, byteorder='big') % self.group.order()
            if scalar == 0:
                scalar = 1
            coords.append(self.group.init(ZR, scalar))
        return coords

    def _ipe_label_id(self, attr):
        return hashlib.sha256(('ipe-label::' + str(attr)).encode('utf-8')).hexdigest()

    def _ipe_match(self, cid, row_index, tk_entry, row_ct):
        # Placeholder: this is not anonymous IPE decryption. It only models the
        # per-(attribute,row) matching cost by doing linear-in-d pairing work
        # before checking the derived hidden label.
        probe = 1
        for index in range(self.ipe_dim):
            probe *= pair(row_ct['ipe_ct']['vector'][index], tk_entry['ipe_key'][index])

        # The probe is intentionally unused except for forcing the above work.
        if probe == 0:
            return False

        expected_tag = self._compute_ipe_tag(cid, row_index, tk_entry['ipe_label'])
        return row_ct['ipe_ct']['tag'] == expected_tag

    def _compute_ipe_tag(self, cid, row_index, ipe_label):
        payload = '{0}|{1}|{2}'.format(cid, row_index, ipe_label)
        return hashlib.sha256(payload.encode('utf-8')).hexdigest()

    def _pad_row(self, row, width):
        return list(row) + [0] * (width - len(row))

    def _dot_product(self, row, vector):
        total = self.group.init(ZR, 0)
        for index, value in enumerate(row):
            total += value * vector[index]
        return total

    def _compute_cid(self, C, C_msg, anonymous_rows, row_components):
        digest = hashlib.sha256()
        digest.update(self.group.serialize(C))
        digest.update(self.group.serialize(C_msg))
        digest.update(repr(anonymous_rows).encode('utf-8'))

        # Only hash stable metadata here so cid can later bind the IPE tag.
        stable_rows = []
        for row_ct in row_components:
            stable_rows.append({
                'token_id': row_ct['token_id'],
                'ipe_label': row_ct['ipe_ct']['ipe_label'],
            })
        digest.update(repr(stable_rows).encode('utf-8'))
        return digest.hexdigest()

    def _compute_row_tag(self, cid, row_index, token_id):
        payload = '{0}|{1}|{2}'.format(cid, row_index, token_id)
        return hashlib.sha256(payload.encode('utf-8')).hexdigest()

    def _find_reconstruction_coefficients(self, anonymous_rows, row_indices):
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
