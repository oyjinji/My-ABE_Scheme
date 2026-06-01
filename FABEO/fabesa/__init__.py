'''
FABESA anonymous CP-A2BE-style CP-ABE based on /home/jinji_o/ABE-Test/a_fabesa_cp.md.

| Notes: Implements the Type-III pairing flow from FABESA_cp.md and the
|        partially hidden structure from a_fabesa_cp.md: payload exposes the
|        MSP rows and attribute names, while attribute values only appear inside
|        cryptographic group components.
| Notes: Keeps the standard CP-ABE interface used by samples/run_cp_schemes.py.
| Notes: The candidate-message verification tag below is a runner-friendly
|        placeholder so value mismatches can be rejected during blind trials.
|        It is NOT a verified authenticated encryption/KEM construction.
|
| type:           ciphertext-policy anonymous attribute-based encryption
| setting:        Pairing
'''

import hashlib
import re
from itertools import combinations, product

from charm.toolbox.pairinggroup import ZR, G1, G2, pair
from charm.toolbox.ABEnc import ABEnc

from ..msp import MSP

debug = False


class FABESACPABE(ABEnc):
    def __init__(self, group_obj, verbose=False):
        ABEnc.__init__(self)
        self.name = "FABESA CP-A2BE"
        self.group = group_obj
        self.util = MSP(self.group, verbose)

    def setup(self):
        """
        Generates public key and master secret key.
        """

        if debug:
            print('\nSetup algorithm:\n')

        g1 = self.group.random(G1)
        g2 = self.group.random(G2)
        g3 = self.group.random(G1)

        alpha = self._random_nonzero_zr()
        b1 = self._random_nonzero_zr()
        b2 = self._random_nonzero_zr()

        pk = {
            'g1': g1,
            'g2': g2,
            'g3': g3,
            'g2_b1': g2 ** b1,
            'g2_b2': g2 ** b2,
            'e_g1g2_alpha': pair(g1, g2) ** alpha,
        }
        msk = {'alpha': alpha, 'b1': b1, 'b2': b2}

        return pk, msk

    def keygen(self, pk, msk, attr_list):
        """
        Generate a key for a list of name/value attributes.
        """

        if debug:
            print('\nKey generation algorithm:\n')

        r = self._random_nonzero_zr()

        sk1 = pk['g2'] ** r
        sk2 = (pk['g1'] ** msk['alpha']) * (pk['g3'] ** (-r))

        entries = {}
        public_names = []
        for attr in attr_list:
            attr_name, attr_value = self._split_attribute(attr)
            public_names.append(attr_name)
            entry = {
                'attr': attr,
                'name': attr_name,
                # The value is not exposed by ciphertext payloads. It remains in
                # the user's secret key and in these randomized hash components.
                'sk3': self._hash_attr('0', attr_value) ** (r / msk['b1']),
                'sk4': self._hash_attr('1', attr_value) ** (r / msk['b2']),
            }
            entries.setdefault(attr_name, []).append(entry)

        return {
            'attr_list': list(attr_list),
            'public_names': public_names,
            'sk1': sk1,
            'sk2': sk2,
            'entries': entries,
        }

    def encrypt(self, pk, msg, policy_str):
        """
        Encrypt a message msg under a partially hidden policy string.
        """

        if debug:
            print('\nEncryption algorithm:\n')

        policy_input, attr_map = self._prepare_policy(policy_str)
        policy = self.util.createPolicy(policy_input)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row

        s1 = self._random_nonzero_zr()
        s2 = self._random_nonzero_zr()
        s = s1 + s2

        v = [s]
        for _ in range(num_cols - 1):
            v.append(self.group.random(ZR))

        ct1 = []
        rows = []
        for row_index, (attr, row) in enumerate(mono_span_prog.items()):
            attr_stripped = self.util.strip_index(attr)
            attr_plain = attr_map.get(attr_stripped, attr_stripped)
            attr_name, attr_value = self._split_attribute(attr_plain)
            share = self._dot_product(row, v)

            ct1.append(
                (pk['g3'] ** share)
                * (self._hash_attr('0', attr_value) ** s1)
                * (self._hash_attr('1', attr_value) ** s2)
            )
            rows.append({
                'row_index': row_index,
                'name': attr_name,
                'row': self._pad_row(row, num_cols),
            })

        ct2 = pk['g2'] ** s
        ct3 = pk['g2_b1'] ** s1
        ct4 = pk['g2_b2'] ** s2
        ct5 = (pk['e_g1g2_alpha'] ** s) * msg

        return {
            'payload': {
                'rows': rows,
                'public_names': [item['name'] for item in rows],
                'len_longest_row': num_cols,
            },
            'ct1': ct1,
            'ct2': ct2,
            'ct3': ct3,
            'ct4': ct4,
            'ct5': ct5,
            # PLACEHOLDER/UNVERIFIED: a real anonymous CP-A2BE deployment should
            # wrap a DEM/KEM or AEAD check here. This tag lets the demo reject
            # wrong value candidates without storing the hidden policy values.
            'msg_tag': self._message_tag(msg),
        }

    def match(self, ctxt, key):
        """
        Locate candidate row subsets using only public attribute names.
        """

        if debug:
            print('\nMatch algorithm:\n')

        rows = ctxt['payload']['rows']
        row_indices = []
        name_tests = 0
        public_names = set(key['entries'].keys())

        for row in rows:
            name_tests += len(public_names)
            if row['name'] in public_names:
                row_indices.append(row['row_index'])

        candidates = []
        for size in range(1, len(row_indices) + 1):
            for subset in combinations(row_indices, size):
                chosen_rows = [rows[index]['row'] for index in subset]
                coeffs = self._solve_subset(chosen_rows, ctxt['payload']['len_longest_row'])
                if coeffs is None:
                    continue

                candidates.append({
                    'row_indices': list(subset),
                    'coeffs': {
                        subset[position]: coeffs[position]
                        for position in range(len(subset))
                    },
                })

        return {
            'candidates': candidates,
            'stats': {
                'matched_subsets': len(candidates),
                'matched_attributes': len(row_indices),
                'name_tests': name_tests,
            },
        }

    def decrypt_with_match(self, pk, ctxt, key, match):
        """
        Blindly try name-matched row subsets until hidden values verify.
        """

        if debug:
            print('\nDecryption algorithm:\n')

        if not match or not match['candidates']:
            print("Policy not satisfied.")
            return None

        rows = ctxt['payload']['rows']
        for candidate in match['candidates']:
            entry_choices = []
            for row_index in candidate['row_indices']:
                name = rows[row_index]['name']
                entries = key['entries'].get(name)
                if not entries:
                    entry_choices = []
                    break
                entry_choices.append(entries)

            if not entry_choices:
                continue

            for selected_entries in product(*entry_choices):
                rec_msg = self._decrypt_candidate(ctxt, key, candidate, selected_entries)
                if rec_msg is not None and self._message_tag(rec_msg) == ctxt['msg_tag']:
                    return rec_msg

        print("Policy not satisfied.")
        return None

    def decrypt(self, pk, ctxt, key):
        """
        Compatibility wrapper for the repository's four-step CP-ABE interface.
        """

        match = self.match(ctxt, key)
        return self.decrypt_with_match(pk, ctxt, key, match)

    def _decrypt_candidate(self, ctxt, key, candidate, selected_entries):
        prod_ct1 = 1
        prod_sk3 = 1
        prod_sk4 = 1

        for position, row_index in enumerate(candidate['row_indices']):
            coeff = candidate['coeffs'][row_index]
            entry = selected_entries[position]
            prod_ct1 *= ctxt['ct1'][row_index] ** coeff
            prod_sk3 *= entry['sk3'] ** coeff
            prod_sk4 *= entry['sk4'] ** coeff

        numerator = ctxt['ct5'] * pair(prod_sk3, ctxt['ct3']) * pair(prod_sk4, ctxt['ct4'])
        denominator = pair(prod_ct1, key['sk1']) * pair(key['sk2'], ctxt['ct2'])

        return numerator / denominator

    def _random_nonzero_zr(self):
        value = self.group.random(ZR)
        while value == 0:
            value = self.group.random(ZR)
        return value

    def _hash_attr(self, prefix, attr_value):
        return self.group.hash('fabesa::{0}::{1}'.format(prefix, attr_value), G1)

    def _prepare_policy(self, policy_str):
        attr_map = {}
        attr_index = {'value': 0}
        pattern = re.compile(r'\b[A-Za-z][A-Za-z0-9]*\s*(?:::|==|:|=)\s*[A-Za-z0-9]+\b')

        def replace_attr(match):
            original = match.group(0)
            normalized = re.sub(r'\s+', '', original)
            token = 'FABESA{0}'.format(attr_index['value'])
            attr_index['value'] += 1
            attr_map[token] = normalized
            return token

        return pattern.sub(replace_attr, str(policy_str)), attr_map

    def _split_attribute(self, attr):
        attr = str(attr)
        for sep in ('::', '==', ':', '='):
            if sep in attr:
                parts = attr.split(sep, 1)
                return parts[0].strip(), parts[1].strip()
        return attr, attr

    def _dot_product(self, row, vector):
        total = self.group.init(ZR, 0)
        for index, value in enumerate(row):
            total += value * vector[index]
        return total

    def _pad_row(self, row, width):
        return list(row) + [0] * (width - len(row))

    def _message_tag(self, msg):
        return hashlib.sha256(self.group.serialize(msg)).hexdigest()

    def _solve_subset(self, rows, width):
        column_count = len(rows)
        modulus = self.group.order()
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

        solution = [self.group.init(ZR, 0)] * column_count
        for row, col in enumerate(pivot_cols):
            solution[col] = self.group.init(ZR, matrix[row][column_count] % modulus)
        return solution


__all__ = ['FABESACPABE']
