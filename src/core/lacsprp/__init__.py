'''
LACS-PRP-style anonymous CP-ABE skeleton based on /home/jinji_o/ABE-Test/LACS-PRP.md.

| Notes: Keeps the standard CP-ABE interface used by Benchmark/run_cp_schemes.py.
| Notes: Follows the BSW07 CP-ABE pairing flow and adds a Path Bloom Filter
|        (PBF) policy-hiding/matching layer inspired by LACS-PRP.
| Notes: The ROBDD builder, PBF encoding, and authentication pieces below are
|        structural placeholders. They are NOT cryptographically verified
|        implementations of the LACS-PRP paper.
|
| type:           ciphertext-policy attribute-based encryption
| setting:        Pairing
'''

import hashlib
import os

from charm.toolbox.pairinggroup import ZR, G1, G2, pair
from charm.toolbox.ABEnc import ABEnc
from charm.toolbox.policytree import OpType

from ..msp import MSP

debug = False


class LACSPRPCPABE(ABEnc):
    def __init__(self, group_obj, pbf_size=2048, hash_count=3, verbose=False):
        ABEnc.__init__(self)
        self.name = "LACS-PRP CP-ABE"
        self.group = group_obj
        self.pbf_size = max(64, int(pbf_size))
        self.hash_count = max(2, int(hash_count))
        self.element_size = 32
        self.util = MSP(self.group, verbose)

    def setup(self):
        """
        Generates public key and master secret key.
        """

        if debug:
            print('\nSetup algorithm:\n')

        # BSW07-style asymmetric CP-ABE core. LACS-PRP's printed formulas mix
        # source groups in a few places, so this runner-compatible skeleton uses
        # the repository's established CP-ABE pairing flow for message recovery.
        g1 = self.group.random(G1)
        g2 = self.group.random(G2)

        beta = self._random_nonzero_zr()
        h = g2 ** beta
        f = g2 ** (1 / beta)

        alpha = self._random_nonzero_zr()
        g1_alpha = g1 ** alpha
        e_gg_alpha = pair(g1_alpha, g2)

        pk = {
            'g1': g1,
            'g2': g2,
            'h': h,
            'f': f,
            'e_gg_alpha': e_gg_alpha,
            'pbf_size': self.pbf_size,
            'hash_count': self.hash_count,
        }
        msk = {'beta': beta, 'g1_alpha': g1_alpha}

        return pk, msk

    def keygen(self, pk, msk, attr_list):
        """
        Generate a key for a set of attributes.
        """

        if debug:
            print('\nKey generation algorithm:\n')

        r = self._random_nonzero_zr()
        g1_r = pk['g1'] ** r
        beta_inverse = 1 / msk['beta']
        k0 = (msk['g1_alpha'] * g1_r) ** beta_inverse

        K = {}
        for attr in attr_list:
            r_attr = self.group.random(ZR)
            attr_hash = self.group.hash(str(attr), G1)
            k_attr1 = g1_r * (attr_hash ** r_attr)
            k_attr2 = pk['g2'] ** r_attr
            K[attr] = (k_attr1, k_attr2)

        return {'attr_list': list(attr_list), 'k0': k0, 'K': K}

    def encrypt(self, pk, msg, policy_str):
        """
        Encrypt a GT message under a policy string and attach a PBF.
        """

        if debug:
            print('\nEncryption algorithm:\n')

        ctxt, pbf_paths = self._encrypt_core(pk, msg, policy_str)
        ctxt['pbf'] = self.pbf_create(pbf_paths)
        return ctxt

    def pbf_create(self, pbf_paths):
        """
        Create a Path Bloom Filter for the satisfiable policy paths.
        """

        if debug:
            print('\nPBF-Create algorithm:\n')

        paths = []
        for path_index, path in enumerate(pbf_paths):
            array = [None] * self.pbf_size
            nodes = []

            for node in path:
                element = self._encode_pbf_element(node['node_id'], node['attr'])
                target = self._element_digest(element)
                positions = self._hash_positions(element)
                free_positions = [pos for pos in positions if array[pos] is None]

                # PLACEHOLDER/UNVERIFIED: a real GBF/PBF implementation should
                # define a rebuild/stash strategy. For this compact skeleton, if
                # all candidate positions are already occupied, the node is put
                # in an overflow list so functional tests remain deterministic.
                if not free_positions:
                    nodes.append({
                        'node_id': node['node_id'],
                        'row_index': node['row_index'],
                        'overflow': self._overflow_tag(element),
                    })
                    continue

                final_pos = free_positions[-1]
                xor_value = bytearray(self.element_size)
                for pos in positions:
                    if pos == final_pos:
                        continue
                    if array[pos] is None:
                        array[pos] = os.urandom(self.element_size)
                    xor_value = self._xor_bytes(xor_value, array[pos])

                array[final_pos] = self._xor_bytes(xor_value, target)
                nodes.append({
                    'node_id': node['node_id'],
                    'row_index': node['row_index'],
                    'overflow': None,
                })

            for index, value in enumerate(array):
                if value is None:
                    array[index] = os.urandom(self.element_size)

            paths.append({
                'path_index': path_index,
                'array': array,
                'nodes': nodes,
                'length': len(nodes),
            })

        return {
            'paths': paths,
            'pbf_size': self.pbf_size,
            'hash_count': self.hash_count,
            'element_size': self.element_size,
        }

    def pbf_check(self, pbf, attr_list):
        """
        Check whether attr_list matches one hidden PBF path.
        """

        if debug:
            print('\nPBF-Check algorithm:\n')

        tests = 0
        for path in pbf['paths']:
            matched_nodes = []
            failed = False

            for node in path['nodes']:
                matched_attr = None
                for attr in attr_list:
                    tests += 1
                    element = self._encode_pbf_element(node['node_id'], attr)
                    if self._pbf_contains(path, element, node['overflow']):
                        matched_attr = attr
                        break

                if matched_attr is None:
                    failed = True
                    break

                matched_nodes.append({
                    'row_index': node['row_index'],
                    'attr': matched_attr,
                    'node_id': node['node_id'],
                })

            if not failed:
                return {
                    'path_index': path['path_index'],
                    'nodes': matched_nodes,
                    'stats': {
                        'pbf_tests': tests,
                        'matched_path_length': len(matched_nodes),
                    },
                }

        return {
            'path_index': None,
            'nodes': [],
            'stats': {
                'pbf_tests': tests,
                'matched_path_length': 0,
            },
        }

    def decrypt_with_match(self, pk, ctxt, key, match):
        """
        Decrypt using a PBF-Check match result.
        """

        if debug:
            print('\nDecryption algorithm:\n')

        if not match or match['path_index'] is None:
            print("Policy not satisfied.")
            return None

        prod = 1
        for node in match['nodes']:
            attr = self.util.strip_index(node['attr'])
            if attr not in key['K']:
                print("Policy not satisfied.")
                return None

            row_ct = ctxt['rows'][node['row_index']]
            k_attr1, k_attr2 = key['K'][attr]
            prod *= pair(k_attr1, row_ct['C_1']) / pair(row_ct['C_2'], k_attr2)

        return (ctxt['C_prime'] * prod) / pair(key['k0'], ctxt['C_0'])

    def decrypt(self, pk, ctxt, key):
        """
        Compatibility wrapper for the repository's four-step CP-ABE interface.
        """

        match = self.pbf_check(ctxt['pbf'], key['attr_list'])
        return self.decrypt_with_match(pk, ctxt, key, match)

    def _encrypt_core(self, pk, msg, policy_str):
        policy = self.util.createPolicy(policy_str)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row

        attr_to_row = {}
        anonymous_rows = []
        rows = []

        u = [self._random_nonzero_zr()]
        for _ in range(num_cols - 1):
            u.append(self.group.random(ZR))
        s = u[0]

        C_0 = pk['h'] ** s
        C_prime = (pk['e_gg_alpha'] ** s) * msg

        for row_index, (attr, row) in enumerate(mono_span_prog.items()):
            cols = len(row)
            share = self.group.init(ZR, 0)
            for index in range(cols):
                share += row[index] * u[index]

            attr_stripped = self.util.strip_index(attr)
            C_1 = pk['g2'] ** share
            C_2 = self.group.hash(str(attr_stripped), G1) ** share

            rows.append({'C_1': C_1, 'C_2': C_2})
            anonymous_rows.append(self._pad_row(row, num_cols))
            attr_to_row[attr] = row_index

        pbf_paths = self._paths_to_pbf_entries(policy, attr_to_row)
        ctxt = {
            'C_0': C_0,
            'C_prime': C_prime,
            'rows': rows,
            'A_star': anonymous_rows,
            'path_count': len(pbf_paths),
            'pk_do_sig': 'placeholder-verification-key',
            'cert_do': 'placeholder-cert',
        }

        return ctxt, pbf_paths

    def _paths_to_pbf_entries(self, policy, attr_to_row):
        paths = []
        for path in self._enumerate_satisfying_paths(policy):
            pbf_path = []
            for attr in path:
                row_index = attr_to_row[attr]
                attr_stripped = self.util.strip_index(attr)
                pbf_path.append({
                    'node_id': row_index + 1,
                    'row_index': row_index,
                    'attr': attr_stripped,
                })
            paths.append(pbf_path)
        return paths

    def _enumerate_satisfying_paths(self, subtree):
        node_type = subtree.getNodeType()
        if node_type == OpType.ATTR:
            return [[subtree.getAttributeAndIndex()]]

        if node_type == OpType.OR:
            left_paths = self._enumerate_satisfying_paths(subtree.getLeft())
            right_paths = self._enumerate_satisfying_paths(subtree.getRight())
            return left_paths + right_paths

        if node_type == OpType.AND:
            left_paths = self._enumerate_satisfying_paths(subtree.getLeft())
            right_paths = self._enumerate_satisfying_paths(subtree.getRight())
            paths = []
            for left_path in left_paths:
                for right_path in right_paths:
                    paths.append(left_path + right_path)
            return paths

        return []

    def _random_nonzero_zr(self):
        value = self.group.random(ZR)
        while value == 0:
            value = self.group.random(ZR)
        return value

    def _pad_row(self, row, width):
        return list(row) + [0] * (width - len(row))

    def _encode_pbf_element(self, node_id, attr):
        return '{0}|{1}'.format(node_id, attr).encode('utf-8')

    def _element_digest(self, element):
        return hashlib.sha256(b'lacsprp::element::' + element).digest()

    def _hash_positions(self, element):
        positions = []
        for index in range(self.hash_count):
            digest = hashlib.sha256(
                b'lacsprp::pbf::' + str(index).encode('utf-8') + b'::' + element
            ).digest()
            positions.append(int.from_bytes(digest, byteorder='big') % self.pbf_size)
        return positions

    def _pbf_contains(self, path, element, overflow_tag):
        if overflow_tag is not None:
            return overflow_tag == self._overflow_tag(element)

        recovered = bytearray(self.element_size)
        for pos in self._hash_positions(element):
            recovered = self._xor_bytes(recovered, path['array'][pos])
        return bytes(recovered) == self._element_digest(element)

    def _overflow_tag(self, element):
        return hashlib.sha256(b'lacsprp::overflow::' + element).hexdigest()

    def _xor_bytes(self, left, right):
        return bytes(a ^ b for a, b in zip(left, right))


__all__ = ['LACSPRPCPABE']
