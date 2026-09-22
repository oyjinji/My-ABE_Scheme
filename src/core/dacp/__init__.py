'''
Double Anonymous CP-ABE prototype based on prompt_doc/ABE-Scheme.md.

| Notes: Implements the document's Setup, KeyGen, Encrypt, Transform, and
|        FinalDec flow with Type-III pairing placement.
| Notes: This is a prototype / benchmark-oriented implementation. The OPRF,
|        ABF, AEAD, certificate, and signature layers are runnable structural
|        models, not production cryptographic implementations.
|
| type:           double anonymous ciphertext-policy attribute-based encryption
| setting:        Pairing
'''

import hashlib
import os
from itertools import combinations

from charm.toolbox.pairinggroup import ZR, G1, G2, pair
from charm.toolbox.ABEnc import ABEnc

from ..msp import MSP
from .components import (
    PrototypeABF,
    PrototypeCertificateAuthority,
    PrototypeGTEnvelope,
    PrototypeHashSignature,
    PrototypeOPRF,
)

debug = False


class DACPCPABE(ABEnc):
    def __init__(self, group_obj, dummy_factor=1, abf_size=4096,
                 hash_count=3, beta=32, epoch_mode=False, verbose=False,
                 oprf=None, abf=None, symmetric=None, signature=None,
                 certificate=None):
        ABEnc.__init__(self)
        self.name = "DACP CP-ABE"
        self.group = group_obj
        self.dummy_factor = max(1, int(dummy_factor))
        self.abf_size = max(64, int(abf_size))
        self.hash_count = max(2, int(hash_count))
        self.beta = max(16, int(beta))
        self.epoch_mode = bool(epoch_mode)
        self.util = MSP(self.group, verbose)
        self._prototype_oprf_kappa = None
        self.oprf = oprf or PrototypeOPRF(self.group, epoch_mode=self.epoch_mode)
        self.abf = abf or PrototypeABF(self.abf_size, self.hash_count, self.beta)
        self.symmetric = symmetric or PrototypeGTEnvelope(self.group)
        if hasattr(self.symmetric, 'set_group'):
            self.symmetric.set_group(self.group)
        self.signature = signature or PrototypeHashSignature()
        self.certificate = certificate or PrototypeCertificateAuthority()

    def setup(self):
        """
        ABE-Scheme.md Setup: generate PP and MSK.
        """

        if debug:
            print('\nSetup algorithm:\n')

        g1 = self.group.random(G1)
        g2 = self.group.random(G2)
        alpha = self._random_nonzero_zr()
        a = self._random_nonzero_zr()
        kappa = self._random_nonzero_zr()
        e_g1g2_alpha = pair(g1, g2) ** alpha

        pp = {
            'version': 'dacp-prototype-v1',
            'g1': g1,
            'g2': g2,
            'g1_a': g1 ** a,
            'e_g1g2_alpha': e_g1g2_alpha,
            'H0': 'dacp::H0',
            'H1': 'dacp::H1',
            'H_chk': 'dacp::H_chk',
            'H_ct': 'dacp::H_ct',
            'H_row': 'dacp::H_row',
            'H_seed': 'dacp::H_seed',
            'KDF': 'dacp::KDF-prototype',
            'AEAD': 'dacp::AEAD-GT-mask-prototype',
            'Sig': 'dacp::hash-signature-prototype',
            'm': self.abf_size,
            'k': self.hash_count,
            'beta': self.beta,
            'epoch_mode': self.epoch_mode,
            'ca_pk': 'prototype-ca-public-key',
        }

        msk = {
            'alpha': alpha,
            'a': a,
            'kappa': kappa,
            'MSK': {
                'alpha': alpha,
                'a': a,
                'kappa': kappa,
            },
        }

        pk = dict(pp)
        pk['PP'] = pp
        # Kept for compatibility with existing benchmark naming.
        pk['sig_vk'] = pp['ca_pk']

        # Prototype-only state: Encrypt simulates the DO<->KGC OPRF exchange on
        # the same object. A production implementation must not depend on this.
        self._prototype_oprf_kappa = kappa
        return pk, msk

    def keygen(self, pk, msk, attr_list, user_id=None, **kwargs):
        """
        ABE-Scheme.md KeyGen: create TK_id for CSP and RK_id for DU.
        """

        if debug:
            print('\nKey generation algorithm:\n')

        epoch = kwargs.get('epoch')
        dummy_factor = int(kwargs.get('dummy_factor', self.dummy_factor))
        real_attrs = list(attr_list)
        dummy_attrs = self._make_dummy_attributes(real_attrs, user_id, epoch, dummy_factor)
        virtual_attrs = real_attrs + dummy_attrs

        t = self._random_nonzero_zr()
        z = self._random_nonzero_zr()
        K_0 = pk['g2'] ** ((msk['alpha'] + (msk['a'] * t)) / z)
        K_1 = pk['g2'] ** (t / z)

        tk_attrs = []
        token_map = {}
        for attr in virtual_attrs:
            tau = self._token_from_attr(attr, msk['kappa'], epoch)
            token_id = self._token_id(tau)
            Q_x = self._H0(tau)
            K_x = Q_x ** (t / z)

            entry = {
                'attribute_tag': token_id,
                'token_id': token_id,
                'tau': tau,
                'token': tau,
                'K_x': K_x,
                'is_dummy': attr not in real_attrs,
            }
            tk_attrs.append(entry)
            if attr in real_attrs:
                token_map[token_id] = attr

        TK_id = {
            'K_0': K_0,
            'K_1': K_1,
            'attributes': tk_attrs,
            'TK': tk_attrs,
            'user_id': user_id,
            'epoch': epoch,
            'real_count': len(real_attrs),
            'dummy_count': len(dummy_attrs),
        }
        RK_id = {
            'z': z,
            'RK': z,
            'Map': token_map,
            'user_id': user_id,
            'epoch': epoch,
        }

        return {
            'attr_list': real_attrs,
            'real_attr_list': real_attrs,
            'dummy_attr_list': dummy_attrs,
            'virtual_attr_list': virtual_attrs,
            'mixed_attr_list': virtual_attrs,
            'TK_id': TK_id,
            'RK_id': RK_id,
            # Legacy aliases used by earlier benchmark helpers.
            'K_0': K_0,
            'K_1': K_1,
            'TK': tk_attrs,
            'RK': z,
            'Map': token_map,
        }

    def encrypt(self, pk, msg, policy_str, oprf_tokens=None,
                require_external_oprf=False, **kwargs):
        """
        ABE-Scheme.md Encrypt: LSSS sharing, prototype OPRF, ABF.Build,
        row components, row tags, context binding, and GT-mask AEAD model.
        """

        if debug:
            print('\nEncryption algorithm:\n')

        epoch = kwargs.get('epoch')
        do_pk_sig = self._normalize_sig_public_key(
            kwargs.get('pk_DO_sig', 'prototype-do-public-key')
        )
        do_sk_sig = kwargs.get('sk_DO_sig', do_pk_sig)
        cert_do = kwargs.get('cert_DO', 'prototype-cert-for-' + str(do_pk_sig))

        policy = self.util.createPolicy(policy_str)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row
        external_tokens = self._validate_external_oprf_tokens(
            oprf_tokens,
            len(mono_span_prog),
            require_external_oprf,
        )

        share_vector = [self._random_nonzero_zr()]
        for _ in range(num_cols - 1):
            share_vector.append(self.group.random(ZR))
        s = share_vector[0]

        C = pk['g1'] ** s
        E = pk['e_g1g2_alpha'] ** s
        rows = []
        anonymous_rows = []
        token_rows = {}
        token_ids = []

        for row_index, (attr, row) in enumerate(mono_span_prog.items()):
            attr_stripped = self.util.strip_index(attr)
            if external_tokens is not None:
                token_entry = external_tokens[row_index]
                tau_i = token_entry['tau_i']
                token_id = token_entry['token_id']
            else:
                # Legacy fallback for algorithm-level benchmarks: encrypt()
                # locally derives prototype OPRF tokens using setup state. This
                # path is disabled when require_external_oprf=True.
                tau_i = self._prototype_oprf_token(pk, attr_stripped, epoch)
                token_id = self._token_id(tau_i)
            Q_i = self._H0(tau_i)
            lambda_i = self._dot_product(row, share_vector)
            r_i = self.group.random(ZR)

            C_i_1 = (pk['g1_a'] ** lambda_i) / (Q_i ** r_i)
            C_i_2 = pk['g2'] ** r_i
            rows.append({
                'C_i_1': C_i_1,
                'C_i_2': C_i_2,
                'sigma_i': None,
            })
            anonymous_rows.append(self._pad_row(row, num_cols))
            token_ids.append(token_id)
            token_rows.setdefault(token_id, []).append(row_index)

        BF = self._abf_build(token_rows, len(rows))
        meta = {
            'version': 'dacp-prototype-v1',
            'epoch': epoch,
            'ell': len(rows),
            'm': BF['m'],
            'k': BF['k'],
            'beta': BF['beta'],
        }
        BF_digest = self._digest_bf(BF)
        row_hashes = [self._H_row(row['C_i_1'], row['C_i_2']) for row in rows]
        D_row = self._digest_row_root(row_hashes)
        cid = self._H_ct(C, anonymous_rows, BF_digest, D_row, meta)

        for row_index, token_id in enumerate(token_ids):
            rows[row_index]['sigma_i'] = self._sign_row(
                do_sk_sig,
                cid,
                row_index,
                token_id,
                row_hashes[row_index],
            )

        ad = self._associated_data(cid, anonymous_rows, BF_digest, do_pk_sig)
        sealed = self.symmetric.seal(msg, E, aad=ad)
        symmetric_mode = sealed.get(
            'mode',
            'GT' if isinstance(self.symmetric, PrototypeGTEnvelope) else self.symmetric.__class__.__name__,
        )

        return {
            'C_sym': sealed.get('C_sym', sealed.get('ciphertext')),
            'nonce_AEAD': sealed.get('nonce_AEAD', sealed.get('nonce')),
            'C': C,
            'rows': rows,
            'A_star': anonymous_rows,
            'meta': meta,
            'BF': BF,
            'ABF': BF,
            'D_row': D_row,
            'cid': cid,
            'policy_tag': cid,
            'attribute_tag_root': D_row,
            'pk_DO_sig': do_pk_sig,
            'cert_DO': cert_do,
            'BF_digest': BF_digest,
            'aead_tag': sealed.get('aead_tag'),
            'symmetric_mode': symmetric_mode,
            'external_oprf_tokens_used': external_tokens is not None,
        }

    def match(self, pk, ctxt, tk_or_key):
        """
        ABE-Scheme.md Transform 4.1: ABF.Query/Verify only.
        """

        tk = self._extract_tk(tk_or_key)
        BF = ctxt.get('BF', ctxt.get('ABF'))
        matches = []
        abf_queries = 0
        for tk_entry in tk['attributes']:
            abf_queries += 1
            row_indices = self._abf_query(BF, tk_entry['tau'])
            if row_indices:
                matches.append({
                    'token_id': tk_entry['token_id'],
                    'tau': tk_entry['tau'],
                    'K_x': tk_entry['K_x'],
                    'rows': row_indices,
                })

        return {
            'matches': matches,
            'stats': {
                'abf_queries': abf_queries,
                'matched_tokens': len(matches),
                'matched_rows': sum(len(item['rows']) for item in matches),
            },
        }

    def transform(self, pk, ctxt, tk):
        """
        ABE-Scheme.md Transform: CSP computes T_0 and T_{i,x}.
        """

        if debug:
            print('\nTransform algorithm:\n')

        TK_id = self._extract_tk(tk)
        match = self.match(pk, ctxt, TK_id)
        T_0 = pair(ctxt['C'], TK_id['K_0'])
        candidates = []

        for item in match['matches']:
            for row_index in item['rows']:
                row_ct = ctxt['rows'][row_index]
                T_ix = pair(row_ct['C_i_1'], TK_id['K_1']) * pair(item['K_x'], row_ct['C_i_2'])
                candidates.append({
                    'i': row_index,
                    'row_index': row_index,
                    'tau': item['tau'],
                    'tau_i': item['tau'],
                    'token_id': item['token_id'],
                    'attribute_tag': item['token_id'],
                    'T_i_x': T_ix,
                    'T': T_ix,
                    'C_i_1': row_ct['C_i_1'],
                    'C_i_2': row_ct['C_i_2'],
                    'sigma_i': row_ct['sigma_i'],
                })

        return {
            'T_0': T_0,
            'C': ctxt['C'],
            'A_star': ctxt['A_star'],
            'C_sym': ctxt['C_sym'],
            'nonce_AEAD': ctxt['nonce_AEAD'],
            'symmetric_mode': ctxt.get('symmetric_mode', 'GT'),
            'cid': ctxt['cid'],
            'policy_tag': ctxt['policy_tag'],
            'meta': ctxt['meta'],
            'pk_DO_sig': ctxt['pk_DO_sig'],
            'cert_DO': ctxt['cert_DO'],
            'BF': ctxt['BF'],
            'ABF': ctxt['BF'],
            'BF_digest': ctxt['BF_digest'],
            'D_row': ctxt['D_row'],
            'aead_tag': ctxt['aead_tag'],
            'candidates': candidates,
            'stats': {
                'abf_queries': match['stats']['abf_queries'],
                'matched_candidates': len(candidates),
            },
        }

    def final_decrypt(self, pk, transformed_ctxt, rk):
        """
        ABE-Scheme.md FinalDec: verify context and row tags, filter dummy
        tokens, solve reconstruction coefficients, unblind E, and recover M.
        """

        if debug:
            print('\nFinal decryption algorithm:\n')

        RK_id = self._extract_rk(rk)
        verification_stats = transformed_ctxt.setdefault('verification_stats', {})
        verification_stats['cert_verified'] = False
        verification_stats['row_signatures_verified'] = 0
        verification_stats['row_signatures_rejected'] = 0
        verification_stats['aead_authenticated'] = False
        verification_stats['failure_reason'] = None

        if not self._verify_cert(transformed_ctxt['cert_DO'], transformed_ctxt['pk_DO_sig']):
            verification_stats['failure_reason'] = 'invalid_certificate'
            print("Invalid DO certificate.")
            return None
        verification_stats['cert_verified'] = True

        BF_digest = self._digest_bf(transformed_ctxt['BF'])
        if transformed_ctxt.get('BF_digest') != BF_digest:
            verification_stats['failure_reason'] = 'abf_digest_mismatch'
            print("ABF digest verification failed.")
            return None
        expected_cid = self._H_ct(
            transformed_ctxt['C'],
            transformed_ctxt['A_star'],
            BF_digest,
            transformed_ctxt['D_row'],
            transformed_ctxt['meta'],
        )
        if expected_cid != transformed_ctxt['cid']:
            verification_stats['failure_reason'] = 'ciphertext_context_mismatch'
            print("Ciphertext context verification failed.")
            return None

        valid_rows = {}
        for item in transformed_ctxt['candidates']:
            token_id = item['token_id']
            if token_id not in RK_id['Map']:
                continue
            candidate_tau = item.get('tau_i', item.get('tau'))
            if candidate_tau is not None and self._token_id(candidate_tau) != token_id:
                verification_stats['row_signatures_rejected'] += 1
                continue

            h_i = self._H_row(item['C_i_1'], item['C_i_2'])
            if not self._verify_row(
                    transformed_ctxt['pk_DO_sig'],
                    transformed_ctxt['cid'],
                    item['row_index'],
                    token_id,
                    h_i,
                    item['sigma_i']):
                verification_stats['row_signatures_rejected'] += 1
                continue

            verification_stats['row_signatures_verified'] += 1
            valid_rows[item['row_index']] = item

        if not valid_rows:
            verification_stats['failure_reason'] = 'no_valid_rows'
            print("Policy not satisfied.")
            return None

        row_indices = sorted(valid_rows.keys())
        coeffs = self._find_reconstruction_coefficients(transformed_ctxt['A_star'], row_indices)
        if coeffs is None:
            verification_stats['failure_reason'] = 'policy_not_satisfied'
            print("Policy not satisfied.")
            return None

        denominator = 1
        for row_index, coeff in coeffs.items():
            denominator *= valid_rows[row_index]['T_i_x'] ** coeff

        E_blinded = transformed_ctxt['T_0'] / denominator
        E = E_blinded ** RK_id['z']
        ad = self._associated_data(
            transformed_ctxt['cid'],
            transformed_ctxt['A_star'],
            BF_digest,
            transformed_ctxt['pk_DO_sig'],
        )
        msg = self.symmetric.open({
            'C_sym': transformed_ctxt['C_sym'],
            'ciphertext': transformed_ctxt['C_sym'],
            'nonce_AEAD': transformed_ctxt['nonce_AEAD'],
            'nonce': transformed_ctxt['nonce_AEAD'],
            'aead_tag': transformed_ctxt['aead_tag'],
            'mode': transformed_ctxt.get('symmetric_mode', 'GT'),
        }, E, aad=ad)
        if msg is None:
            verification_stats['failure_reason'] = 'aead_authentication_failed'
            print("AEAD verification failed.")
            return None
        verification_stats['aead_authenticated'] = True

        return msg

    def decrypt_with_match(self, pk, ctxt, key):
        """
        Compatibility helper for callers that name the outsourced path as
        decrypt_with_match().
        """

        partial = self.transform(pk, ctxt, self._extract_tk(key))
        return self.final_decrypt(pk, partial, self._extract_rk(key))

    def decrypt(self, pk, ctxt, key):
        """
        Repository-compatible CP-ABE wrapper.
        """

        if debug:
            print('\nDecryption algorithm:\n')

        return self.decrypt_with_match(pk, ctxt, key)

    def pbf_create(self, token_rows, row_count=None):
        """
        Alias for the document's BF/ABF build step.
        """

        if row_count is None:
            row_count = 0
            for rows in token_rows.values():
                if rows:
                    row_count = max(row_count, max(rows) + 1)
        return self._abf_build(token_rows, row_count)

    def pbf_check(self, BF, token_or_entries):
        """
        Alias for BF/ABF query. Accepts a single token or a TK attribute list.
        """

        if isinstance(token_or_entries, list):
            result = {}
            for entry in token_or_entries:
                result[entry['token_id']] = self._abf_query(BF, entry['tau'])
            return result
        return self._abf_query(BF, token_or_entries)

    def _extract_tk(self, value):
        if 'TK_id' in value:
            return value['TK_id']
        if 'attributes' in value:
            return value
        if 'TK' in value and 'K_0' in value and 'K_1' in value:
            return {
                'K_0': value['K_0'],
                'K_1': value['K_1'],
                'attributes': value['TK'],
                'TK': value['TK'],
            }
        return value

    def _extract_rk(self, value):
        if 'RK_id' in value:
            return value['RK_id']
        if 'z' in value and 'Map' in value:
            return value
        if 'RK' in value and 'Map' in value:
            return {'z': value['RK'], 'RK': value['RK'], 'Map': value['Map']}
        return value

    def _validate_external_oprf_tokens(self, oprf_tokens, row_count, require_external_oprf):
        if oprf_tokens is None:
            if require_external_oprf:
                raise ValueError('require_external_oprf=True requires oprf_tokens')
            return None

        if not isinstance(oprf_tokens, list):
            raise ValueError('oprf_tokens must be a list of row token dictionaries')
        if len(oprf_tokens) != row_count:
            raise ValueError(
                'oprf_tokens length {0} does not match policy row count {1}'.format(
                    len(oprf_tokens),
                    row_count,
                )
            )

        by_index = {}
        for token in oprf_tokens:
            for field in ('item_index', 'tau_i', 'token_id'):
                if field not in token:
                    raise ValueError('oprf token is missing required field {0}'.format(field))
            item_index = token['item_index']
            if not isinstance(item_index, int):
                raise ValueError('oprf token item_index must be an int')
            if item_index in by_index:
                raise ValueError('duplicate oprf token item_index {0}'.format(item_index))
            if item_index < 0 or item_index >= row_count:
                raise ValueError('oprf token item_index {0} out of range'.format(item_index))
            expected_token_id = self._token_id(token['tau_i'])
            if token['token_id'] != expected_token_id:
                raise ValueError('oprf token_id mismatch at item_index {0}'.format(item_index))
            by_index[item_index] = token

        missing = [index for index in range(row_count) if index not in by_index]
        if missing:
            raise ValueError('missing oprf token item_index values: {0}'.format(missing))
        return [by_index[index] for index in range(row_count)]

    def _random_nonzero_zr(self):
        value = self.group.random(ZR)
        while value == 0:
            value = self.group.random(ZR)
        return value

    def _make_dummy_attributes(self, attr_list, user_id, epoch, dummy_factor):
        count = max(1, len(attr_list) * max(1, int(dummy_factor)))
        prefix = 'dummy::{0}::{1}'.format(user_id if user_id is not None else 'user', epoch)
        return ['{0}::{1}'.format(prefix, index) for index in range(count)]

    def _chi_epoch(self, attr, epoch):
        if self.epoch_mode or epoch is not None:
            return '{0}|epoch={1}'.format(attr, epoch)
        return str(attr)

    def _token_from_attr(self, attr, kappa, epoch):
        if hasattr(self.oprf, 'token_from_attr'):
            return self.oprf.token_from_attr(attr, kappa, epoch=epoch)
        base = self.group.hash('dacp::H1::' + self._chi_epoch(attr, epoch), G1)
        return base ** kappa

    def _prototype_oprf_token(self, pk, attr, epoch):
        # Prototype model of the DO<->KGC OPRF interaction in Encrypt. The same
        # object keeps kappa from setup so encryption can produce matching
        # tokens without exposing a full network OPRF implementation.
        if self._prototype_oprf_kappa is None:
            raise ValueError('prototype OPRF state is missing; call setup() before encrypt()')
        return self._token_from_attr(attr, self._prototype_oprf_kappa, epoch)

    def _token_id(self, token):
        return self.oprf.token_id(token)

    def _H0(self, token):
        if hasattr(self.oprf, 'H0'):
            return self.oprf.H0(token)
        return self.group.hash('dacp::H0::' + self._token_id(token), G1)

    def _H_chk(self, token):
        return hashlib.sha256(b'dacp::H_chk::' + self.group.serialize(token)).digest()[:self.beta]

    def _KDF(self, element):
        if hasattr(self.symmetric, 'kdf'):
            return self.symmetric.kdf(element)
        return hashlib.sha256(b'dacp::KDF::' + self.group.serialize(element)).hexdigest()

    def _H_row(self, C_i_1, C_i_2):
        digest = hashlib.sha256()
        digest.update(b'dacp::H_row::')
        digest.update(self.group.serialize(C_i_1))
        digest.update(self.group.serialize(C_i_2))
        return digest.hexdigest()

    def _digest_row_root(self, row_hashes):
        digest = hashlib.sha256()
        digest.update(b'dacp::D_row::')
        for row_hash in row_hashes:
            digest.update(str(row_hash).encode('utf-8'))
        return digest.hexdigest()

    def _H_ct(self, C, A_star, BF_digest, D_row, meta):
        digest = hashlib.sha256()
        digest.update(b'dacp::H_ct::')
        digest.update(self.group.serialize(C))
        digest.update(repr(A_star).encode('utf-8'))
        digest.update(str(BF_digest).encode('utf-8'))
        digest.update(str(D_row).encode('utf-8'))
        digest.update(repr(meta).encode('utf-8'))
        return digest.hexdigest()

    def _associated_data(self, cid, A_star, BF_digest, pk_DO_sig):
        return repr((
            cid,
            A_star,
            BF_digest,
            self._normalize_sig_public_key(pk_DO_sig),
        )).encode('utf-8')

    def _aead_tag(self, K_ses, nonce, C_sym, ad, msg):
        if hasattr(self.symmetric, 'tag'):
            return self.symmetric.tag(K_ses, nonce, C_sym, ad, msg)
        digest = hashlib.sha256()
        digest.update(b'dacp::AEAD::')
        digest.update(str(K_ses).encode('utf-8'))
        digest.update(str(nonce).encode('utf-8'))
        digest.update(self.group.serialize(C_sym))
        digest.update(ad)
        digest.update(self.group.serialize(msg))
        return digest.hexdigest()

    def _sign_row(self, sk_DO_sig, cid, row_index, token_id, row_hash):
        return self.signature.sign(sk_DO_sig, self._row_message(cid, row_index, token_id, row_hash))

    def _verify_row(self, pk_DO_sig, cid, row_index, token_id, row_hash, sigma):
        return self.signature.verify(
            pk_DO_sig,
            self._row_message(cid, row_index, token_id, row_hash),
            sigma,
        )

    def _row_message(self, cid, row_index, token_id, row_hash):
        return {
            'cid': cid,
            'row_index': row_index,
            'token_id': token_id,
            'row_hash': row_hash,
        }

    def _row_tag_digest(self, key_material, cid, row_index, token_id, row_hash):
        payload = 'dacp::Sig::{0}|{1}|{2}|{3}|{4}'.format(
            key_material,
            cid,
            row_index,
            token_id,
            row_hash,
        )
        return hashlib.sha256(payload.encode('utf-8')).hexdigest()

    def _verify_cert(self, cert_DO, pk_DO_sig):
        return self.certificate.verify_cert(
            cert_DO,
            public_key=self._normalize_sig_public_key(pk_DO_sig),
        )

    def _normalize_sig_public_key(self, pk_DO_sig):
        if hasattr(self.signature, 'serialize_public_key'):
            try:
                return self.signature.serialize_public_key(pk_DO_sig).hex()
            except Exception:
                pass
        if isinstance(pk_DO_sig, bytes):
            return pk_DO_sig.hex()
        if isinstance(pk_DO_sig, bytearray):
            return bytes(pk_DO_sig).hex()
        return pk_DO_sig

    def _dot_product(self, row, vector):
        total = self.group.init(ZR, 0)
        for index, value in enumerate(row):
            total += value * vector[index]
        return total

    def _pad_row(self, row, width):
        return list(row) + [0] * (width - len(row))

    def _abf_payload_len(self, row_count):
        return row_count + self.beta

    def _abf_payload(self, row_indices, row_count, token):
        bitmap = bytearray(row_count)
        for row_index in row_indices:
            bitmap[row_index] = 1
        return bytes(bitmap) + self._H_chk(token)

    def _abf_positions(self, seed, token_id, m, k):
        positions = []
        counter = 0
        while len(positions) < k:
            digest = hashlib.sha256(
                b'dacp::H_seed::' + seed + token_id.encode('utf-8') +
                b'::' + str(counter).encode('utf-8')
            ).digest()
            pos = int.from_bytes(digest, byteorder='big') % m
            counter += 1
            if pos not in positions:
                positions.append(pos)
        return positions

    def _abf_build(self, token_rows, row_count):
        return self.abf.build(token_rows, params={
            'row_count': row_count,
            'm': self.abf_size,
            'k': self.hash_count,
            'beta': self.beta,
        })

    def _abf_build_with_seed(self, token_rows, row_count, seed, payload_len):
        slots = [None] * self.abf_size
        # token_rows maps token_id to rows; stash token_id checks are not enough
        # for query, so Encrypt stores a prototype check table only as slot data.
        for token_id, row_indices in token_rows.items():
            positions = self._abf_positions(seed, token_id, self.abf_size, self.hash_count)
            free_positions = [pos for pos in positions if slots[pos] is None]
            if not free_positions:
                raise RuntimeError('ABF seed unexpectedly exhausted')
            reserved = free_positions[-1]
            # The check string is token-id based in this prototype so the ABF
            # can be queried without storing token plaintext.
            payload = self._abf_payload_from_token_id(row_indices, row_count, token_id)
            acc = bytes(payload_len)
            for pos in positions:
                if pos == reserved:
                    continue
                if slots[pos] is None:
                    slots[pos] = os.urandom(payload_len)
                acc = self._xor_bytes(acc, slots[pos])
            slots[reserved] = self._xor_bytes(acc, payload)

        for index, value in enumerate(slots):
            if value is None:
                slots[index] = os.urandom(payload_len)

        return {
            'slots': slots,
            'seed_ABF': seed.hex(),
            'm': self.abf_size,
            'k': self.hash_count,
            'ell': row_count,
            'beta': self.beta,
            'payload_len': payload_len,
            'prototype': True,
        }

    def _abf_payload_from_token_id(self, row_indices, row_count, token_id):
        bitmap = bytearray(row_count)
        for row_index in row_indices:
            bitmap[row_index] = 1
        check = hashlib.sha256(('dacp::H_chk_id::' + token_id).encode('utf-8')).digest()[:self.beta]
        return bytes(bitmap) + check

    def _abf_query(self, BF, token):
        token_id = self._token_id(token)
        return self.abf.query(BF, token_id)

    def _digest_bf(self, BF):
        if hasattr(self.abf, 'digest'):
            return self.abf.digest(BF)
        digest = hashlib.sha256()
        digest.update(b'dacp::DigestBF::')
        for slot in BF['slots']:
            digest.update(slot)
        digest.update(BF['seed_ABF'].encode('utf-8'))
        digest.update(str(BF['m']).encode('utf-8'))
        digest.update(str(BF['k']).encode('utf-8'))
        digest.update(str(BF['ell']).encode('utf-8'))
        digest.update(str(BF['beta']).encode('utf-8'))
        return digest.hexdigest()

    def _xor_bytes(self, left, right):
        return bytes(a ^ b for a, b in zip(left, right))

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


__all__ = ['DACPCPABE']
