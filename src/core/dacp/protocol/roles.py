'''
Protocol roles for the local DACP simulation.

The role layer intentionally wraps the algorithm-level DACPCPABE object rather
than replacing it. OPRF, signatures, certificates, and AEAD are still prototype
models supplied by the algorithm-level implementation; this module only makes
the protocol message flow explicit and measurable.
'''

from .messages import (
    ACCESS_REQUEST,
    CIPHERTEXT_UPLOAD,
    ERROR,
    OPRF_REQUEST,
    OPRF_RESPONSE,
    TK_PROVISION,
    TRANSFORM_RESPONSE,
    USER_KEY_REQUEST,
    USER_KEY_RESPONSE,
    make_message,
    new_nonce,
    new_session_id,
)


class KGC:
    def __init__(self, scheme, kgc_id="KGC", csp_id="CSP", metrics=None, transport=None):
        self.scheme = scheme
        self.kgc_id = kgc_id
        self.csp_id = csp_id
        self.metrics = metrics
        self.transport = transport
        self.pk = None
        self.msk = None

    def setup(self):
        if self.metrics is not None:
            self.metrics.start_timer('setup_time')
        self.pk, self.msk = self.scheme.setup()
        if self.metrics is not None:
            self.metrics.stop_timer('setup_time')
        return self.pk, self.msk

    def handle_user_key_request(self, msg):
        if self.metrics is not None:
            self.metrics.start_timer('user_key_time')

        payload = msg.payload
        du_id = payload.get('du_id', msg.sender)
        attr_list = payload.get('attr_list', [])
        epoch = payload.get('epoch')
        key = self.scheme.keygen(self.pk, self.msk, attr_list, user_id=du_id, epoch=epoch)
        du_key = dict(key)
        # M2 boundary: DU receives only local recovery material and bookkeeping.
        # The transform key is provisioned to CSP via TK_PROVISION below.
        for field in ('TK_id', 'TK', 'K_0', 'K_1'):
            du_key.pop(field, None)

        du_response = make_message(
            USER_KEY_RESPONSE,
            self.kgc_id,
            msg.sender,
            {
                'du_id': du_id,
                'key': du_key,
                'RK_id': key['RK_id'],
                'real_attr_list': key['real_attr_list'],
                'dummy_attr_list': key['dummy_attr_list'],
            },
            session_id=msg.session_id,
        )
        tk_provision = make_message(
            TK_PROVISION,
            self.kgc_id,
            payload.get('csp_id', self.csp_id),
            {
                'du_id': du_id,
                'TK_id': key['TK_id'],
                'epoch': epoch,
                'real_count': len(key['real_attr_list']),
                'dummy_count': len(key['dummy_attr_list']),
            },
            session_id=msg.session_id,
        )

        if self.metrics is not None:
            self.metrics.stop_timer('user_key_time')
        self._send_or_return(tk_provision)
        return self._send_or_return(du_response)

    def handle_oprf_request(self, msg):
        """
        Prototype OPRF service.

        Real DACP should receive only blinded group elements B_i and return
        R_i = B_i^kappa. In this M2 protocol boundary model, OPRF_REQUEST no
        longer carries plaintext attributes. The response therefore returns
        prototype handles derived from the blinded item handles; algorithm-level
        encrypt() still computes matching tokens internally until a real OPRF
        interface is wired into DACPCPABE.
        """

        payload = msg.payload
        epoch = payload.get('epoch')
        evaluated_items = self.scheme.oprf.evaluate(
            payload.get('blinded_items', []),
            self.msk['kappa'],
            epoch=epoch,
        )

        response = make_message(
            OPRF_RESPONSE,
            self.kgc_id,
            msg.sender,
            {
                'batch_id': payload.get('batch_id'),
                'nonce_oprf': payload.get('nonce_oprf'),
                'evaluated_items': evaluated_items,
                'prototype_note': (
                    'Local simulation returns evaluated tokens directly; '
                    'replace with blinded OPRF messages for production.'
                ),
            },
            session_id=msg.session_id,
        )
        return self._send_or_return(response)

    def _send_or_return(self, message):
        if self.transport is not None:
            self.transport.send(message)
        return message


class DataOwner:
    def __init__(self, scheme, do_id="DO", kgc_id="KGC", csp_id="CSP",
                 metrics=None, transport=None, sk_DO_sig=None,
                 pk_DO_sig=None, cert_DO=None):
        self.scheme = scheme
        self.do_id = do_id
        self.kgc_id = kgc_id
        self.csp_id = csp_id
        self.metrics = metrics
        self.transport = transport
        self.pk = None
        self.oprf_cache = {}
        self.oprf_token_cache = {}
        self.oprf_blind_state = {}
        self.last_ct_id = None
        self.sk_DO_sig, self.pk_DO_sig = self._init_signature_keys(sk_DO_sig, pk_DO_sig)
        self.pk_DO_sig_ref = self._public_key_ref(self.pk_DO_sig)
        self.cert_DO = cert_DO or self.scheme.certificate.issue_cert(
            self.do_id,
            self.pk_DO_sig,
        )

    def set_public_key(self, pk):
        self.pk = pk

    def prepare_oprf_request(self, policy_str, epoch=None, session_id=None):
        policy_attrs = self._policy_attributes(policy_str)
        batch_id = new_session_id()
        nonce_oprf = new_nonce()
        # Prototype OPRF message shape: blind_state is local DO state and is
        # never sent in the envelope. The payload carries only opaque handles.
        blinded_items, blind_state = self.scheme.oprf.blind(
            policy_attrs,
            nonce=nonce_oprf,
            epoch=epoch,
        )
        self.oprf_blind_state[batch_id] = blind_state

        message = make_message(
            OPRF_REQUEST,
            self.do_id,
            self.kgc_id,
            {
                'batch_id': batch_id,
                'nonce_oprf': nonce_oprf,
                'blinded_items': blinded_items,
                'num_items': len(blinded_items),
                'epoch': epoch,
            },
            session_id=session_id,
        )
        return self._send_or_return(message)

    def handle_oprf_response(self, msg):
        batch_id = msg.payload.get('batch_id')
        tokens = self.scheme.oprf.unblind(
            msg.payload.get('evaluated_items', []),
            self.oprf_blind_state.get(batch_id),
        )
        cached = dict(msg.payload)
        cached['tokens'] = tokens
        self.oprf_cache[batch_id] = cached
        self.oprf_token_cache[batch_id] = tokens
        return cached

    def encrypt_and_upload(self, msg_GT, policy_str, csp_id=None,
                           ct_id=None, epoch=None, session_id=None,
                           batch_id=None, require_external_oprf=False):
        receiver = csp_id or self.csp_id
        ct_id = ct_id or ('ct-' + new_session_id())
        oprf_tokens = None
        if require_external_oprf:
            if batch_id is None:
                raise ValueError('batch_id is required when require_external_oprf=True')
            if batch_id not in self.oprf_token_cache:
                raise ValueError('no cached OPRF tokens for batch_id {0}'.format(batch_id))
            oprf_tokens = self.oprf_token_cache[batch_id]
            if self.metrics is not None:
                self.metrics.increment('num_external_oprf_tokens', len(oprf_tokens))
        if self.metrics is not None:
            self.metrics.start_timer('do_encrypt_time')
        ctxt = self.scheme.encrypt(
            self.pk,
            msg_GT,
            policy_str,
            oprf_tokens=oprf_tokens,
            require_external_oprf=require_external_oprf,
            epoch=epoch,
            pk_DO_sig=self.pk_DO_sig_ref,
            sk_DO_sig=self.sk_DO_sig,
            cert_DO=self.cert_DO,
        )
        if self.metrics is not None:
            self.metrics.stop_timer('do_encrypt_time')

        self.last_ct_id = ct_id
        message = make_message(
            CIPHERTEXT_UPLOAD,
            self.do_id,
            receiver,
            {
                'ct_id': ct_id,
                'ctxt': ctxt,
                'policy_tag': ctxt.get('policy_tag'),
                'meta': ctxt.get('meta'),
                'external_oprf_tokens_used': ctxt.get('external_oprf_tokens_used', False),
            },
            session_id=session_id,
        )
        return self._send_or_return(message)

    def _policy_attributes(self, policy_str):
        policy = self.scheme.util.createPolicy(policy_str)
        mono_span_prog = self.scheme.util.convert_policy_to_msp(policy)
        attrs = []
        for attr in mono_span_prog.keys():
            stripped = self.scheme.util.strip_index(attr)
            attrs.append(stripped)
        return attrs

    def _send_or_return(self, message):
        if self.transport is not None:
            self.transport.send(message)
        return message

    def _init_signature_keys(self, sk_DO_sig, pk_DO_sig):
        if sk_DO_sig is not None and pk_DO_sig is not None:
            return sk_DO_sig, pk_DO_sig
        if hasattr(self.scheme.signature, 'keygen'):
            try:
                return self.scheme.signature.keygen()
            except NotImplementedError:
                pass
        key = self.do_id + '-sig-key'
        return key, key

    def _public_key_ref(self, pk_DO_sig):
        if hasattr(self.scheme.signature, 'serialize_public_key'):
            try:
                return self.scheme.signature.serialize_public_key(pk_DO_sig).hex()
            except Exception:
                pass
        if isinstance(pk_DO_sig, bytes):
            return pk_DO_sig.hex()
        if isinstance(pk_DO_sig, bytearray):
            return bytes(pk_DO_sig).hex()
        return pk_DO_sig


class CloudServiceProvider:
    def __init__(self, scheme, csp_id="CSP", metrics=None, transport=None):
        self.scheme = scheme
        self.csp_id = csp_id
        self.metrics = metrics
        self.transport = transport
        self.pk = None
        self.ciphertexts = {}
        self.user_transform_keys = {}

    def set_public_key(self, pk):
        self.pk = pk

    def store_ciphertext(self, msg):
        ct_id = msg.payload['ct_id']
        self.ciphertexts[ct_id] = msg.payload['ctxt']
        return ct_id

    def handle_tk_provision(self, msg):
        du_id = msg.payload['du_id']
        self.user_transform_keys[du_id] = msg.payload['TK_id']
        return du_id

    def handle_access_request(self, msg):
        payload = msg.payload
        ct_id = payload.get('ct_id')
        du_id = payload.get('du_id', msg.sender)
        tk = self.user_transform_keys.get(du_id)
        ctxt = self.ciphertexts.get(ct_id)
        if ctxt is None:
            response = make_message(
                ERROR,
                self.csp_id,
                msg.sender,
                {'error': 'unknown ciphertext', 'ct_id': ct_id},
                session_id=msg.session_id,
            )
            return self._send_or_return(response)
        if tk is None:
            response = make_message(
                ERROR,
                self.csp_id,
                msg.sender,
                {'error': 'missing transform key', 'ct_id': ct_id, 'du_id': du_id},
                session_id=msg.session_id,
            )
            return self._send_or_return(response)

        if self.metrics is not None:
            self.metrics.start_timer('csp_transform_time')
        transformed = self.scheme.transform(self.pk, ctxt, tk)
        if self.metrics is not None:
            self.metrics.stop_timer('csp_transform_time')
            self.metrics.increment('num_abf_queries', transformed['stats'].get('abf_queries', 0))
            self.metrics.increment(
                'num_matched_candidates',
                transformed['stats'].get('matched_candidates', len(transformed.get('candidates', []))),
            )

        response = make_message(
            TRANSFORM_RESPONSE,
            self.csp_id,
            msg.sender,
            {
                'ct_id': ct_id,
                'transformed_ctxt': transformed,
                'stats': transformed.get('stats', {}),
            },
            session_id=msg.session_id,
        )
        return self._send_or_return(response)

    def _send_or_return(self, message):
        if self.transport is not None:
            self.transport.send(message)
        return message


class DataUser:
    def __init__(self, scheme, du_id="DU", kgc_id="KGC", csp_id="CSP",
                 metrics=None, transport=None):
        self.scheme = scheme
        self.du_id = du_id
        self.kgc_id = kgc_id
        self.csp_id = csp_id
        self.metrics = metrics
        self.transport = transport
        self.pk = None
        self.key = None
        self.TK_id = None
        self.RK_id = None
        self.last_plaintext = None
        self.last_verification_stats = {}

    def set_public_key(self, pk):
        self.pk = pk

    def request_user_key(self, attr_list, epoch=None, session_id=None):
        message = make_message(
            USER_KEY_REQUEST,
            self.du_id,
            self.kgc_id,
            {
                'du_id': self.du_id,
                'attr_list': list(attr_list),
                'epoch': epoch,
            },
            session_id=session_id,
        )
        return self._send_or_return(message)

    def handle_user_key_response(self, msg):
        self.key = msg.payload['key']
        self.TK_id = None
        self.RK_id = msg.payload['RK_id']
        return self.key

    def request_access(self, ct_id, session_id=None):
        """
        Prototype access request.

        M2 boundary model: DU sends only identity and ciphertext handle. CSP
        looks up TK_id from its KGC-provisioned user_transform_keys table.
        """

        message = make_message(
            ACCESS_REQUEST,
            self.du_id,
            self.csp_id,
            {
                'du_id': self.du_id,
                'ct_id': ct_id,
            },
            session_id=session_id,
        )
        return self._send_or_return(message)

    def handle_transform_response(self, msg):
        if msg.msg_type == ERROR:
            self.last_plaintext = None
            return None
        if self.metrics is not None:
            self.metrics.start_timer('du_final_decrypt_time')
        self.last_plaintext = self.scheme.final_decrypt(
            self.pk,
            msg.payload['transformed_ctxt'],
            self.RK_id,
        )
        self.last_verification_stats = msg.payload['transformed_ctxt'].get(
            'verification_stats',
            {},
        )
        if self.metrics is not None:
            self.metrics.stop_timer('du_final_decrypt_time')
        return self.last_plaintext

    def _send_or_return(self, message):
        if self.transport is not None:
            self.transport.send(message)
        return message
