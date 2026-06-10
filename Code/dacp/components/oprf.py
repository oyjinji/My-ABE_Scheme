'''
Prototype OPRF component for DACP.

PrototypeOPRF keeps the current local benchmark behavior and message shape:
protocol messages carry opaque blinded handles, not plaintext attributes. This
is not a real OPRF. Replace this component with one implementing
B_i = H(attr_i)^b_i, R_i = B_i^kappa, tau_i = R_i^(1/b_i) for production.
'''

import hashlib

from charm.toolbox.pairinggroup import G1, ZR


class OPRFAdapter:
    def blind(self, attrs, **kwargs):
        raise NotImplementedError

    def evaluate(self, blinded_items, kappa, **kwargs):
        raise NotImplementedError

    def unblind(self, evaluated_items, blind_state=None, **kwargs):
        raise NotImplementedError

    def token_id(self, token, **kwargs):
        raise NotImplementedError


class PrototypeOPRF(OPRFAdapter):
    def __init__(self, group, epoch_mode=False, namespace='dacp'):
        self.group = group
        self.epoch_mode = bool(epoch_mode)
        self.namespace = namespace

    def blind(self, attrs, **kwargs):
        nonce = kwargs.get('nonce', '')
        blinded_items = []
        blind_state = {'attrs': {}, 'nonce': nonce, 'epoch': kwargs.get('epoch')}
        for index, attr in enumerate(attrs):
            handle = hashlib.sha256(
                ('{0}::prototype-blind::{1}::{2}'.format(
                    self.namespace, attr, nonce
                )).encode('utf-8')
            ).hexdigest()
            blinded_items.append({'item_index': index, 'B_i': handle})
            # Local-only state; never put this in MessageEnvelope payload.
            blind_state['attrs'][index] = attr
        return blinded_items, blind_state

    def evaluate(self, blinded_items, kappa, **kwargs):
        epoch = kwargs.get('epoch')
        evaluated = []
        for item in blinded_items:
            digest = hashlib.sha256(
                ('{0}::prototype-oprf-eval::{1}::{2}'.format(
                    self.namespace, item.get('B_i'), epoch
                )).encode('utf-8')
            ).hexdigest()
            evaluated.append({'item_index': item.get('item_index'), 'R_i': digest})
        return evaluated

    def unblind(self, evaluated_items, blind_state=None, **kwargs):
        # Real OPRF would divide out the blinding factor. Here we only return
        # opaque evaluated handles; algorithm-level encrypt still computes
        # tokens locally until a real OPRF is wired through.
        return {
            'evaluated_items': list(evaluated_items),
            'blind_state': blind_state or {},
            'prototype': True,
        }

    def token_from_attr(self, attr, kappa, epoch=None):
        base = self.group.hash(
            '{0}::H1::{1}'.format(self.namespace, self._chi_epoch(attr, epoch)),
            G1,
        )
        return base ** kappa

    def token_id(self, token, **kwargs):
        try:
            data = self.group.serialize(token)
        except Exception:
            data = repr(token).encode('utf-8')
        return hashlib.sha256(data).hexdigest()

    def H0(self, token):
        return self.group.hash(
            '{0}::H0::{1}'.format(self.namespace, self.token_id(token)),
            G1,
        )

    def _chi_epoch(self, attr, epoch):
        if self.epoch_mode or epoch is not None:
            return '{0}|epoch={1}'.format(attr, epoch)
        return str(attr)


class BlindPairingOPRF(OPRFAdapter):
    """
    Pairing-group blind OPRF adapter.

    This adapter implements the local cryptographic shape of:
        DO:  B_i = H(attr_i)^b_i
        KGC: R_i = B_i^kappa
        DO:  tau_i = R_i^(1 / b_i)

    It is still a prototype-real adapter: transport, subgroup checks, and wire
    encoding are outside this class. Message payloads contain B_i/R_i group
    elements, while attr is kept only in blind_state on the DO side.
    """

    def __init__(self, group, hash_prefix="dacp::oprf::H1", epoch_mode=False):
        self.group = group
        self.hash_prefix = hash_prefix
        self.epoch_mode = bool(epoch_mode)

    def blind(self, attrs, **kwargs):
        epoch = kwargs.get('epoch')
        blinded_items = []
        blind_state = {}
        for index, attr in enumerate(attrs):
            b_i = self._random_nonzero_zr()
            X_i = self._hash_attr(attr, epoch)
            B_i = X_i ** b_i
            blinded_items.append({
                'item_index': index,
                'B_i': B_i,
            })
            # Local-only DO state. This must never enter MessageEnvelope.
            blind_state[index] = {
                'b_i': b_i,
                'attr': attr,
                'epoch': epoch,
            }
        return blinded_items, blind_state

    def evaluate(self, blinded_items, kappa, **kwargs):
        evaluated_items = []
        for item in blinded_items:
            evaluated_items.append({
                'item_index': item.get('item_index'),
                'R_i': item['B_i'] ** kappa,
            })
        return evaluated_items

    def unblind(self, evaluated_items, blind_state=None, **kwargs):
        blind_state = blind_state or {}
        tokens = []
        for item in evaluated_items:
            index = item.get('item_index')
            state = blind_state.get(index)
            if state is None:
                continue
            tau_i = item['R_i'] ** (1 / state['b_i'])
            tokens.append({
                'item_index': index,
                'tau_i': tau_i,
                'token_id': self.token_id(tau_i),
            })
        return tokens

    def token_from_attr(self, attr, kappa, epoch=None):
        return self._hash_attr(attr, epoch) ** kappa

    def token_id(self, token, **kwargs):
        try:
            data = self.group.serialize(token)
        except Exception:
            # Fallback only for local benchmark accounting; real wire formats
            # should serialize group elements explicitly and canonically.
            data = repr(token).encode('utf-8')
        return hashlib.sha256(data).hexdigest()

    def H0(self, token):
        return self.group.hash('dacp::H0::' + self.token_id(token), G1)

    def _hash_attr(self, attr, epoch=None):
        return self.group.hash(
            '{0}::{1}'.format(self.hash_prefix, self._chi_epoch(attr, epoch)),
            G1,
        )

    def _chi_epoch(self, attr, epoch):
        if self.epoch_mode or epoch is not None:
            return '{0}|epoch={1}'.format(attr, epoch)
        return str(attr)

    def _random_nonzero_zr(self):
        value = self.group.random(ZR)
        while value == 0:
            value = self.group.random(ZR)
        return value
