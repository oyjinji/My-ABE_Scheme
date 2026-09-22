"""Blind pairing-group OPRF used on both policy and user attributes."""

import hashlib
from time import perf_counter_ns

from charm.toolbox.pairinggroup import G1, ZR

from .encoding import canonical_attribute


class PairingOPRF:
    def __init__(self, group, system="FXDACP", namespace="default"):
        self.group = group
        self.system = system
        self.namespace = namespace

    def canonicalize(self, attribute, epoch, version):
        return canonical_attribute(
            attribute, epoch, version=version, system=self.system,
            namespace=self.namespace,
        )

    def hash_attribute(self, encoded_attribute):
        # Charm 0.63 may treat embedded NULs in a bytes hash input as a C
        # string terminator.  Hash the canonical bytes first and pass an ASCII
        # domain-separated digest to Charm.
        digest = hashlib.sha256(b"FXDACP-H1-v1" + encoded_attribute).hexdigest()
        return self.group.hash("FXDACP-H1-v1::" + digest, G1)

    def blind(self, encoded_attributes):
        blinded, state = [], []
        for encoded in encoded_attributes:
            blind = self._random_nonzero()
            blinded.append(self.hash_attribute(encoded) ** blind)
            state.append(blind)
        return blinded, state

    def evaluate(self, blinded, kappa):
        return [item ** kappa for item in blinded]

    def unblind(self, evaluated, state):
        if len(evaluated) != len(state):
            raise ValueError("OPRF response length mismatch")
        return [item ** (1 / blind) for item, blind in zip(evaluated, state)]

    def batch_tokens(self, attributes, epoch, version, kappa, metrics=None):
        started = perf_counter_ns()
        encoded = [self.canonicalize(attr, epoch, version) for attr in attributes]
        after_encode = perf_counter_ns()
        blinded, state = self.blind(encoded)
        after_blind = perf_counter_ns()
        evaluated = self.evaluate(blinded, kappa)
        after_evaluate = perf_counter_ns()
        tokens = self.unblind(evaluated, state)
        after_unblind = perf_counter_ns()
        # Force serialization/token-id work into its separately reported phase.
        for token in tokens:
            self.token_bytes(token)
        after_map = perf_counter_ns()
        if metrics is not None:
            metrics.set("canonical_encoding_ns", after_encode - started)
            metrics.set("oprf_blind_ns", after_blind - after_encode)
            metrics.set("oprf_evaluate_ns", after_evaluate - after_blind)
            metrics.set("oprf_unblind_ns", after_unblind - after_evaluate)
            metrics.set("token_to_group_ns", after_map - after_unblind)
            metrics.set("token_generation_count", len(attributes))
        return encoded, tokens

    def direct_token(self, attribute, epoch, version, kappa):
        return self.hash_attribute(self.canonicalize(attribute, epoch, version)) ** kappa

    def token_bytes(self, token):
        return self.group.serialize(token)

    def token_id(self, token):
        return hashlib.sha256(self.token_bytes(token)).digest()

    def H0(self, token):
        digest = hashlib.sha256(self.token_bytes(token)).hexdigest()
        return self.group.hash("FXDACP-H0-v1::" + digest, G1)

    def _random_nonzero(self):
        value = self.group.random(ZR)
        while value == 0:
            value = self.group.random(ZR)
        return value
