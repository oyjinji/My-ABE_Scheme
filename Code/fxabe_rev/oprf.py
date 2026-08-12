"""Pairing-group OPRF used for two-sided anonymous attribute tokens."""

import hashlib
from charm.toolbox.pairinggroup import G1

from .encoding import canonical_attribute, encode, encode_group


class PairingOPRF:
    def __init__(self, group):
        self.group = group

    def H1(self, encoded_attribute):
        digest = hashlib.sha256(
            encode(["FXABE-H1-v1", encoded_attribute])
        ).hexdigest()
        return self.group.hash("FXABE-H1-" + digest, G1)

    def H0(self, token):
        digest = hashlib.sha256(
            encode(["FXABE-H0-v1", encode_group(self.group, token)])
        ).hexdigest()
        return self.group.hash("FXABE-H0-" + digest, G1)

    def direct_token(self, attribute, privacy_epoch, version, kappa):
        chi = canonical_attribute(attribute, privacy_epoch, version)
        return self.H1(chi) ** kappa

    def blind(self, attribute, privacy_epoch, version, scalar_source):
        chi = canonical_attribute(attribute, privacy_epoch, version)
        blind = scalar_source.scalar(nonzero=True)
        return chi, self.H1(chi) ** blind, blind

    @staticmethod
    def evaluate(blinded, kappa):
        return blinded ** kappa

    @staticmethod
    def unblind(evaluated, blind):
        return evaluated ** (1 / blind)

    def token_bytes(self, token):
        return self.group.serialize(token)
