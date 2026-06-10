'''
Replaceable prototype components for DACP.

The default components are deliberately benchmark-oriented. They preserve the
current runnable DACP behavior while making future swaps for real OPRF, ABF,
AEAD, signatures, and certificates localized to this package.
'''

from .abf import ABFAdapter, PrototypeABF
from .certificate import CertificateAuthority, PrototypeCertificateAuthority
from .oprf import BlindPairingOPRF, OPRFAdapter, PrototypeOPRF
from .signature import Ed25519Signature, PrototypeHashSignature, SignatureAdapter
from .symmetric import AESGCMEnvelope, PrototypeGTEnvelope, SymmetricEnvelope

__all__ = [
    'ABFAdapter',
    'PrototypeABF',
    'CertificateAuthority',
    'PrototypeCertificateAuthority',
    'OPRFAdapter',
    'BlindPairingOPRF',
    'PrototypeOPRF',
    'Ed25519Signature',
    'PrototypeHashSignature',
    'SignatureAdapter',
    'AESGCMEnvelope',
    'PrototypeGTEnvelope',
    'SymmetricEnvelope',
]
