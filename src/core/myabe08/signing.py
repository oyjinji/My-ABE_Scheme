"""Ed25519 canonical-message adapter. Keys remain distinct by caller role."""
from .encoding import encode, require_bytes
from .errors import AuthenticationError, ContractError


def public_key_bytes(private_key):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ContractError('Ed25519 private key required')
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw,serialization.PublicFormat.Raw)


def private_key_from_seed(seed):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    require_bytes(seed,'Ed25519 seed',32)
    return Ed25519PrivateKey.from_private_bytes(seed)


def new_private_key():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.generate()


def sign_canonical(private_key, domain, *fields):
    if type(domain) is not str or not domain:
        raise ContractError('signature domain required')
    public_key_bytes(private_key)
    return private_key.sign(encode((domain,)+fields))


def verify_canonical(public_key, signature, domain, *fields):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    require_bytes(public_key,'Ed25519 public key',32)
    require_bytes(signature,'Ed25519 signature',64)
    if type(domain) is not str or not domain:
        raise ContractError('signature domain required')
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature,encode((domain,)+fields))
    except (InvalidSignature,ValueError) as exc:
        raise AuthenticationError('signature verification failed') from exc
