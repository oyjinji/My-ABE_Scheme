"""KeyGen and PrivacyKeyUpt entry points."""

def KeyGen(scheme, *args, **kwargs):
    return scheme.keygen(*args, **kwargs)


def PrivacyKeyUpt(scheme, *args, **kwargs):
    return scheme.privacy_key_upt(*args, **kwargs)
