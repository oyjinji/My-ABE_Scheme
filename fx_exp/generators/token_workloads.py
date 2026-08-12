import hashlib
import random


def derive_seed(master_seed, *parts):
    material = "|".join([str(master_seed)] + [str(part) for part in parts]).encode("utf-8")
    return int.from_bytes(hashlib.sha256(material).digest()[:8], "big")


def token_entries(u, seed, posting_lists=None):
    rng = random.Random(seed)
    tokens = []
    for index in range(u):
        salt = rng.getrandbits(128).to_bytes(16, "big")
        tokens.append(hashlib.sha256(b"FXEXP-token" + index.to_bytes(8, "big") + salt).digest())
    if posting_lists is None:
        posting_lists = [[index + 1] for index in range(u)]
    if len(posting_lists) != u:
        raise ValueError("posting list count must equal token count")
    return {token: list(rows) for token, rows in zip(tokens, posting_lists)}


def nonmember_tokens(count, seed):
    rng = random.Random(seed)
    return [hashlib.sha256(b"FXEXP-nonmember" + rng.getrandbits(256).to_bytes(32, "big")).digest()
            for _ in range(count)]
