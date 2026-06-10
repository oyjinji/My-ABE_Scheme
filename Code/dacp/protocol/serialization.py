'''
Rough size estimation for local protocol messages.
'''

import pickle
from dataclasses import fields, is_dataclass


def estimate_size(obj):
    """
    Return a coarse byte size for benchmark accounting.

    Charm elements and nested objects are first tried with pickle. If pickle
    cannot serialize a value, the function falls back recursively and finally
    to repr(). This is a measurement helper, not a wire encoding.
    """

    try:
        return len(pickle.dumps(obj, protocol=pickle.HIGHEST_PROTOCOL))
    except Exception:
        pass

    if is_dataclass(obj):
        total = 0
        for field in fields(obj):
            total += estimate_size(field.name)
            total += estimate_size(getattr(obj, field.name))
        return total
    if isinstance(obj, dict):
        return sum(estimate_size(k) + estimate_size(v) for k, v in obj.items())
    if isinstance(obj, (list, tuple, set)):
        return sum(estimate_size(item) for item in obj)
    if isinstance(obj, bytes):
        return len(obj)
    if isinstance(obj, str):
        return len(obj.encode('utf-8'))
    if isinstance(obj, int):
        return max(1, (obj.bit_length() + 7) // 8)
    if isinstance(obj, float):
        return 8
    if obj is None:
        return 0
    return len(repr(obj).encode('utf-8'))
