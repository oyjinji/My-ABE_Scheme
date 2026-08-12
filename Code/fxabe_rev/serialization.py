"""Portable recursive serialization for tests and canonical size accounting."""

import base64
import json


def _wire(value, group):
    if isinstance(value, bytes):
        return {"@bytes": base64.b64encode(value).decode("ascii")}
    if isinstance(value, tuple):
        return {"@tuple": [_wire(x, group) for x in value]}
    if isinstance(value, list):
        return [_wire(x, group) for x in value]
    if isinstance(value, dict):
        return {str(k): _wire(v, group) for k, v in value.items()}
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    try:
        raw = group.serialize(value)
        return {"@group": base64.b64encode(raw).decode("ascii")}
    except Exception as exc:
        raise TypeError("not serializable: %s" % type(value).__name__) from exc


def _unwire(value, group):
    if isinstance(value, list):
        return [_unwire(x, group) for x in value]
    if isinstance(value, dict):
        if set(value) == {"@bytes"}:
            return base64.b64decode(value["@bytes"])
        if set(value) == {"@group"}:
            return group.deserialize(base64.b64decode(value["@group"]))
        if set(value) == {"@tuple"}:
            return tuple(_unwire(x, group) for x in value["@tuple"])
        return {k: _unwire(v, group) for k, v in value.items()}
    return value


def dumps(value, group):
    return json.dumps(_wire(value, group), sort_keys=True, separators=(",", ":")).encode("utf-8")


def loads(data, group):
    return _unwire(json.loads(data.decode("utf-8")), group)


def serialized_size(value, group):
    return len(dumps(value, group))
