'''
Stable JSON wire codec for DACP local protocol messages.

The codec is intentionally strict: unsupported objects raise TypeError instead
of silently falling back to repr(). Charm group elements are serialized with
PairingGroup.serialize() and restored with PairingGroup.deserialize().
'''

import base64
import json
from dataclasses import fields, is_dataclass

from charm.toolbox.pairinggroup import G1, G2, GT, ZR

from .messages import MessageEnvelope


_GROUP_TYPE_NAMES = {
    ZR: 'ZR',
    G1: 'G1',
    G2: 'G2',
    GT: 'GT',
}


class WireCodec:
    def __init__(self, group=None):
        self.group = group

    def encode_obj(self, obj):
        if is_dataclass(obj):
            return {
                '__dacp_type__': obj.__class__.__name__,
                'fields': {
                    field.name: self.encode_obj(getattr(obj, field.name))
                    for field in fields(obj)
                },
            }
        if self._is_group_element(obj):
            return self.encode_group_element(obj)
        if isinstance(obj, bytes):
            return {
                '__dacp_type__': 'bytes',
                'encoding': 'base64',
                'value': base64.b64encode(obj).decode('ascii'),
            }
        if isinstance(obj, bytearray):
            return self.encode_obj(bytes(obj))
        if isinstance(obj, tuple):
            return {
                '__dacp_type__': 'tuple',
                'items': [self.encode_obj(item) for item in obj],
            }
        if isinstance(obj, list):
            return [self.encode_obj(item) for item in obj]
        if isinstance(obj, dict):
            items = [
                [self.encode_obj(key), self.encode_obj(value)]
                for key, value in obj.items()
            ]
            return {
                '__dacp_type__': 'dict',
                'items': items,
            }
        if isinstance(obj, (str, int, float, bool)) or obj is None:
            return obj
        raise TypeError('WireCodec cannot encode object of type {0}'.format(type(obj).__name__))

    def decode_obj(self, obj):
        if isinstance(obj, list):
            return [self.decode_obj(item) for item in obj]
        if not isinstance(obj, dict) or '__dacp_type__' not in obj:
            return obj

        kind = obj['__dacp_type__']
        if kind == 'bytes':
            return base64.b64decode(obj['value'].encode('ascii'))
        if kind == 'tuple':
            return tuple(self.decode_obj(item) for item in obj['items'])
        if kind == 'dict':
            return {
                self.decode_obj(key): self.decode_obj(value)
                for key, value in obj['items']
            }
        if kind == 'group_element':
            return self.decode_group_element(obj)
        if kind == 'MessageEnvelope':
            decoded = {
                key: self.decode_obj(value)
                for key, value in obj['fields'].items()
            }
            return MessageEnvelope(**decoded)
        raise TypeError('WireCodec cannot decode DACP type {0}'.format(kind))

    def encode_message(self, msg):
        encoded = self.encode_obj(msg)
        return json.dumps(
            encoded,
            sort_keys=True,
            separators=(',', ':'),
        ).encode('utf-8')

    def decode_message(self, data):
        if not isinstance(data, bytes):
            raise TypeError('decode_message expects bytes')
        obj = json.loads(data.decode('utf-8'))
        msg = self.decode_obj(obj)
        if not isinstance(msg, MessageEnvelope):
            raise TypeError('decoded object is not a MessageEnvelope')
        return msg

    def encoded_size(self, obj):
        if isinstance(obj, MessageEnvelope):
            return len(self.encode_message(obj))
        return len(json.dumps(
            self.encode_obj(obj),
            sort_keys=True,
            separators=(',', ':'),
        ).encode('utf-8'))

    def encode_group_element(self, x):
        if self.group is None:
            raise TypeError('WireCodec requires a PairingGroup to encode group elements')
        try:
            serialized = self.group.serialize(x)
        except Exception as exc:
            raise TypeError('cannot serialize group element: {0}'.format(exc))
        return {
            '__dacp_type__': 'group_element',
            'group_type': _GROUP_TYPE_NAMES.get(getattr(x, 'type', None), 'UNKNOWN'),
            'encoding': 'charm-base64',
            'value': base64.b64encode(serialized).decode('ascii'),
        }

    def decode_group_element(self, encoded):
        if self.group is None:
            raise TypeError('WireCodec requires a PairingGroup to decode group elements')
        if encoded.get('encoding') != 'charm-base64':
            raise TypeError('unsupported group element encoding {0}'.format(encoded.get('encoding')))
        data = base64.b64decode(encoded['value'].encode('ascii'))
        return self.group.deserialize(data)

    def _is_group_element(self, obj):
        return hasattr(obj, 'type') and obj.__class__.__name__ == 'Element'
