'''
Local protocol simulation layer for DACP.

This package models KGC, DO, CSP, and DU message exchange around the
algorithm-level DACPCPABE implementation. It is intentionally local and
benchmark-oriented: no HTTP, sockets, persistent queues, or production trust
checks are performed here.
'''

from .messages import (
    ACCESS_REQUEST,
    CIPHERTEXT_UPLOAD,
    ERROR,
    OPRF_REQUEST,
    OPRF_RESPONSE,
    TK_PROVISION,
    TRANSFORM_RESPONSE,
    USER_KEY_REQUEST,
    USER_KEY_RESPONSE,
    MessageEnvelope,
    make_message,
    new_nonce,
    new_session_id,
)
from .metrics import ProtocolMetrics
from .roles import KGC, CloudServiceProvider, DataOwner, DataUser
from .transport import LocalTransport
from .wire import WireCodec

__all__ = [
    'ACCESS_REQUEST',
    'CIPHERTEXT_UPLOAD',
    'ERROR',
    'OPRF_REQUEST',
    'OPRF_RESPONSE',
    'TK_PROVISION',
    'TRANSFORM_RESPONSE',
    'USER_KEY_REQUEST',
    'USER_KEY_RESPONSE',
    'MessageEnvelope',
    'make_message',
    'new_nonce',
    'new_session_id',
    'ProtocolMetrics',
    'KGC',
    'CloudServiceProvider',
    'DataOwner',
    'DataUser',
    'LocalTransport',
    'WireCodec',
]
