'''
Message envelopes for the local DACP protocol simulation.
'''

import time
import uuid
from dataclasses import dataclass
from typing import Optional

USER_KEY_REQUEST = 'USER_KEY_REQUEST'
USER_KEY_RESPONSE = 'USER_KEY_RESPONSE'
OPRF_REQUEST = 'OPRF_REQUEST'
OPRF_RESPONSE = 'OPRF_RESPONSE'
CIPHERTEXT_UPLOAD = 'CIPHERTEXT_UPLOAD'
ACCESS_REQUEST = 'ACCESS_REQUEST'
TRANSFORM_RESPONSE = 'TRANSFORM_RESPONSE'
TK_PROVISION = 'TK_PROVISION'
ERROR = 'ERROR'


@dataclass
class MessageEnvelope:
    message_id: str
    msg_type: str
    sender: str
    receiver: str
    session_id: str
    nonce: str
    seq: int
    expires_at: Optional[float]
    payload: dict
    timestamp: float


def new_session_id():
    return uuid.uuid4().hex


def new_nonce():
    return uuid.uuid4().hex


def make_message(msg_type, sender, receiver, payload=None,
                 session_id=None, nonce=None, timestamp=None,
                 message_id=None, seq=0, expires_at=None):
    return MessageEnvelope(
        message_id=message_id or new_session_id(),
        msg_type=msg_type,
        sender=sender,
        receiver=receiver,
        session_id=session_id or new_session_id(),
        nonce=nonce or new_nonce(),
        seq=seq,
        expires_at=expires_at,
        payload=payload or {},
        timestamp=time.time() if timestamp is None else timestamp,
    )
