'''
Local in-memory transport for DACP protocol simulation.
'''

from .messages import (
    ACCESS_REQUEST,
    CIPHERTEXT_UPLOAD,
    OPRF_REQUEST,
    OPRF_RESPONSE,
    TK_PROVISION,
    TRANSFORM_RESPONSE,
)
from .serialization import estimate_size


_BYTE_COUNTERS = {
    OPRF_REQUEST: 'oprf_request_bytes',
    OPRF_RESPONSE: 'oprf_response_bytes',
    TK_PROVISION: 'tk_provision_bytes',
    CIPHERTEXT_UPLOAD: 'ciphertext_upload_bytes',
    ACCESS_REQUEST: 'access_request_bytes',
    TRANSFORM_RESPONSE: 'transform_response_bytes',
}

_WIRE_BYTE_COUNTERS = {
    OPRF_REQUEST: 'oprf_request_wire_bytes',
    OPRF_RESPONSE: 'oprf_response_wire_bytes',
    TK_PROVISION: 'tk_provision_wire_bytes',
    CIPHERTEXT_UPLOAD: 'ciphertext_upload_wire_bytes',
    ACCESS_REQUEST: 'access_request_wire_bytes',
    TRANSFORM_RESPONSE: 'transform_response_wire_bytes',
}


class LocalTransport:
    def __init__(self, metrics=None, wire_codec=None, wire_mode=False):
        self.metrics = metrics
        self.wire_codec = wire_codec
        self.wire_mode = bool(wire_mode)
        self._messages = []
        self.log = []
        self.seen_message_ids = set()

    def send(self, message):
        replayed = message.message_id in self.seen_message_ids
        if replayed and self.metrics is not None:
            self.metrics.increment('num_replayed_messages')
        self.seen_message_ids.add(message.message_id)

        expired = False
        if message.expires_at is not None:
            import time
            expired = time.time() > message.expires_at
            if expired and self.metrics is not None:
                self.metrics.increment('num_expired_messages')

        wire_size = 0
        if self.wire_mode:
            if self.wire_codec is None:
                raise RuntimeError('wire_mode=True requires a wire_codec')
            try:
                data = self.wire_codec.encode_message(message)
                wire_size = len(data)
                message = self.wire_codec.decode_message(data)
            except Exception as exc:
                raise RuntimeError(
                    'wire encode/decode failed for {0}: {1}'.format(
                        message.msg_type,
                        exc,
                    )
                )

        self._messages.append(message)
        size = wire_size if self.wire_mode else estimate_size(message)
        self.log.append({
            'message_id': message.message_id,
            'msg_type': message.msg_type,
            'sender': message.sender,
            'receiver': message.receiver,
            'session_id': message.session_id,
            'nonce': message.nonce,
            'seq': message.seq,
            'replayed': replayed,
            'expired': expired,
            'bytes': size,
            'wire_bytes': wire_size,
        })
        if self.metrics is not None:
            self.metrics.increment('num_messages')
            if message.msg_type == TK_PROVISION:
                self.metrics.increment('num_tk_provision')
            counter_name = _BYTE_COUNTERS.get(message.msg_type)
            if counter_name is not None:
                self.metrics.add_bytes(counter_name, size)
            else:
                self.metrics.add_bytes('other_protocol_bytes', size)
            if self.wire_mode:
                self.metrics.increment('wire_num_messages')
                self.metrics.increment('wire_total_bytes', wire_size)
                wire_counter_name = _WIRE_BYTE_COUNTERS.get(message.msg_type)
                if wire_counter_name is not None:
                    self.metrics.increment(wire_counter_name, wire_size)
                else:
                    self.metrics.increment('other_protocol_wire_bytes', wire_size)
        return message

    def receive(self, receiver):
        messages = [msg for msg in self._messages if msg.receiver == receiver]
        self._messages = [msg for msg in self._messages if msg.receiver != receiver]
        return messages

    def receive_one(self, receiver, msg_type=None):
        for index, msg in enumerate(self._messages):
            if msg.receiver != receiver:
                continue
            if msg_type is not None and msg.msg_type != msg_type:
                continue
            return self._messages.pop(index)
        return None

    def clear(self):
        self._messages = []
        self.log = []
        self.seen_message_ids = set()
