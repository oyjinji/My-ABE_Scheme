"""Bounded, one-request-per-connection canonical RPC transport.

TCP transport is NOT an attested or authenticated secure channel. Private
records require a separate TEST-only encrypted session until RA is available.
"""
import secrets
import socket
import struct
from time import perf_counter_ns

from ..encoding import decode, encode, require_bytes
from ..errors import ContractError

MAGIC=b'MY08'
VERSION=1
HEADER=struct.Struct('>4sBB16sI')
HEALTH=1
PROFILE_INFO=2
DEBUG_TEST_BOOTSTRAP=3
OPEN_TEST_SESSION=4
POLICY_TOKENIZE=5
TEST_REGISTER_USER=6
USER_AUTHORIZE=7
REV_STATE_UPDATE=8
TEST_COMMIT_HEAD=9
TEST_SHUTDOWN=10
RA_QUOTE_PROBE=11
RA_SESSION_OPEN=12
RA_SESSION_ACTIVATE=13
RA_DUMMY_PROVISION=14
TEST_STATE_OBSERVE=15
TEST_STATE_FAULT=16
TYPES=frozenset(range(1,17))
LIMITS={HEALTH:1024,PROFILE_INFO:1024,DEBUG_TEST_BOOTSTRAP:4096,
        OPEN_TEST_SESSION:4096,POLICY_TOKENIZE:256*1024,
        TEST_REGISTER_USER:256*1024,USER_AUTHORIZE:2*1024*1024,
        REV_STATE_UPDATE:256*1024,TEST_COMMIT_HEAD:4096,TEST_SHUTDOWN:1024,
        RA_QUOTE_PROBE:1024,RA_SESSION_OPEN:1024,
        RA_SESSION_ACTIVATE:4096,RA_DUMMY_PROVISION:4096,
        TEST_STATE_OBSERVE:1024,TEST_STATE_FAULT:1024}
MAX_RESPONSE=2*1024*1024
ERROR_CODES=frozenset(('INVALID_REQUEST','AUTH_FAILED','STATE_UNAVAILABLE',
                       'REVOKED','UNSUPPORTED','INTERNAL_ERROR'))


def _read_exact(sock,length):
    chunks=[]
    while length:
        chunk=sock.recv(length)
        if not chunk: raise ContractError('truncated RPC frame')
        chunks.append(chunk);length-=len(chunk)
    return b''.join(chunks)


def frame(message_type,request_id,payload):
    if type(message_type) is not int or message_type not in TYPES:
        raise ContractError('unknown RPC type')
    require_bytes(request_id,'RPC request ID',16)
    require_bytes(payload,'RPC payload')
    if len(payload)>LIMITS[message_type]: raise ContractError('RPC payload limit')
    value=decode(payload)
    if encode(value)!=payload: raise ContractError('noncanonical RPC payload')
    return HEADER.pack(MAGIC,VERSION,message_type,request_id,len(payload))+payload


def read_request(sock):
    raw=_read_exact(sock,HEADER.size)
    magic,version,message_type,request_id,length=HEADER.unpack(raw)
    if magic!=MAGIC or version!=VERSION or message_type not in TYPES:
        raise ContractError('RPC magic/version/type rejected')
    if length>LIMITS[message_type]: raise ContractError('RPC payload limit')
    payload=_read_exact(sock,length)
    if sock.recv(1): raise ContractError('RPC trailing bytes')
    value=decode(payload)
    if encode(value)!=payload: raise ContractError('noncanonical RPC payload')
    return message_type,request_id,value


def write_response(sock,message_type,request_id,value,*,error=False):
    require_bytes(request_id,'RPC request ID',16)
    if error:
        if value not in ERROR_CODES: raise ContractError('unknown error code')
        body=encode(('MYABE08-RPC-ERROR',value))
        response_type=0x7f
    else:
        body=encode(value)
        response_type=message_type|0x80
    if len(body)>MAX_RESPONSE: raise ContractError('RPC response limit')
    sock.sendall(HEADER.pack(MAGIC,VERSION,response_type,request_id,len(body))+body)


class RpcError(Exception):
    def __init__(self,code):
        self.code=code
        super().__init__(code)


def call(address,message_type,value,*,timeout=15,transport_timings_ns=None):
    body=encode(value)
    request_id=secrets.token_bytes(16)
    outgoing=frame(message_type,request_id,body)
    with socket.create_connection(address,timeout=timeout) as sock:
        sock.settimeout(timeout)
        send_started=perf_counter_ns() if transport_timings_ns is not None else None
        sock.sendall(outgoing)
        if transport_timings_ns is not None:
            transport_timings_ns['rpc_send_ns']=perf_counter_ns()-send_started
            transport_timings_ns['rpc_send_bytes']=len(outgoing)
        sock.shutdown(socket.SHUT_WR)
        if transport_timings_ns is not None:
            receive_started=perf_counter_ns()
        raw=_read_exact(sock,HEADER.size)
        magic,version,kind,received_id,length=HEADER.unpack(raw)
        if (magic!=MAGIC or version!=VERSION or received_id!=request_id or
                length>MAX_RESPONSE or kind not in (message_type|0x80,0x7f)):
            raise ContractError('RPC response header rejected')
        payload=_read_exact(sock,length)
        if transport_timings_ns is not None:
            transport_timings_ns['rpc_receive_ns']=perf_counter_ns()-receive_started
            transport_timings_ns['rpc_receive_bytes']=HEADER.size+len(payload)
        if sock.recv(1): raise ContractError('RPC response trailing bytes')
    result=decode(payload)
    if encode(result)!=payload: raise ContractError('noncanonical RPC response')
    if kind==0x7f:
        if (type(result) is not tuple or len(result)!=2 or
                result[0]!='MYABE08-RPC-ERROR' or result[1] not in ERROR_CODES):
            raise ContractError('malformed RPC error')
        raise RpcError(result[1])
    return result
