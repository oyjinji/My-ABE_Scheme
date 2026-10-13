"""Strict wire-format tests, not arbitrary Python object serialization."""
import struct
from dataclasses import dataclass

import pytest

from core.myabe08.encoding import (
    FixedScalarBytes, StructuredRecord, UInt32, UInt64, decode, encode,
)
from core.myabe08.errors import ContractError


@pytest.mark.parametrize('value', [
    b'', b'\x00|\xff', '', '属性\x00', UInt32(0), UInt32(2**32-1),
    UInt64(0), UInt64(2**64-1), FixedScalarBytes(bytes(32)), [], (),
    [b'a', UInt32(1)], (b'a', UInt64(1)),
    StructuredRecord('R', (('a', UInt32(1)), ('b', [b'x', 'y']))),
])
def test_roundtrip_and_same_semantic_value_same_encoding(value):
    encoded = encode(value)
    assert decode(encoded) == value
    assert encode(decode(encoded)) == encoded


def test_type_and_length_separation():
    values = [b'1', '1', UInt32(1), UInt64(1), FixedScalarBytes(bytes(31)+b'\x01'),
              [UInt32(1)], (UInt32(1),), StructuredRecord('R', (('x', UInt32(1)),))]
    assert len(set(map(encode, values))) == len(values)
    assert encode((b'ab', b'c')) != encode((b'a', b'bc'))
    assert encode(('a\x00b', 'c')) != encode(('a', 'b\x00c'))
    assert encode(StructuredRecord('R', (('a', b'1'), ('b', b'2')))) != encode(
        StructuredRecord('R', (('b', b'2'), ('a', b'1'))))


@pytest.mark.parametrize('value', [None, True, 1, -1, 1.5, {}, {'a': b'b'}, bytearray(b'a'), {1}])
def test_no_implicit_coercion_or_generic_objects(value):
    with pytest.raises(ContractError):
        encode(value)


def test_record_constructor_is_explicit():
    for fields in ({'a': b'x'}, (('a', b'x'), ('a', b'y'))):
        with pytest.raises(ContractError):
            StructuredRecord('R', fields)
    with pytest.raises(ContractError):
        UInt32(True)
    with pytest.raises(ContractError):
        UInt32(2**32)
    with pytest.raises(ContractError):
        UInt64(-1)
    with pytest.raises(ContractError):
        FixedScalarBytes(bytes(31))
    with pytest.raises(ContractError):
        encode('\ud800')


@pytest.mark.parametrize('bad', [
    b'', b'\x01', b'\x01\x00\x00\x00\x01',
    b'\xff\x00\x00\x00\x00', b'\x02\x00\x00\x00\x01\xff',
    b'\x03\x00\x00\x00\x01\x01',  # uint32 cannot use short form
    b'\x04\x00\x00\x00\x09'+bytes(9),
    b'\x05\x00\x00\x00\x1f'+bytes(31),
    b'\x06\x00\x00\x00\x04\xff\xff\xff\xff',
    b'\x07\x00\x00\x00\x04\x00\x00\x00\x01',
    encode(b'ok')+b'\0',
    b'\x06'+struct.pack('>I', 4+len(encode(b'a')))+bytes(4)+encode(b'a'),
])
def test_strict_decoder_rejects_malformed(bad):
    with pytest.raises(ContractError):
        decode(bad)


def test_truncation_at_every_offset_and_depth_limits():
    data = encode(StructuredRecord('R', (('x', ('UTF8', UInt32(7))),)))
    for end in range(len(data)):
        with pytest.raises(ContractError):
            decode(data[:end])
    obj = b'x'
    for _ in range(66):
        obj = (obj,)
    with pytest.raises(ContractError):
        encode(obj)
    data = encode(b'x')
    for _ in range(66):
        data = b'\x07'+struct.pack('>I',4+len(data))+struct.pack('>I',1)+data
    with pytest.raises(ContractError):
        decode(data)
