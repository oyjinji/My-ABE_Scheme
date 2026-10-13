import struct
import pytest
from core.myabe08.encoding import encode_fixed_rows, decode_fixed_rows
from core.myabe08.errors import ContractError


def test_exact_fixed_payload_and_uint32_endpoint():
    raw = encode_fixed_rows((1, 3, 7), 5, 7)
    assert raw.hex() == '000000030000000100000003000000070000000000000000'
    assert len(raw) == 4*(5+1)
    assert decode_fixed_rows(raw, 5, 7) == (1, 3, 7)
    assert decode_fixed_rows(encode_fixed_rows((2**32-1,), 1, 2**32-1),1,2**32-1) == (2**32-1,)


@pytest.mark.parametrize('rows,cmax,ell', [
    ((),3,7), ((1,2),1,7), ((0,),3,7), ((2,1),3,7), ((1,1),3,7),
    ((8,),3,7), ((True,),3,7), ((1,),0,7), ((1,),3,0), ((1,),3,2**32),
    ((1,),True,7), ((1,),3,True), ((1.0,),3,7), ({1},3,7),
])
def test_noncanonical_rows_fail_closed(rows,cmax,ell):
    with pytest.raises(ContractError):
        encode_fixed_rows(rows,cmax,ell)


@pytest.mark.parametrize('fields', [
    (0,0,0,0), (4,1,2,3), (1,1,0,2), (2,2,1,0),
    (2,1,1,0), (1,0,0,0), (1,8,0,0),
])
def test_decoder_checks_length_padding_order_and_range(fields):
    with pytest.raises(ContractError):
        decode_fixed_rows(struct.pack('>4I',*fields),3,7)


def test_exact_input_size_required():
    raw = encode_fixed_rows((1,),3,7)
    for bad in (raw[:-1],raw+b'\0',bytearray(raw)):
        with pytest.raises(ContractError):
            decode_fixed_rows(bad,3,7)
