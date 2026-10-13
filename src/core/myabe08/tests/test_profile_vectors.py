"""Read-only frozen TEST fixtures. Never regenerate expected bytes in pytest."""
import json
from pathlib import Path

from core.myabe08.crypto import (
    BLS12381Backend, compute_ctx_priv, contextual_token, derive_row_key,
    derive_af_nonce, derive_af_nonce_material, derive_dem_key,
)
from core.myabe08.encoding import (
    encode, decode, UInt32, UInt64, FixedScalarBytes, StructuredRecord,
    encode_attribute, encode_priv_context, encode_token_input, encode_dem_ad,
    encode_fixed_rows, decode_fixed_rows,
)


def test_frozen_profile_v1_vectors():
    v=json.loads((Path(__file__).parent/'vectors/profile_v1.json').read_text())
    inputs={k:bytes.fromhex(value) for k,value in v['inputs'].items() if k.endswith('_hex')}
    enc=v['encoding']
    values={'bytes':b'\0\xff','utf8':'属性','uint32':UInt32(7),'uint64':UInt64(7),
            'scalar32':FixedScalarBytes(bytes(31)+b'\1'),'list':[b'x',UInt32(1)],
            'tuple':(b'x',UInt32(1)),
            'record':StructuredRecord('TestRecord',(('first','a'),('second',UInt64(2))))}
    for key,value in values.items():
        assert encode(value).hex()==enc[key]
        assert decode(bytes.fromhex(enc[key]))==value
    attr=encode_attribute('test','role','analyst');assert attr.hex()==enc['attribute']
    sysid=inputs['sys_id_hex'];pcid=inputs['policy_context_id_hex'];version=v['inputs']['policy_version']
    ctx=compute_ctx_priv(sysid,pcid,version);assert ctx.hex()==v['ctx_priv_hex']
    assert encode_priv_context(sysid,pcid,version).hex()==enc['ctx_priv_input']
    assert encode_token_input(sysid,ctx,attr).hex()==enc['token_input']
    token=contextual_token(inputs['test_key_hex'],sysid,ctx,attr);assert token.hex()==v['token_hex']
    assert derive_row_key(inputs['ctx_af_hex'],token).hex()==v['row_key_hex']
    assert derive_af_nonce_material(inputs['ctx_af_hex'],token).hex()==v['af_nonce_material_hex']
    assert derive_af_nonce(inputs['ctx_af_hex'],token).hex()==v['af_nonce_hex']
    rows=v['fixed_rows'];raw=encode_fixed_rows(tuple(rows['rows']),rows['c_max'],rows['ell'])
    assert raw.hex()==rows['hex']
    assert decode_fixed_rows(bytes.fromhex(rows['hex']),rows['c_max'],rows['ell'])==tuple(rows['rows'])
    assert encode_dem_ad(inputs['ctx_ct_hex']).hex()==enc['dem_ad']
    assert derive_dem_key(inputs['ctx_ct_hex'],inputs['canonical_e_hex']).hex()==v['dem_key_hex']
    b=BLS12381Backend(sysid)
    assert b.hash_to_g1(token).encoded.hex()==v['h0_g1_hex']
    # Fixture IKM really is a canonical subgroup GT, not an arbitrary 576 bytes.
    assert b.deserialize_gt(inputs['canonical_e_hex'],binding=b.binding).encoded==inputs['canonical_e_hex']
