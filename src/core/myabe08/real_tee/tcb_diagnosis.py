"""Read-only matching of parsed Intel PCK/QE TCB levels; no cache mutation."""
from datetime import datetime, timezone

from ..errors import ContractError


def collateral_current(document, now=None):
    if now is None:
        now=datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ContractError('timezone-aware diagnostic time required')
    try:
        issued=datetime.fromisoformat(document['issueDate'].replace('Z','+00:00'))
        expires=datetime.fromisoformat(document['nextUpdate'].replace('Z','+00:00'))
    except (KeyError,ValueError,TypeError) as exc:
        raise ContractError('collateral dates malformed') from exc
    return issued<=now<expires


def match_platform_tcb_level(tcb_info, components, pce_svn):
    """Intel's ordered first matching level using 16 PCK component SVNs."""
    if (type(components) not in (tuple,list) or len(components)!=16 or
            any(type(x) is not int or not 0<=x<=255 for x in components) or
            type(pce_svn) is not int or not 0<=pce_svn<=65535):
        raise ContractError('PCK TCB vector malformed')
    for level in tcb_info['tcbLevels']:
        tcb=level['tcb']
        required=tcb['sgxtcbcomponents']
        if len(required)!=16:
            raise ContractError('Intel TCB level vector malformed')
        if (pce_svn>=tcb['pcesvn'] and
                all(actual>=entry['svn'] for actual,entry in zip(components,required))):
            return level
    raise ContractError('no matching Intel platform TCB level')


def match_qe_tcb_level(identity, *, mrsigner, product_id, svn):
    if (type(mrsigner) is not str or type(product_id) is not int or
            type(svn) is not int or svn<0 or
            identity['mrsigner'].upper()!=mrsigner.upper() or
            identity['isvprodid']!=product_id):
        raise ContractError('QE identity mismatch')
    for level in identity['tcbLevels']:
        if svn>=level['tcb']['isvsvn']:
            return level
    raise ContractError('no matching QE TCB level')
