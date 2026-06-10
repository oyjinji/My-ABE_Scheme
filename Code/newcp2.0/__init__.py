'''
Legacy NewCP2.0 wrapper for the DACP prototype.

| Notes: The old newcp2.0 skeleton is kept as a runnable transition scheme.
| Notes: The implementation now delegates to Code.dacp.DACPCPABE so its fields
|        and flow align with prompt_doc/ABE-Scheme.md.
| Notes: This remains a prototype / benchmark-oriented implementation; see
|        Code/dacp/__init__.py for placeholder details.
|
| type:           ciphertext-policy attribute-based encryption
| setting:        Pairing
'''

from ..dacp import DACPCPABE

debug = False


class NewCP20CPABE(DACPCPABE):
    def __init__(self, group_obj, dummy_factor=1, abf_size=4096,
                 hash_count=3, beta=32, epoch_mode=False, verbose=False):
        DACPCPABE.__init__(
            self,
            group_obj,
            dummy_factor=dummy_factor,
            abf_size=abf_size,
            hash_count=hash_count,
            beta=beta,
            epoch_mode=epoch_mode,
            verbose=verbose,
        )
        self.name = "NewCP2.0 CP-ABE"
        self.legacy_name = "newcp2.0"


__all__ = ['NewCP20CPABE']
