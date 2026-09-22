"""Non-invasive adapter over the repository's official FABEO CP-ABE source."""

from core.fabeo22cp import FABEO22CPABE
from core.fxabe_05_3_exp.scheme import OperationCounts
from core.fxabe_05_3_exp.storage import fabeo_ciphertext_bytes, recursive_group_bytes


class FABEOAdapter:
    name = "FABEO"
    source_path = "src/core/fabeo22cp/__init__.py"

    def __init__(self, group):
        self.group = group
        self.scheme = FABEO22CPABE(group)

    def setup(self):
        result = self.scheme.setup()
        return result, OperationCounts(GT_exp=1, pair_count=1)

    def keygen(self, pk, msk, attributes):
        key = self.scheme.keygen(pk, msk, attributes)
        return key, OperationCounts(G1_exp=len(attributes) + 2, G2_exp=1)

    def encrypt(self, pk, message, policy):
        ct = self.scheme.encrypt(pk, message, policy)
        # Preserve the exact adapter input for canonical policy metadata byte
        # accounting.  Charm's left-deep policy-tree __str__ recurses past the
        # Python limit around ell=640; FABEO decrypt ignores this audit field.
        ct["_benchmark_policy_string"] = str(policy)
        ell = len(ct["ct"])
        return ct, OperationCounts(G1_exp=2 * ell, G2_exp=2, GT_exp=1)

    def decrypt(self, pk, ct, key):
        result = self.scheme.decrypt(pk, ct, key)
        # Official source aggregates selected rows and always executes 3 pairs.
        return result, OperationCounts(pair_count=3)

    def ciphertext_bytes(self, ct):
        return fabeo_ciphertext_bytes(self.group, ct)

    def key_bytes(self, key):
        return recursive_group_bytes(self.group, key)
