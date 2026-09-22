# FXDACP reference analysis

## Repository CP-ABE APIs

| Scheme | Constructor | Setup | Key generation | Encryption | Final operation |
|---|---|---|---|---|---|
| `BSW07CPABE` | `(group, verbose=False)` | `setup() -> (pk, msk)` | `keygen(pk, msk, attr_list)` | `encrypt(pk, GT_message, policy_string)` | `decrypt(pk, ct, key)` |
| `AC17CPABE` | `(group, assump_size, verbose=False)` | same | same | same | same |
| `FABEO22CPABE` | `(group, verbose=False)` | same | same | same | same |
| `FXDACP` | `(group, FX_parameters..., rng=None)` | `setup() -> (pk, msk)` | `keygen(pk, msk, attrs, identity, epoch, version, metrics)` | `encrypt(pk, msk, bytes_message, policy, epoch, version, metrics)` | `transform(...)`, then `final_dec(...)` |

All three references inherit `ABEnc`, use dictionary-shaped keys/ciphertexts, receive an existing `PairingGroup`, and expose lower-case algorithm methods. FXDACP follows those conventions and additionally exposes the document spellings `Setup`, `KeyGen`, `Encrypt`, `Transform`, and `FinalDec`. Its extra `msk` argument to `encrypt` models the documented online KGC OPRF evaluation; it is not presented as ordinary public-key encryption without KGC interaction.

## MSP, attributes, groups and errors

The reference implementations share `Code.msp.MSP`. It parses AND/OR policies, labels duplicate leaves, returns a dict of indexed attribute names to MSP rows, and strips duplicate suffixes before hashing. FXDACP uses it for policy strings and also accepts explicit `{matrix, rho}` input for general monotone LSSS policies. It preserves one independently randomized ABE component per matrix row and groups only the OPRF work by canonical attribute.

Existing schemes use Charm `ZR`, `G1`, `G2`, `GT`, `pair`, native group serialization and Python dictionaries. A failed policy returns `None` (the older schemes also print a message); FXDACP returns `None` without printing. Reference benchmark entry points initialize `PairingGroup('MNT224')`.

## Reused components

- `Code.msp.MSP`: policy parsing and policy-to-MSP conversion.
- Charm group operations, group hashing after an ASCII digest boundary, serialization, and `pair`.
- The AES-GCM choice already used by `Code.dacp.components.symmetric.AESGCMEnvelope`, through the same `cryptography` library. FXDACP implements scheme-specific KDF domains and canonical AAD locally because the DACP envelope uses DACP-specific domains and compatibility fields.
- Repository benchmark conventions: caller-created pairing groups, dictionary results and `MNT224` for comparisons.

## Components inspected but not directly reused

- `Code.dacp.components.PrototypeOPRF` explicitly states that it is not a real OPRF. `BlindPairingOPRF` has the right algebraic shape, but its attribute encoding is delimiter based and its subgroup checks remain outside the component. FXDACP therefore implements the same blind/evaluate/unblind algebra over canonical attribute bytes in `oprf.py`.
- `Code.dacp.components.PrototypeABF` stores an `ell`-byte bitmap per token, is benchmark-only, and is neither the documented compact original ABF nor FX-ABF. It is not reused.
- `PrototypeGTEnvelope` is explicitly not AEAD. It is not reused.
- Existing DACP certificate/signature/protocol code is outside the FXDACP threat model and is not imported.
- Existing result utilities target another comparison hierarchy. The new append-only JSONL, manifest, resume and CSV code is kept under `fx_exp` so existing results are untouched.

## Type-III caveat

The theory specifies a prime-order Type-III asymmetric pairing. Charm 0.63's repository-standard `MNT224` environment exposes distinct `G1` and `G2` APIs and supports the required ordered pairing calls, but this legacy environment is not a production-grade strict Type-III instantiation and does not expose all validation/subgroup APIs assumed by the formal protocol. This implementation is therefore an algorithm and performance prototype using the same pairing environment as the existing comparison schemes. It must not be represented as a production cryptographic implementation or as proof that all Type-III validation requirements have been met.

## Final interface decision

`FXDACP` keeps dictionary wire objects because that is the repository norm. Stable fields are documented in `README.md`. FX-ABF build/query statistics and general operation metrics use dataclasses or a fixed metrics dictionary. Messages are bytes and are protected with AES-GCM; no XOR-based message encryption, signature, certificate, Merkle tree, dummy attribute, revocation, dynamic update or malicious-CSP verification was added.
