# Anonymous-index leakage matrix

## Two distinct boundaries

The audit must distinguish:

1. **Current Python runtime state**: every PStore returned by `build_pstore`
   retains `pstore["ids"]`, a Python dictionary from serialized OPRF token
   bytes directly to compact identifier `j`. Query never uses this dictionary.
2. **Declared serialized/integrated representation**: `pstore_size()` counts
   only nonce+ciphertext records, while locator bytes are separately counted.
   Under this intended representation, `ids` is build-only material and is not
   part of the reported stored index.

Until the unused `ids` map is removed after construction or a real serializer
proves it is omitted at deployment, the runtime prototype gives the CSP an
explicit enumerable `token -> j` map for **all five indexes**. Therefore the
current prototype cannot claim a runtime leakage advantage for FX-ABF.

## Matrix

| Property visible to CSP | Legacy ABF | Bloom+Locator | Cuckoo+Locator | Xor+Locator | FX-ABF |
|---|---|---|---|---|---|
| Runtime `pstore["ids"]` raw OPRF-token -> `j` map | Yes (unused artifact) | Yes (used to build locator only) | Yes (used to build locator only) | Yes (used to build locator only) | Yes (unused artifact) |
| Declared serialized explicit token digest -> `j` map | No | Yes | Yes | Yes | No |
| Can enumerate exact locator keys in intended representation | No | Yes | Yes | Yes | No |
| Directly recovers value/pointer from slots | Yes | No | No | No | Yes |
| Membership structure additionally visible | Greedy XOR retrieval slots | Bloom bitmap | Cuckoo fingerprints/buckets | XOR fingerprint slots | Segmented XOR value slots |
| Compact PStore identifiers visible | Yes, as record positions | Yes | Yes | Yes | Yes |
| Identifier stable across ciphertexts/epochs | No; shuffled per build | No | No | No | No |
| Same-privacy-epoch token equality visible | Yes | Yes | Yes | Yes | Yes |
| Exact offline test for a candidate token from locator alone | No in intended form | Yes | Yes | Yes | No in intended form |
| Query oracle can test a candidate token | Yes | Yes | Yes | Yes | Yes |
| Requires high-entropy OPRF token | Yes | Yes | Yes | Yes | Yes |
| Privacy weakens under KGC/CSP collusion | Yes | Yes | Yes | Yes | Yes |

## Interpretation

- The three locator baselines explicitly serialize an enumerable set of
  context-bound SHA-256 token digests and their `j` values. Because OPRF tokens
  are intended to be high entropy, this does not directly disclose attribute
  plaintext, but it does expose exact indexed-key cardinality and an exact
  candidate-token membership/mapping relation.
- Legacy ABF and FX-ABF recover `j || check` from XOR slots and do not require
  an explicit key list in their intended serialized form. Their structures and
  query oracle still reveal successful equality tests, index cardinality, and
  per-ciphertext posting identifiers.
- All five reveal equality of the same deterministic OPRF token within a
  privacy epoch when the CSP observes repeated queries. Privacy-epoch changes
  change the token.
- All rely on the OPRF token being unguessable without the KGC secret and on
  the assumed KGC/CSP non-collusion boundary.

## Fair comparison rule

The intended serialized designs are not leakage-equivalent. Results should
therefore be presented in three dimensions:

1. performance (system query/build time);
2. complete serialized space;
3. leakage/representation (explicit exact key map versus implicit XOR
   retrieval).

For the current runtime prototype, the retained `pstore["ids"]` artifact must
be disclosed because it temporarily collapses this distinction. Removing that
unused build map later would be a semantic-preserving hardening change, not a
ranking optimization; it was deliberately not changed in this audit phase.
