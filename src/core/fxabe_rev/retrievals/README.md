# Functionally equivalent static retrievals

This package isolates the algorithmic question:

```text
serialized OPRF token -> fixed-width Encode_bj(j) || 64-bit check, or miss
```

It deliberately contains no PStore, KDF, AEAD, exact locator, Python
token-to-value dictionary, or ABE operation. Build may consume a temporary
input dictionary, but no token key is retained after `build`.

The five constructions are:

- **Legacy ABF retrieval**: greedy three-global-position XOR assignment. A
  retry occurs when a new key has no unassigned position.
- **Bloomier retrieval**: four-partition peelable static-function table. Each
  key selects one cell in each disjoint partition; reverse XOR assignment
  stores the value.
- **Cuckoo payload table**: two-bucket Cuckoo hashing. Every occupied slot
  stores `16-bit fingerprint || complete fixed-width value`.
- **Plain XOR retrieval**: three independent global positions, hypergraph
  peeling, and reverse XOR assignment.
- **FX-ABF retrieval**: the repaired adaptive Binary-Fuse-style three
  consecutive-segment position function, hypergraph peeling, and reverse XOR
  assignment.

All position/check hashes call the same canonical SHA-256 helper. All direct
retrieval structures validate the same token-bound check. Serialization is a
canonical JSON metadata header followed by a fixed-width binary slot/table
array; deserialization reconstructs no key map.
