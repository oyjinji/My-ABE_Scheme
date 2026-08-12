# Metric definitions

- `filter_only_bytes`: serialized bit/fingerprint/XOR-slot payload only.
- `locator_bytes`: canonical digest-to-compact-id exact locator; zero for
  Legacy ABF and FX-ABF.
- `pstore_bytes`: actual AES-GCM nonce, ciphertext, and tag bytes.
- `metadata_bytes`: canonical parameters required to query the index.
- `integrated_index_bytes`: exact sum of the preceding four metrics.
- `membership_or_retrieval_ms`: membership test or direct XOR value recovery.
- `locator_lookup_ms`: exact anonymous locator lookup; zero for Legacy ABF and
  FX-ABF.
- `pstore_kdf_ms`: posting-record key derivation.
- `pstore_aead_ms`: associated-data construction and AES-GCM authentication.
- `posting_decode_ms`: canonical posting-list decoding.
- `integrated_index_query_ms`: exact sum of the preceding five query phases.
- `index_query_ms`: compatibility aggregate of membership/retrieval and locator.
- `pstore_processing_ms`: compatibility aggregate of KDF, AEAD, and decoding.
- `structure_build_ms`: wall-time remainder after locator, PStore, and metadata
  construction; includes validation, layout/payload work, retries, and the
  concrete structure build.
- `integrated_build_ms`: exactly the wall-clock `build_total_ms`, not a
  re-summed measurement.
- `core_transform_ms`: Path/Cover lookup, two revocation pairings, `2r` row
  pairings, and transformed-result construction.
- `transform_total_ms`: metadata validation, index query, PStore processing,
  and core transform.

Space metrics never use `sys.getsizeof()`. Figure error bars are the 2.5th and
97.5th percentiles of deterministic bootstrap medians.
