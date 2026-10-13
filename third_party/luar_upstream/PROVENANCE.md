# LUAR published upstream snapshot — audit only

- Paper-advertised repository: https://github.com/Aw-creat/SGX_ABE
- Retrieved UTC: 2026-09-27T10:16:53Z
- Repository HEAD: `eeaeb5ea6125077b8a9687d61483ec1f45e43068`
- Repository HEAD commit time: 2025-04-07T20:44:55+08:00
- Original repository payload: `SGX_ABE-main.zip`, copied byte-for-byte without extraction or modification.
- Archive SHA-256: `498a37227b36dfce47dd4dc775f8a42dbb75f20077822c28711d0eb958cd5dbb`
- Contents: 81 ZIP entries including C++/PBC SGX sample-style source, `.o` files, `.so` files, and a test-signing PEM. The archive is **not** a validated LUAR implementation or a common-backend port.

The paper reports SGX **simulation** experiments. Source audit found uninitialized current time, fixed/truncated nonce, pointer-length attribute hashing, absent key-expiry assignment, and commented-out Merkle verification in `SGX_ABE/Enclave/Enclave.cpp`. See `src/core/myabe08/baselines/FORMULA_AUDIT.md`. This snapshot must not be executed as a trusted baseline or used for a real-SGX performance ratio.
