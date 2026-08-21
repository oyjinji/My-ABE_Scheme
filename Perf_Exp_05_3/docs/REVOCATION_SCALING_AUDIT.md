# Revocation Scaling Audit

Result: **PASS**.

| n | revoked | tree height | cover size | RevKeyUpt median (ms) | G2 exp |
|---:|---:|---:|---:|---:|---:|
| 32 | 2 | 5 | 4 | 32.899 | 8 |
| 64 | 3 | 6 | 5 | 41.568 | 10 |
| 128 | 6 | 7 | 5 | 42.376 | 10 |
| 256 | 13 | 8 | 6 | 49.758 | 12 |
| 512 | 26 | 9 | 6 | 51.470 | 12 |
| 1024 | 51 | 10 | 7 | 59.043 | 14 |

The experiment controls revoked users at approximately 5% of registered users; tree height and the measured cover are retained in the derived CSV. The timed boundary is only `RevKeyUpt`: tree cover computation plus KU cryptographic construction/serialization-state work. User OPRF/token issuance, privacy-key refresh, FX build, and PStore build are outside it.

The Coupled/Dual median update-lifecycle ratio is **11.511x**. This is an update lifecycle ablation: Coupled-Epoch additionally refreshes every active user's privacy material; it is not a comparison of two complete cryptographic schemes.
