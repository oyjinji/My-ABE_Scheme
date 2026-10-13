# LUAR authoritative-correction check — Phase 5D-R

Status: `BLOCKED_CORRECTNESS` and `LITERATURE_REFERENCE_ONLY` for local
performance comparison. This is isolated from the MyABE/FABEO tracks.

On 2026-09-27 UTC the published 19-page PDF identified by DOI
`10.32604/cmc.2025.073423` and SHA-256
`88e2f58327f6cce589cf8ad67a2949e218ab8b24dd11ea376c78551606244bfd`
was checked for a correction/erratum notice affecting §6.3–6.4; none was
identified in that PDF. The repository advertised by the paper,
`https://github.com/Aw-creat/SGX_ABE`, still resolves at HEAD
`eeaeb5ea6125077b8a9687d61483ec1f45e43068` by `git ls-remote`.
The GitHub commits page confirms that SHA. The public open and closed issue
pages each reported zero search results; no authoritative formula correction
was identified. The GitHub API returned
HTTP 403 rate limiting, so this is a documented search limit, not proof that
no private or later author clarification exists.

The published PDF's §6.4 still asserts
`e(g1,g2)^{βst Σω_i}=e(g1,g2)^{βst}` without requiring `Σω_i=1`.
The valid two-row AND counterexample and ZIP-source defects remain in
`FORMULA_AUDIT.md`. Neither a proposed row-blinding repair nor the existing
upstream code qualifies as an authoritative correction. No local LUAR port,
timing, or MyABE/LUAR ratio is eligible. Paper-reported numbers, if later
transcribed, must carry `measurement_origin=PAPER_REPORTED` and remain apart
from locally measured curves.
