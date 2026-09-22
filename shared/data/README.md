# DACP Data Workspace

This directory (`shared/data/`) is for local dataset experiments.

- `shared/data/raw/`: user-downloaded real datasets.
- `shared/data/work/`: synthetic files and temporary local inputs.
- `shared/data/encrypted/`: encrypted experiment outputs.
- `shared/data/recovered/`: recovered plaintext outputs for local verification.
- `shared/data/products/`: generated product fixtures.

Do not commit real datasets, encrypted datasets, recovered datasets, or large
experiment outputs to Git.

Controlled datasets such as MIMIC-IV must only be used in a local compliant
environment. Do not upload controlled data to external services.