# DACP Data Workspace

This directory is for local dataset experiments.

- `data/raw/`: user-downloaded real datasets.
- `data/work/`: synthetic files and temporary local inputs.
- `data/encrypted/`: encrypted experiment outputs.
- `data/recovered/`: recovered plaintext outputs for local verification.

Do not commit real datasets, encrypted datasets, recovered datasets, or large
experiment outputs to Git.

Controlled datasets such as MIMIC-IV must only be used in a local compliant
environment. Do not upload controlled data to external services.
