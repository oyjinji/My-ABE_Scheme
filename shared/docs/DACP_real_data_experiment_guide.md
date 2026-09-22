# DACP Real Data Experiment Guide

## Current Status

DACP currently supports algorithm benchmarks and local protocol simulation with:

- Blind pairing OPRF
- Ed25519 row signatures
- AES-GCM bytes plaintext encryption
- JSON wire-format simulation
- Dataset-file scaffold for opaque bytes experiments

The most complete local protocol command is:

```bash
python3 Benchmark/run_dacp_protocol.py --oprf blind --sig ed25519 --symmetric aesgcm --wire json
```

This is still a local simulation. There is no HTTP, socket, database, user
login, production CA, revocation, or data marketplace service.

## Data Layout

Place user-downloaded real datasets in:

```text
data/raw/
```

Do not commit real data, encrypted data, recovered data, or large result files
to Git. The repository `.gitignore` is configured for this.

Synthetic and temporary files may be placed in:

```text
data/work/
```

Encrypted outputs and recovered verification files are written under each
experiment output directory, typically:

```text
results/dacp_data/<experiment_name>/
```

## Single File Experiment

Run a local file as opaque bytes:

```bash
python3 Benchmark/run_dacp_dataset_file.py \
  --dataset-path data/raw/creditcard.csv \
  --dataset-name creditcard_fraud_sample \
  --domain financial \
  --policy-template credit_fraud \
  --output-dir results/dacp_data/creditcard_test
```

The script reads bytes, encrypts the file with AES-GCM, encrypts the dataset
key with DACP, recovers the key through CSP transform and DU final decrypt,
decrypts the file, and checks SHA256 equality.

## Chunk Mode

For larger files, enable chunk mode:

```bash
python3 Benchmark/run_dacp_dataset_file.py \
  --dataset-path data/raw/creditcard.csv \
  --dataset-name creditcard_fraud_sample \
  --domain financial \
  --policy-template credit_fraud \
  --output-dir results/dacp_data/creditcard_test \
  --chunk-mode \
  --chunk-size 16777216
```

Each chunk is encrypted independently with AES-GCM and recorded in the manifest.

## Batch Experiments

Batch configuration uses JSON:

```bash
python3 Benchmark/benchmark_dacp_dataset_files.py \
  --config configs/dacp_datasets.example.json \
  --summary-csv results/dacp_data/batch_summary.csv
```

Missing files are recorded as `skipped=True` with a reason instead of stopping
the whole batch.

## Summary CSV Fields

The summary JSON/CSV uses stable field names, including:

- `dataset_id`
- `dataset_name`
- `domain`
- `source_path`
- `policy_str`
- `file_size`
- `plaintext_sha256`
- `recovered_sha256`
- `dataset_encrypt_success`
- `dacp_key_recover_success`
- `dataset_recover_success`
- `chunk_mode`
- `chunk_size`
- `num_chunks`
- `encrypted_size`
- `manifest_path`
- `audit_log_path`
- `summary_path`
- `total_time`
- `dataset_encrypt_time`
- `dataset_decrypt_time`
- `dacp_encrypt_time`
- `csp_transform_time`
- `du_final_decrypt_time`
- `wire_total_bytes`
- `created_at`
- `skipped`
- `skip_reason`

## Recommended Dataset Order

1. Credit Card Fraud Detection
2. NYC TLC Trip Record Data
3. Lending Club
4. MIMIC-like / MIMIC-IV local compliant sample

The code does not parse dataset-specific fields in this stage.

## Compliance Notes

MIMIC-IV and other controlled medical datasets must only be used in a local
compliant environment. Do not upload controlled data to external services.

This scaffold does not perform de-identification or data sanitization. It only
supports encryption and access-control experiments over already available local
files.
