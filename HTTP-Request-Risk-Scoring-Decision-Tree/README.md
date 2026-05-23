# HTTP Request Risk Ranking

Supervised-learning project for scoring HTTP requests by security risk.

Input:

```text
HTTP request: method, URL, path, query string, headers, body
```

Output:

```text
risk_score = P(attack) * 10
```

Models:

```text
Decision Tree Classifier baseline
Random Forest Classifier active notebook model
```

## Project Layout

```text
data/
  raw/              Source-specific converted request CSVs and original raw logs
  external/         Downloaded third-party datasets
  processed/        Training features, merged datasets, and external test CSVs
  reports/          Duplicate/leakage reports
docs/               Notes, pipeline documentation, and improvement plans
notebooks/          Colab/Jupyter training and testing notebook
scripts/
  data_sources/     Convert each dataset source into the common request schema
  pipeline/         Merge, deduplicate, and extract features for training
  external_tests/   Convert external Burp XML logs for post-training tests
src/                Reusable canonicalization and feature extraction code
```

## Main Files

```text
data/processed/features.csv
```

Main training feature file. QLDT PTIT is intentionally excluded from this file.

```text
data/processed/qldt_ptit_normal_requests.csv
```

External normal benchmark converted from Burp XML. Used to test the trained
model, not to train it.

```text
notebooks/train_decision_tree.ipynb
```

Minimal notebook for training Decision Tree and Random Forest models, comparing
metrics, running manual tests, CSIC benchmark, QLDT benchmark, and generic Burp
XML testing.

## Rebuild Data Pipeline

Run from project root:

```bash
python3 scripts/data_sources/process_malicious_zip.py
python3 scripts/data_sources/process_normal_legitimate.py
python3 scripts/data_sources/process_csic_dataset.py
python3 scripts/data_sources/process_modsec_learn_dataset.py
python3 scripts/data_sources/process_owasp_modsec_logs.py
python3 scripts/external_tests/process_qldt_burp_xml.py
cp data/raw/normal/qldt_ptit_normal_requests.csv data/processed/qldt_ptit_normal_requests.csv
python3 scripts/pipeline/merge_dataset.py
python3 scripts/pipeline/deduplicate_requests.py
python3 scripts/pipeline/extract_features.py
```

Expected training output:

```text
data/processed/features.csv
```

## Colab Upload Folder

For the notebook, upload these into:

```text
/content/drive/MyDrive/processed/
```

Required:

```text
features.csv
src/
```

Optional external tests:

```text
qldt_ptit_normal_requests.csv
any_burp_export.xml
```

Full pipeline documentation:

```text
docs/data_processing_to_training.md
```
