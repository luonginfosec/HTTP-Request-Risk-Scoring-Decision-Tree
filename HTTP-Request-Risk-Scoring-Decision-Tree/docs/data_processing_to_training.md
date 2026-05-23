# Data Processing, Training, and Testing Pipeline

## 1. Goal

The project builds a supervised learning model to score HTTP requests by security risk.

Input:

```text
HTTP request: method, URL, path, query string, headers, body
```

Output:

```text
risk_score = P(attack) * 10
```

Label meaning:

```text
0 = normal request
1 = attack / suspicious request
```

Current model:

```text
Decision Tree Classifier
```

No hard-coded scoring rule is used during evaluation. The score comes from `model.predict_proba`.

## 2. Data Sources

### Positive Data

Positive data means attack or suspicious requests.

| File | Source | Rows | Label |
|---|---:|---:|---:|
| `data/raw/positive/luongvd_attack_requests.csv` | ExploitDB / local luongvd collector | 2,129 | 1 |
| `data/raw/positive/malicious_requests.csv` | OpenAppSec malicious JSON | 4,254 | 1 |
| `data/raw/positive/csic_attack_requests.csv` | CSIC 2010 anomalous requests | 3,000 | 1 |
| `data/raw/positive/modsec_learn_sqli_requests.csv` | ModSec-Learn SQLi query payloads | 3,000 | 1 |
| `data/raw/positive/owasp_modsec_requests.csv` | OWASP ModSecurity audit logs | 3,000 | 1 |

Attack types currently include:

```text
sqli, xss, lfi, traversal, cmdexe, log4shell, xxe, shellshock, rce, idor, ssrf, ssti
```

### Normal Data

Normal data means ordinary valid HTTP requests.

| File | Source | Rows | Label |
|---|---:|---:|---:|
| `data/raw/normal/legitimate_normal_requests.csv` | OpenAppSec legitimate browsing traffic | 3,000 | 0 |
| `data/raw/normal/csic_normal_requests.csv` | CSIC 2010 normal requests | 3,000 | 0 |
| `data/raw/normal/modsec_learn_legitimate_requests.csv` | ModSec-Learn legitimate query strings | 3,000 | 0 |
| `data/raw/normal/qldt_ptit_normal_requests.csv` | QLDT PTIT Burp Suite normal traffic, external test only | 102 | 0 |

The OpenAppSec legitimate data contains real browser traffic, analytics requests, API-like requests, and background browser requests.

The CSIC normal data contains normal traffic from an old ecommerce-style Java/JSP application.

The ModSec-Learn data is a query-string dataset used by the "Boosting
ModSecurity with Machine Learning" paper. It adds legitimate parameterized
requests and SQLi payload variants, but it does not contain full original HTTP
headers or application paths. The converter reconstructs simple `GET /?...`
requests using the project schema.

The QLDT PTIT data is a Burp Suite XML export from normal browsing/API usage.
Only request data is converted; response data is ignored. Sensitive request
headers and fields such as cookies, authorization, CSRF/XSRF values, tokens,
passwords, and secrets are redacted to `PRESENT`.

QLDT PTIT is not included in `features.csv` for training. It is kept as an
external normal benchmark to test whether the model generalizes to a real
application log that it has not seen during training.

### OWASP ModSecurity Logs

The OWASP ModSecurity data is sampled from audit logs already matched by OWASP
CRS rules. The converter keeps web attack categories such as SQLi, XSS, RCE,
LFI/RFI, PHP injection, and Java/Log4j-style attacks, while skipping pure
bad-bot/protocol-policy noise unless a web attack signal is present.

Input logs:

```text
data/raw/owasp/*/modsec_audit.anon.log
```

Output:

```text
data/raw/positive/owasp_modsec_requests.csv
```

## 3. Common Request Schema

All raw sources are converted into the same CSV schema:

```csv
id,label,source,source_url,method,url,path,query_string,headers,body,raw_request,notes
```
    
Column meaning:

| Column | Meaning |
|---|---|
| `id` | Unique row id |
| `label` | `0` normal, `1` attack |
| `source` | Dataset source name |
| `source_url` | Original file or evidence source |
| `method` | HTTP method |
| `url` | Full URL |
| `path` | URL path |
| `query_string` | URL query string |
| `headers` | JSON-encoded headers |
| `body` | Request body |
| `raw_request` | Reconstructed raw HTTP request |
| `notes` | Dataset note or attack category |

This schema is stored in the raw normalized files under:

```text
data/raw/positive/
data/raw/normal/
```

## 4. Processing Scripts

### Import ExploitDB / luongvd Positive Data

Script:

```text
scripts/data_sources/import_luongvd_positive.py
```

Purpose:

```text
Convert ../luongvd/attack_requests.csv into project schema.
```

Output:

```text
data/raw/positive/luongvd_attack_requests.csv
```

### Process OpenAppSec Malicious Data

Script:

```text
scripts/data_sources/process_malicious_zip.py
```

Purpose:

```text
Convert data/raw/positive/malicious.zip into positive request rows.
```

Output:

```text
data/raw/positive/malicious_requests.csv
```

### Process OpenAppSec Legitimate Data

Script:

```text
scripts/data_sources/process_normal_legitimate.py
```

Purpose:

```text
Convert data/raw/normal/legitimate.zip into normal request rows.
```

Important processing steps:

```text
- keep HTTP request fields
- remove static-only noise where possible
- remove payload-like rows
- redact sensitive headers such as cookies and tokens
- keep up to 3,000 normal rows by default
```

Output:

```text
data/raw/normal/legitimate_normal_requests.csv
```

### Process CSIC 2010 Dataset

Script:

```text
scripts/data_sources/process_csic_dataset.py
```

Input:

```text
data/csic_database.csv
```

Outputs:

```text
data/raw/normal/csic_normal_requests.csv
data/raw/positive/csic_attack_requests.csv
```

Current default:

```text
normal rows: 3,000
attack rows: 3,000
sampling: random sample with seed 42
```

Reason for resizing:

```text
The full CSIC dataset is much larger than the other sources.
Using all CSIC rows made the model learn mostly CSIC-specific patterns.
```

### Process ModSec-Learn Dataset

Script:

```text
scripts/data_sources/process_modsec_learn_dataset.py
```

Input:

```text
data/external/modsec-learn-dataset/
```

Outputs:

```text
data/raw/normal/modsec_learn_legitimate_requests.csv
data/raw/positive/modsec_learn_sqli_requests.csv
```

Current default:

```text
normal rows: 3,000
SQLi rows:   3,000
sampling: random sample with seed 42
```

Reason for limiting:

```text
The legitimate side contains more than 500,000 query strings, and the SQLi side
contains more than 30,000 payload strings. Keeping only 3,000 rows from each
side adds diversity without letting this source dominate the whole dataset.
Sensitive normal query values such as `key`, `token`, `secret`, and `sig` are
redacted to `PRESENT`.
```

### Process OWASP ModSecurity Logs

Script:

```text
scripts/data_sources/process_owasp_modsec_logs.py
```

Input:

```text
data/raw/owasp/*/modsec_audit.anon.log
```

Output:

```text
data/raw/positive/owasp_modsec_requests.csv
```

Current default:

```text
positive rows: 3,000
sampling: reservoir sample by attack category with seed 42
categories: SQLi, XSS, RCE, LFI/RFI, PHP injection, Java/Log4j
```

### Process QLDT PTIT Burp XML

Script:

```text
scripts/external_tests/process_qldt_burp_xml.py
```

Input:

```text
data/raw/qldt-ptit.xml
```

Output:

```text
data/raw/normal/qldt_ptit_normal_requests.csv
```

Current output:

```text
normal rows: 102
```

Privacy handling:

```text
- parse only Burp request data
- ignore Burp response data
- redact sensitive headers and body fields to PRESENT
```

### Process Any Burp XML For External Testing

Script:

```text
scripts/external_tests/process_burp_xml.py
```

Example:

```bash
python3 scripts/external_tests/process_burp_xml.py \
  --input data/raw/my_burp_log.xml \
  --output data/processed/my_burp_log_requests.csv \
  --label 0 \
  --source burp_external \
  --notes burp_external_normal
```

The output CSV can be passed to the notebook `test_csv()` helper. This is for
external evaluation only and is not merged into `features.csv` unless explicitly
added later.

## 5. Merge Dataset

Script:

```text
scripts/pipeline/merge_dataset.py
```

Inputs:

```text
data/raw/positive/luongvd_attack_requests.csv
data/raw/positive/malicious_requests.csv
data/raw/positive/csic_attack_requests.csv
data/raw/positive/modsec_learn_sqli_requests.csv
data/raw/positive/owasp_modsec_requests.csv
data/raw/normal/legitimate_normal_requests.csv
data/raw/normal/csic_normal_requests.csv
data/raw/normal/modsec_learn_legitimate_requests.csv
```

Output:

```text
data/processed/requests_dataset.csv
```

Current merge ratio:

```text
70% normal
30% attack
```

Script parameter:

```bash
python3 scripts/pipeline/merge_dataset.py --normal-ratio 0.7
```

Current output:

```text
rows: 12,857
normal: 9,000
attack: 3,857
```

Current source distribution:

```text
csic_2010: 3,774
modsec_learn_legitimate: 3,000
openappsec_legitimate: 3,000
openappsec_malicious: 1,062
modsec_learn_sqli: 789
owasp_modsecurity: 718
exploitdb: 514
```

`requests_dataset.csv` is still request-level data. It contains URL, headers, body, and raw request text. It is not yet suitable for direct model training.

### Deduplication and Leakage Reports

Script:

```text
scripts/pipeline/deduplicate_requests.py
```

Purpose:

```text
Detect exact duplicates, label conflicts, source overlaps, and near-duplicate
groups before feature extraction and train/test split.
```

The script adds three hash columns:

```text
canonical_raw_request_hash
endpoint_shape_hash
payload_family_hash
```

Hash meaning:

```text
canonical_raw_request_hash:
same method, host, normalized path, canonical query params, and body

endpoint_shape_hash:
same method, normalized path, and sorted parameter names

payload_family_hash:
similar decoded payload family and normalized payload skeleton
```

Current command:

```bash
python3 scripts/pipeline/deduplicate_requests.py
```

Current output:

```text
input rows:       12,857
deduped rows:     10,332
removed rows:     2,525
exact conflicts:  1
```

Deduplicated dataset:

```text
data/processed/requests_dataset_dedup.csv
```

Reports:

```text
data/reports/duplicate_report.csv
data/reports/endpoint_shape_report.csv
data/reports/payload_family_report.csv
data/reports/label_conflict_report.csv
data/reports/source_overlap_report.csv
```

Current report summary:

```text
exact duplicate groups: 139
endpoint shape groups: 915
payload family groups: 737
label conflict groups: 24
source overlap groups: 13
```

The deduplicated output removes exact duplicate requests and drops exact
canonical request groups that contain both label `0` and label `1`.
Endpoint-shape and payload-family conflicts are reported, but not automatically
removed, because they may be valid normal/attack pairs that require benchmark
grouping rather than deletion.

## 6. Feature Extraction

Script:

```text
scripts/pipeline/extract_features.py
```

Core feature logic:

```text
src/request_canonicalizer.py
src/feature_extractor.py
```

`request_canonicalizer.py` creates multiple representations before feature extraction:

```text
raw value
lowercase value
URL-decoded once
URL-decoded recursively up to 3 rounds
HTML entity decoded
Unicode normalized
normalized path
query params parsed while preserving duplicate parameter names
```

`feature_extractor.py` keeps both raw and decoded signals. Raw features preserve
obfuscation indicators, while decoded features catch payloads hidden behind URL
encoding or HTML entities.

Input:

```text
data/processed/requests_dataset_dedup.csv
```

Output:

```text
data/processed/features.csv
```

Current output:

```text
rows: 10,332
total columns: 72
feature columns: 68
```

`features.csv` is the only feature file used for model training. It is generated
from the deduplicated request dataset, not from the raw merged dataset.

Current training `features.csv` excludes QLDT PTIT:

```text
qldt_ptit_burp rows: 0
```

Metadata columns:

```text
id, label, source, notes
```

Feature categories:

```text
HTTP method:
method_get, method_post, method_put, method_patch, method_delete

URL structure:
path_depth, has_query, num_params, duplicate_param_count,
max_duplicate_param_name_count

Path keywords:
has_api_path, has_admin_path, has_internal_path, has_debug_path,
has_document_path, has_user_path, has_payment_path, has_upload_path

Parameter names:
has_id_param, has_url_param, has_file_param, has_business_param, has_search_param

Parameter/body values:
has_numeric_value, has_uuid_value, has_url_value, has_private_ip_value,
has_base64_like_value, has_encoded_value, has_special_chars,
has_double_encoded_value, decoded_changes_value, raw_encoded_ratio,
has_html_entity_value, has_unicode_normalized_change

Recursive decoded payload signals:
has_recursive_decoded_traversal, has_recursive_decoded_sqli,
has_recursive_decoded_xss, has_recursive_decoded_private_ip,
has_recursive_decoded_url

Headers:
has_authorization_header, has_cookie_header, has_content_type_json,
has_content_type_form, has_content_type_xml, has_tenant_header,
has_origin_header, has_referer_header, has_x_forwarded_for

Body:
has_json_body, has_xml_body, has_form_body, body_has_role,
body_has_admin_value, body_has_id_field, body_has_url_field,
body_has_file_field, body_has_price_field

Interaction features:
has_admin_and_url, has_document_and_id, has_tenant_and_id,
has_auth_and_id, has_write_method_and_id, has_upload_and_file,
has_url_param_and_private_ip, has_role_and_admin_value
```

## 7. Reproduce the Data Pipeline

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

Expected final files:

```text
data/processed/requests_dataset.csv
data/processed/requests_dataset_dedup.csv
data/processed/features.csv
data/processed/qldt_ptit_normal_requests.csv
```

## 8. Training

Notebook:

```text
notebooks/train_decision_tree.ipynb
```

The notebook is intentionally minimal for presentation.

Training input:

```text
data/processed/features.csv
```

Training steps:

```text
1. Load features.csv
2. Remove metadata columns: id, label, source, notes
3. Use remaining 68 columns as X
4. Use label as y
5. Split train/test with stratification
6. Train Decision Tree
7. Convert probability to risk_score
```

Model:

```python
DecisionTreeClassifier(
    max_depth=8,
    min_samples_leaf=20,
    random_state=42
)
```

Risk score:

```text
risk_score = P(label=1) * 10
```

Binary threshold:

```text
risk_score < 5.0  => normal
risk_score >= 5.0 => attack
```

Saved model:

```text
models/decision_tree.joblib
```

The saved bundle includes:

```text
model
feature_columns
threshold
```

## 9. Testing and Evaluation

### Overall Test Split

The notebook evaluates the train/test split using:

```text
accuracy
classification report
confusion matrix
ROC-AUC
PR-AUC
```

For this security-oriented task, the most important values are:

```text
attack recall    = how many attack requests are detected
attack precision = how many predicted attacks are truly attacks
```

### Source-Specific CSIC Benchmark

The notebook also filters the test split:

```text
source == "csic_2010"
```

This is used to show performance on CSIC data specifically.

### External QLDT PTIT Benchmark

QLDT PTIT is tested after training from a separate raw request CSV:

```text
data/processed/qldt_ptit_normal_requests.csv
```

This file is not part of `features.csv`. The notebook converts each QLDT raw
request to the same 68 feature columns, runs `model.predict_proba`, then sorts
the QLDT requests by `risk_score` descending. Because all QLDT rows are normal,
predicted attacks in this benchmark are false positives.

### External Burp XML Benchmark

The notebook also supports an arbitrary Burp Suite XML export placed in:

```text
/content/drive/MyDrive/processed/
```

Set:

```python
BURP_XML_FILE = "sample.xml"
BURP_LABEL = 0
```

The notebook converts the XML into `<filename>_requests.csv`, redacts sensitive
headers/body fields, runs the trained model, and displays the highest-risk
requests first.

### Manual Tests

The notebook includes 25 manually written requests.

These tests are not the main benchmark. They are used as qualitative analysis.

They show:

```text
- the model detects clear payloads such as SQLi, XSS, traversal, command injection
- the model may falsely rank normal GET requests with query parameters as risky
- the model struggles with flows missing from training data, such as business logic role changes
```

Manual tests are useful for explaining limitations, but the main evaluation should come from the held-out test split.

## 10. Known Limitations

### Missing Normal Business Flows

Some manual normal examples still fail:

```text
/product?id=123
/document?id=123
/callback?code=...&state=...
/redirect?next=/dashboard
/tenant/dashboard?tenant_id=...
```

Reason:

```text
The training data has many attack requests with GET query parameters,
but not enough normal requests with business-flow query parameters.
```

The model may learn:

```text
GET + query + id/url-like parameter => risky
```

This is a data distribution problem, not a scoring-code problem.

### No Hard-Code Evaluation Logic

Earlier calibration logic was removed. The current notebook uses only:

```text
model.predict_proba
```

## 11. Next Improvements

Recommended next steps:

```text
1. Collect more normal requests from Juice Shop, crAPI, or a demo ecommerce/API app.
2. Include valid flows such as product detail, search, order detail, callback, redirect, tenant dashboard.
3. Add more real normal traffic from authenticated API applications.
4. Add more features for SSRF, XXE, redirect, OAuth callback, and business logic patterns.
5. Compare 50/50 and 70/30 train datasets.
6. Report metrics by source, not only overall accuracy.
```
