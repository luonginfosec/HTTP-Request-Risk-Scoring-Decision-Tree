# Giải thích toàn bộ project HTTP Request Risk Scoring

## 1. Mục tiêu project

Project này xây dựng mô hình học máy có giám sát để đánh giá mức độ rủi ro của một HTTP request.

Input của hệ thống là thông tin request:

```text
method, url, path, query string, headers, body, raw_request
```

Output là điểm rủi ro:

```text
risk_score = P(attack) * 10
```

Trong đó:

```text
0 = request bình thường
1 = request tấn công hoặc đáng nghi
```

Nếu `risk_score >= 5.0`, notebook hiện tại phân loại request là `attack`. Nếu nhỏ hơn `5.0`, request được phân loại là `normal`.

## 2. Ý tưởng tổng thể

Project không train trực tiếp trên chuỗi HTTP thô. Thay vào đó, pipeline làm theo các bước:

```text
Raw data sources
  -> chuẩn hóa về cùng schema request CSV
  -> merge dữ liệu normal/attack
  -> deduplicate và tạo leakage reports
  -> trích xuất feature thủ công
  -> train Decision Tree và Random Forest
  -> chấm điểm request/test file bằng predict_proba
```

Lý do dùng feature thủ công là HTTP attack thường có dấu hiệu rõ trong path, query, body, header, encoding, payload pattern. Ví dụ:

```text
SQLi: union select, or 1=1, sleep(...)
XSS: <script>, javascript:, onerror=
Traversal: ../, /etc/passwd
SSRF: URL parameter trỏ tới localhost/private IP
Encoding: double URL encoding, HTML entity, Unicode normalization change
```

## 3. Cấu trúc thư mục

```text
data/
  raw/              Dữ liệu nguồn đã convert hoặc log gốc
  processed/        Dataset đã merge, dedup, feature, external test CSV
  reports/          Báo cáo duplicate/leakage
docs/               Ghi chú pipeline và kế hoạch cải tiến
notebooks/          Notebook train/test model
scripts/
  data_sources/     Script convert từng nguồn dữ liệu về schema chung
  pipeline/         Script merge, dedup, extract features
  external_tests/   Script convert Burp XML cho kiểm thử ngoài
src/                Code tái sử dụng cho canonicalization, feature extraction, Burp XML
```

Các file quan trọng:

```text
data/processed/features.csv
```

Đây là file chính dùng để train model.

```text
notebooks/train_decision_tree.ipynb
```

Notebook chính để train Decision Tree và Random Forest, so sánh metric, xem feature importance, test CSIC, test Burp XML, và test CSV ngoài.

```text
src/feature_extractor.py
```

File định nghĩa toàn bộ feature thủ công.

```text
src/request_canonicalizer.py
```

File chuẩn hóa URL/path/query/body trước khi extract feature.

```text
src/burp_xml_converter.py
```

File convert Burp Suite XML export thành CSV request schema.

## 4. Schema request chung

Mọi nguồn dữ liệu raw được convert về cùng schema:

```csv
id,label,source,source_url,method,url,path,query_string,headers,body,raw_request,notes
```

Ý nghĩa cột:

| Cột | Ý nghĩa |
|---|---|
| `id` | ID duy nhất của dòng |
| `label` | `0` normal, `1` attack |
| `source` | Tên nguồn dữ liệu |
| `source_url` | File hoặc URL nguồn |
| `method` | HTTP method |
| `url` | URL đầy đủ |
| `path` | URL path |
| `query_string` | Query string |
| `headers` | Header dạng JSON string |
| `body` | Request body |
| `raw_request` | HTTP request tái dựng |
| `notes` | Ghi chú nguồn hoặc loại attack |

Schema chung này giúp pipeline không phụ thuộc vào format riêng của từng dataset.

## 5. Nguồn dữ liệu

### Dữ liệu attack

Các file attack nằm trong:

```text
data/raw/positive/
```

Các nguồn chính:

| File | Nguồn | Label |
|---|---|---|
| `luongvd_attack_requests.csv` | ExploitDB/local collector | `1` |
| `malicious_requests.csv` | OpenAppSec malicious JSON | `1` |
| `csic_attack_requests.csv` | CSIC 2010 anomalous requests | `1` |
| `modsec_learn_sqli_requests.csv` | ModSec-Learn SQLi payloads | `1` |
| `owasp_modsec_requests.csv` | OWASP ModSecurity audit logs | `1` |

Attack family thường gặp:

```text
sqli, xss, lfi, traversal, cmdexe, log4shell, xxe, shellshock, rce, ssrf, ssti
```

### Dữ liệu normal

Các file normal nằm trong:

```text
data/raw/normal/
```

Các nguồn chính:

| File | Nguồn | Label |
|---|---|---|
| `legitimate_normal_requests.csv` | OpenAppSec legitimate browsing traffic | `0` |
| `csic_normal_requests.csv` | CSIC 2010 normal requests | `0` |
| `modsec_learn_legitimate_requests.csv` | ModSec-Learn legitimate query strings | `0` |
| `qldt_ptit_normal_requests.csv` | QLDT PTIT Burp XML normal traffic | `0` |

QLDT PTIT không được đưa vào training mặc định. Nó được giữ làm external benchmark để kiểm tra false positive trên traffic bình thường thực tế.

## 6. Các script convert dữ liệu nguồn

Các script nằm trong:

```text
scripts/data_sources/
```

Vai trò từng script:

```text
process_malicious_zip.py
```

Convert dữ liệu OpenAppSec malicious thành `data/raw/positive/malicious_requests.csv`.

```text
process_normal_legitimate.py
```

Convert OpenAppSec legitimate traffic thành `data/raw/normal/legitimate_normal_requests.csv`. Script này cũng lọc bớt static/noise và redact dữ liệu nhạy cảm.

```text
process_csic_dataset.py
```

Convert `data/csic_database.csv` thành hai file:

```text
data/raw/normal/csic_normal_requests.csv
data/raw/positive/csic_attack_requests.csv
```

```text
process_modsec_learn_dataset.py
```

Convert ModSec-Learn dataset thành normal query strings và SQLi query payloads.

```text
process_owasp_modsec_logs.py
```

Parse audit logs ở:

```text
data/raw/owasp/*/modsec_audit.anon.log
```

và xuất ra:

```text
data/raw/positive/owasp_modsec_requests.csv
```

```text
import_luongvd_positive.py
```

Import dữ liệu attack từ collector bên ngoài về schema chung.

## 7. Pipeline xử lý dữ liệu

Các script pipeline nằm trong:

```text
scripts/pipeline/
```

### 7.1. Merge dataset

Script:

```text
scripts/pipeline/merge_dataset.py
```

Input mặc định:

```text
data/raw/positive/*.csv
data/raw/normal/legitimate_normal_requests.csv
data/raw/normal/csic_normal_requests.csv
data/raw/normal/modsec_learn_legitimate_requests.csv
```

Output:

```text
data/processed/requests_dataset.csv
```

File hiện tại có:

```text
12,857 rows
9,000 normal
3,857 attack
```

Tỷ lệ mặc định là khoảng:

```text
70% normal
30% attack
```

QLDT normal không được merge vào training mặc định.

### 7.2. Deduplicate và leakage reports

Script:

```text
scripts/pipeline/deduplicate_requests.py
```

Input:

```text
data/processed/requests_dataset.csv
```

Output:

```text
data/processed/requests_dataset_dedup.csv
```

Dataset dedup hiện tại có:

```text
10,332 rows
6,810 normal
3,522 attack
```

Script tạo thêm ba hash:

```text
canonical_raw_request_hash
endpoint_shape_hash
payload_family_hash
```

Ý nghĩa:

| Hash | Mục đích |
|---|---|
| `canonical_raw_request_hash` | Phát hiện request giống nhau sau khi chuẩn hóa |
| `endpoint_shape_hash` | Phát hiện cùng method/path/tên parameter |
| `payload_family_hash` | Phát hiện payload cùng họ như SQLi/XSS/traversal |

Báo cáo được ghi vào:

```text
data/reports/
```

Các file report:

```text
duplicate_report.csv
endpoint_shape_report.csv
payload_family_report.csv
label_conflict_report.csv
source_overlap_report.csv
```

Mục tiêu của bước này là giảm duplicate và phát hiện nguy cơ leakage giữa train/test.

### 7.3. Extract features

Script:

```text
scripts/pipeline/extract_features.py
```

Input:

```text
data/processed/requests_dataset_dedup.csv
```

Output:

```text
data/processed/features.csv
```

File `features.csv` hiện tại có:

```text
10,332 rows
72 columns
4 metadata columns
68 feature columns
```

Metadata columns:

```text
id, label, source, notes
```

Các cột còn lại là feature dùng để train model.

## 8. Canonicalization

File:

```text
src/request_canonicalizer.py
```

Nhiệm vụ của file này là chuẩn hóa request trước khi extract feature. Một request có thể bị obfuscate bằng URL encoding, double encoding, HTML entity, Unicode trick, hoặc path traversal. Vì vậy code tạo nhiều representation:

```text
raw
lowercase
URL decoded once
URL decoded recursive tối đa 3 vòng
HTML entity decoded
Unicode normalized
normalized path
query params giữ duplicate parameter names
```

Ví dụ:

```text
%252e%252e%252f
```

có thể decode nhiều vòng thành:

```text
../
```

Nếu chỉ nhìn raw string, model có thể bỏ sót traversal. Vì vậy feature extraction dùng cả raw và decoded text.

## 9. Feature extraction

File:

```text
src/feature_extractor.py
```

Hàm chính:

```python
extract_features(row: dict[str, str]) -> dict[str, int]
```

Feature được chia thành nhiều nhóm.

### Method features

```text
method_get
method_post
method_put
method_patch
method_delete
```

### URL/path/query structure

```text
path_depth
has_query
num_params
duplicate_param_count
max_duplicate_param_name_count
```

### Path semantic features

```text
has_api_path
has_admin_path
has_internal_path
has_debug_path
has_document_path
has_user_path
has_payment_path
has_upload_path
```

### Parameter name features

```text
has_id_param
has_url_param
has_file_param
has_business_param
has_search_param
```

### Value/payload features

```text
has_numeric_value
has_uuid_value
has_url_value
has_private_ip_value
has_base64_like_value
has_encoded_value
has_special_chars
has_double_encoded_value
decoded_changes_value
raw_encoded_ratio
has_html_entity_value
has_unicode_normalized_change
```

### Recursive decoded attack features

```text
has_recursive_decoded_traversal
has_recursive_decoded_sqli
has_recursive_decoded_xss
has_recursive_decoded_private_ip
has_recursive_decoded_url
```

### Header features

```text
has_authorization_header
has_cookie_header
has_content_type_json
has_content_type_form
has_content_type_xml
has_tenant_header
has_origin_header
has_referer_header
has_x_forwarded_for
```

### Body features

```text
has_json_body
has_xml_body
has_form_body
body_has_role
body_has_admin_value
body_has_id_field
body_has_url_field
body_has_file_field
body_has_price_field
```

### Interaction features

```text
has_admin_and_url
has_document_and_id
has_tenant_and_id
has_auth_and_id
has_write_method_and_id
has_upload_and_file
has_url_param_and_private_ip
has_role_and_admin_value
```

Interaction feature giúp model học các tổ hợp có ý nghĩa bảo mật. Ví dụ:

```text
has_url_param_and_private_ip
```

có thể là tín hiệu SSRF.

```text
has_role_and_admin_value
```

có thể là tín hiệu privilege escalation hoặc business logic abuse.

## 10. Notebook training

Notebook chính:

```text
notebooks/train_decision_tree.ipynb
```

Notebook hiện hỗ trợ cả local Jupyter/VS Code và Google Colab.

Nếu chạy ở Colab, cell setup sẽ mount Google Drive và dùng:

```text
/content/drive/MyDrive/processed/
```

Nếu chạy local, notebook bỏ qua `google.colab` và tự tìm repo local.

### Dữ liệu training

Notebook load:

```text
data/processed/features.csv
```

Sau đó tách:

```text
meta_cols = id, label, source, notes
X = toàn bộ feature columns
y = label
```

Split train/test:

```python
train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y,
)
```

`stratify=y` giữ tỷ lệ normal/attack tương đối ổn định giữa train và test.

## 11. Model trong notebook

Notebook train hai model:

```python
DecisionTreeClassifier(
    max_depth=8,
    min_samples_leaf=20,
    random_state=42,
)
```

và:

```python
RandomForestClassifier(
    n_estimators=200,
    min_samples_leaf=5,
    class_weight="balanced_subsample",
    n_jobs=-1,
    random_state=42,
)
```

Các model được lưu trong biến:

```python
fitted_models
```

Model đang dùng mặc định:

```python
ACTIVE_MODEL_NAME = "random_forest"
model = fitted_models[ACTIVE_MODEL_NAME]
```

Điểm rủi ro được tính bằng:

```python
y_prob = model.predict_proba(X_test)[:, 1]
risk_score = y_prob * 10
```

Ngưỡng phân loại:

```python
THRESHOLD = 5.0
y_pred = (risk_score >= THRESHOLD).astype(int)
```

Notebook cũng tạo bảng so sánh:

```text
model
accuracy_pct
roc_auc
avg_precision
pred_normal
pred_attack
```

Kết quả kiểm tra gần nhất trong môi trường local:

| Model | Accuracy | ROC-AUC | Average precision |
|---|---:|---:|---:|
| Random Forest | 94.10% | 0.9897 | 0.9818 |
| Decision Tree | 94.53% | 0.9836 | 0.9736 |

Decision Tree có accuracy nhỉnh hơn ở split này, nhưng Random Forest có ROC-AUC và average precision tốt hơn. Vì vậy notebook đang chọn Random Forest làm active model để chấm điểm tiếp.

## 12. Feature importance

Sau khi chọn active model, notebook hiển thị feature importance:

```python
importance = pd.DataFrame({
    "feature": feature_cols,
    "importance": model.feature_importances_,
}).sort_values("importance", ascending=False)
```

Với Random Forest, feature importance là trung bình đóng góp của feature qua nhiều cây. Nó giúp giải thích model đang dựa nhiều vào tín hiệu nào, ví dụ số parameter, encoding ratio, referer/header, recursive decoded signal.

## 13. Test CSV trong notebook

Notebook có helper:

```python
test_csv(filename, threshold=THRESHOLD, top_n=30, estimator=None, model_name=None)
```

Hàm này hỗ trợ hai loại input:

### Feature CSV

Nếu file đã có đủ feature columns, notebook dùng trực tiếp:

```python
X_ext = data.reindex(columns=feature_cols, fill_value=0)
scores = model.predict_proba(X_ext)[:, 1] * 10
```

Ví dụ:

```python
test_csv("features.csv")
```

### Raw request CSV

Nếu file chưa có feature columns, notebook gọi:

```python
extract_features(req)
```

rồi mới chấm điểm.

Điều này cho phép test các file như:

```text
qldt_ptit_normal_requests.csv
samplectf_requests.csv
```

## 14. Burp XML testing

File:

```text
src/burp_xml_converter.py
```

Hàm chính:

```python
convert_burp_xml_to_csv(...)
```

Nó đọc Burp Suite XML export, parse request, redact dữ liệu nhạy cảm, rồi ghi ra CSV theo schema chung.

Các dữ liệu nhạy cảm bị redact:

```text
authorization
cookie
set-cookie
x-api-key
x-csrf-token
x-xsrf-token
password
secret
token
xsrf
```

Cell Burp XML trong notebook hiện tìm file input ở nhiều vị trí:

```text
PROJECT_ROOT/<file>
current working directory/<file>
CODE_ROOT/<file>
CODE_ROOT/data/raw/<file>
CODE_ROOT/data/processed/<file>
DRIVE_PROCESSED_DIR/<file>
```

Vì vậy local file:

```text
data/raw/samplectf.xml
```

có thể được tìm thấy dù `PROJECT_ROOT` là `data/processed`.

Output CSV của Burp XML được ghi vào:

```text
data/processed/<stem>_requests.csv
```

sau đó được chấm điểm bằng `test_csv()`.

## 15. External QLDT benchmark

File:

```text
data/processed/qldt_ptit_normal_requests.csv
```

File này có:

```text
102 rows
label = 0
```

Nó dùng để test false positive trên traffic normal ngoài training set. Vì toàn bộ label là normal, mọi dòng bị predict `attack` đều là false positive.

## 16. Cách chạy lại toàn bộ pipeline

Chạy từ project root.

Trên Windows PowerShell có thể dùng:

```powershell
python scripts/data_sources/process_malicious_zip.py
python scripts/data_sources/process_normal_legitimate.py
python scripts/data_sources/process_csic_dataset.py
python scripts/data_sources/process_modsec_learn_dataset.py
python scripts/data_sources/process_owasp_modsec_logs.py
python scripts/external_tests/process_qldt_burp_xml.py
Copy-Item data/raw/normal/qldt_ptit_normal_requests.csv data/processed/qldt_ptit_normal_requests.csv
python scripts/pipeline/merge_dataset.py
python scripts/pipeline/deduplicate_requests.py
python scripts/pipeline/extract_features.py
```

Trên Linux/macOS:

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

Output cuối cùng cần có:

```text
data/processed/requests_dataset.csv
data/processed/requests_dataset_dedup.csv
data/processed/features.csv
data/processed/qldt_ptit_normal_requests.csv
```

## 17. Dependencies

File:

```text
requirements.txt
```

Dependencies chính:

```text
pandas
scikit-learn
joblib
```

Cài bằng:

```powershell
pip install -r requirements.txt
```

## 18. Cách chạy notebook local

Mở:

```text
notebooks/train_decision_tree.ipynb
```

Chạy từ trên xuống:

```text
1. Setup local/Colab path
2. Import dependencies và tìm CODE_ROOT/PROJECT_ROOT
3. Load features.csv
4. Train Decision Tree và Random Forest
5. Xem feature importance
6. Xem CSIC benchmark trong test split
7. Định nghĩa helper test_csv
8. Test Burp XML nếu có samplectf.xml
9. Test features.csv hoặc file ngoài
```

Nếu chạy local, không cần `google.colab`.

Nếu chạy Colab, cần có:

```text
/content/drive/MyDrive/processed/features.csv
/content/drive/MyDrive/processed/src/
```

Notebook có logic download/copy hỗ trợ Colab, nhưng local repo đầy đủ vẫn là cách ổn định nhất.

## 19. Lỗi thường gặp

### ModuleNotFoundError: google.colab

Lỗi này xảy ra khi chạy notebook local nhưng cell setup import cứng:

```python
from google.colab import drive
```

Notebook hiện đã được sửa để dùng:

```python
try:
    from google.colab import drive
    IS_COLAB = True
except ModuleNotFoundError:
    IS_COLAB = False
```

Local sẽ skip Google Drive setup.

### Burp XML file not found

Lỗi cũ:

```text
Skipping Burp XML test; file not found: .../data/processed/samplectf.xml
```

Nguyên nhân là `PROJECT_ROOT` trỏ tới `data/processed`, còn `samplectf.xml` nằm ở:

```text
data/raw/samplectf.xml
```

Notebook hiện đã được sửa để tìm XML ở nhiều vị trí, bao gồm `data/raw`.

### Không import được src.feature_extractor

Nguyên nhân thường là notebook không chạy từ project root hoặc thiếu thư mục `src`.

Cách xử lý:

```text
1. Mở notebook trong repo này.
2. Chạy cell setup/import từ đầu.
3. Đảm bảo có src/feature_extractor.py.
4. Nếu dùng Colab, upload cả src/ vào /content/drive/MyDrive/processed/src/.
```

### File features.csv không tồn tại

Nếu thiếu:

```text
data/processed/features.csv
```

hãy chạy lại pipeline extract features:

```powershell
python scripts/pipeline/extract_features.py
```

Nếu thiếu cả `requests_dataset_dedup.csv`, chạy lại từ merge/dedup.

## 20. Điểm mạnh của project

Project có một số điểm tốt:

```text
1. Có schema request chung cho nhiều nguồn dữ liệu.
2. Có bước canonicalization để xử lý encoding/obfuscation.
3. Có dedup và leakage reports trước khi train.
4. Có feature thủ công dễ giải thích.
5. Có external benchmark QLDT và Burp XML.
6. Có Decision Tree baseline và Random Forest cải tiến.
```

Random Forest giúp giảm phụ thuộc vào một cây đơn lẻ, thường ổn định hơn Decision Tree khi feature có nhiều tương tác.

## 21. Hạn chế hiện tại

Một số hạn chế cần chú ý:

```text
1. Dataset normal business flow còn chưa đa dạng.
2. Một số normal request có query parameter có thể bị chấm rủi ro cao.
3. Model chưa hiểu ngữ cảnh ứng dụng thật như authorization flow, role flow, tenant boundary.
4. Feature vẫn là thủ công, chưa dùng embedding hoặc sequence model.
5. Split hiện tại là row-level; endpoint/payload family grouping đã được report nhưng chưa dùng làm grouped split.
```

Ví dụ các request bình thường có thể dễ bị false positive nếu training data thiếu ví dụ tương tự:

```text
/product?id=123
/document?id=123
/callback?code=...&state=...
/redirect?next=/dashboard
/tenant/dashboard?tenant_id=...
```

Nguyên nhân là nhiều request attack cũng có dạng:

```text
GET + query + id/url-like parameter
```

Nếu normal data thiếu các pattern này, model có thể học nhầm rằng pattern đó luôn nguy hiểm.

## 22. Hướng cải tiến

Các hướng cải tiến thực tế:

```text
1. Thu thập thêm normal traffic từ app thật hoặc demo app như Juice Shop, crAPI.
2. Bổ sung normal business flows: product detail, order detail, callback, redirect, tenant dashboard.
3. Dùng grouped split theo endpoint_shape_hash hoặc payload_family_hash để giảm leakage tốt hơn.
4. Tuning Random Forest: max_depth, max_features, min_samples_leaf, class_weight.
5. Thử thêm Gradient Boosting, XGBoost, LightGBM nếu được phép thêm dependency.
6. Báo cáo metric theo source, không chỉ overall accuracy.
7. Theo dõi riêng false positive trên QLDT/Burp external normal logs.
8. Lưu model bằng joblib khi chọn được cấu hình cuối.
```

## 23. Tóm tắt ngắn gọn

Project này là một pipeline ML hoàn chỉnh cho HTTP request risk scoring:

```text
data collection
  -> normalization
  -> deduplication
  -> feature engineering
  -> Decision Tree baseline
  -> Random Forest active model
  -> external testing with CSV/Burp XML
```

File training chính là:

```text
data/processed/features.csv
```

Notebook chính là:

```text
notebooks/train_decision_tree.ipynb
```

Model active hiện tại là:

```text
Random Forest
```

Điểm đầu ra là:

```text
risk_score = probability_of_attack * 10
```

Toàn bộ thiết kế tập trung vào việc biến HTTP request thành các feature bảo mật dễ giải thích, sau đó dùng mô hình tree-based để phân biệt normal và attack.
