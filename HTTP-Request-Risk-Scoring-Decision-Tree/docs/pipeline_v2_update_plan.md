# Pipeline Update Plan V2

## 1. Nhận xét tổng quan

Pipeline hiện tại đã đủ để demo ý tưởng học có giám sát:

```text
raw request -> merge dataset -> extract feature -> train Decision Tree -> risk_score
```

Tuy nhiên kết quả manual test còn nhiều false positive với các request normal dạng:

```text
GET /product?id=123
GET /document?id=123
GET /callback?code=...&state=...
GET /redirect?next=/dashboard
GET /tenant/dashboard?tenant_id=...
```

Lý do chính không nằm ở Decision Tree, mà nằm ở chất lượng pipeline dữ liệu:

- Feature hiện tại còn thô, chưa canonicalize payload tốt.
- Có thể tồn tại duplicate hoặc near-duplicate giữa train/test.
- Split hiện tại chủ yếu là random stratified split, dễ làm model học đặc trưng của dataset thay vì học đặc trưng request nguy hiểm.
- Normal data chưa đủ nhiều request nghiệp vụ có query/id/url/callback/tenant.
- `predict_proba` của Decision Tree chưa nên hiểu là xác suất nguy cơ thật ngoài đời.

V2 nên tập trung nâng cấp tiền xử lý và đánh giá trước khi đổi sang mô hình phức tạp hơn.

## 2. Mục tiêu V2

Mục tiêu kỹ thuật:

- Giữ scoring thuần bằng model, không thêm hard-code rule trong lúc đánh giá.
- Chuẩn hóa request trước khi extract feature nhưng vẫn giữ tín hiệu raw/obfuscated.
- Giảm data leakage do duplicate hoặc payload giống nhau.
- Đánh giá model bằng nhiều benchmark thay vì chỉ random split.
- Bổ sung normal traffic khó hơn để giảm false positive.
- Hiệu chỉnh risk score để dễ diễn giải hơn.

Output kỳ vọng:

```text
0-3   likely benign
3-6   suspicious / review
6-8   likely attack
8-10  high-confidence attack
```

Ngưỡng `5.0` vẫn có thể dùng tạm để phân loại normal/attack trong notebook, nhưng không nên coi là ngưỡng cố định cuối cùng.

## 3. Ưu tiên 1: Canonicalization trước khi extract feature

### Vấn đề

Payload giống nhau có thể được viết theo nhiều dạng:

```text
../etc/passwd
..%2f..%2fetc%2fpasswd
%252e%252e%252fetc%252fpasswd
```

Nếu chỉ extract feature trên raw string, model có thể miss payload bị encode. Nếu decode quá mạnh và bỏ raw string, model lại mất tín hiệu obfuscation.

### Cách sửa

Thêm module canonicalization trước `src/feature_extractor.py`.

File đề xuất:

```text
src/request_canonicalizer.py
```

Mỗi request nên có nhiều representation:

```text
raw_value
lowercase_value
url_decoded_once
url_decoded_recursive_3
html_entity_decoded
unicode_normalized
normalized_path
parsed_query_with_duplicate_params
```

Nguyên tắc:

- Không thay thế raw bằng decoded.ư
- Giữ cả raw feature và decoded feature.
- Extract feature trên cả hai lớp:
  - raw signal: có `%25`, `%2f`, encoded nhiều lớp, ký tự lạ.
  - decoded signal: có `../`, `/etc/passwd`, `<script>`, `union select`, `localhost`.

### Việc cần làm

1. Tạo `src/request_canonicalizer.py`.
2. Update `src/feature_extractor.py` để dùng output canonical.
3. Thêm feature mới:

```text
has_double_encoding
has_recursive_decoded_traversal
has_recursive_decoded_sqli
has_recursive_decoded_xss
has_recursive_decoded_private_ip
raw_encoded_ratio
decoded_changes_value
duplicate_param_count
max_duplicate_param_name_count
```

## 4. Ưu tiên 2: Duplicate và near-duplicate removal

### Vấn đề

Security ML dataset rất dễ bị leakage:

- Cùng request xuất hiện ở cả label `0` và `1`.
- Cùng request xuất hiện ở nhiều source.
- Payload gần giống nhau nằm cả train và test.

Khi đó benchmark random split có thể cao giả tạo.

### Cách sửa

Thêm bước kiểm tra trước khi split.

File đề xuất:

```text
scripts/pipeline/deduplicate_requests.py
```

Tạo các hash:

```text
canonical_raw_request_hash
method_normalized_path_sorted_param_names_hash
payload_family_hash
```

Ý nghĩa:

- `canonical_raw_request_hash`: phát hiện request gần như trùng hoàn toàn.
- `method_normalized_path_sorted_param_names_hash`: phát hiện cùng endpoint/shape dù value khác.
- `payload_family_hash`: phát hiện cùng loại payload như traversal, SQLi, XSS, SSRF.

### Việc cần làm

1. Deduplicate trong từng source.
2. Kiểm tra conflict label:

```text
same hash nhưng vừa label 0 vừa label 1
```

3. Xuất report:

```text
data/reports/duplicate_report.csv
data/reports/label_conflict_report.csv
```

4. Với conflict label:
   - Không tự sửa bằng rule.
   - Ghi ra report để kiểm tra nguồn.
   - Loại khỏi training nếu không xác định được label đúng.

## 5. Ưu tiên 3: Split theo source/app/payload family

### Vấn đề

Random stratified split chỉ kiểm tra model có học được pattern trong cùng phân phối dữ liệu không. Nó không trả lời được câu hỏi model có generalize sang source khác không.

### Cách sửa

Notebook nên có 3 benchmark:

```text
Benchmark A: random stratified split
Benchmark B: source-aware split
Benchmark C: leave-one-source-out
```

### Benchmark A: Random stratified split

Dùng để so sánh baseline nhanh.

```text
train/test có cùng tỷ lệ label
```

Nếu A tốt, nghĩa là model học được pattern trong dataset hiện tại.

### Benchmark B: Source-aware split

Không để cùng source group rơi cả train và test nếu có thể.

Group có thể là:

```text
source
source_url
app_name
```

Nếu B giảm mạnh so với A, model đang học artifact của source.

### Benchmark C: Leave-one-source-out

Train trên các source còn lại, test trên một source bị giữ lại.

Ví dụ:

```text
train: luongvd + openappsec + csic normal
test:  csic attack/normal
```

Hoặc:

```text
train: luongvd + csic + openappsec malicious
test:  openappsec legitimate
```

Nếu C kém, cần thêm dữ liệu hoặc feature tổng quát hơn.

### Việc cần làm

1. Thêm file:

```text
scripts/pipeline/evaluate_splits.py
```

2. Notebook hiển thị ngắn gọn:

```text
accuracy
precision
recall
f1
confusion matrix
false positive rate
false negative rate
```

3. Report theo source:

```text
source, rows, accuracy, precision, recall, f1, fpr, fnr
```

## 6. Ưu tiên 4: Bổ sung hard negatives từ traffic normal thật

### Làm rõ khái niệm

Hard negative ở đây không phải hard-code logic và không phải request tự bịa để ép model.

Hard negative nghĩa là request bình thường thật nhưng có hình dạng dễ bị model hiểu nhầm là nguy hiểm.

Ví dụ:

```text
GET /product?id=123
GET /document?id=123
GET /orders?id=123
GET /callback?code=abc&state=xyz
GET /redirect?next=/dashboard
GET /tenant/dashboard?tenant_id=123
POST /api/profile/me {"display_name":"alice"}
POST /api/cart/items {"product_id":123,"quantity":1}
```

Đây là phần quan trọng nhất để giảm false positive.

### Nguồn đề xuất

Nên thu thập từ app local hoặc dataset public có normal traffic:

```text
OWASP Juice Shop
OWASP crAPI
demo ecommerce/API app
OAuth demo flow
tenant/multitenant dashboard
file/document management app
search/order/payment flows
```

### Dữ liệu cần ưu tiên

Normal request cần có nhiều endpoint như:

```text
product detail
search
order detail
checkout/payment
profile update
OAuth callback
relative redirect
tenant dashboard
document download
file upload hợp lệ
API GET có id
API POST JSON có id
```

### Việc cần làm

1. Tạo folder:

```text
data/raw/normal/hard_negative_collected/
```

2. Viết converter cho từng nguồn:

```text
scripts/data_sources/process_juice_shop_normal.py
scripts/data_sources/process_crapi_normal.py
```

3. Mỗi row vẫn dùng schema chung:

```csv
id,label,source,source_url,method,url,path,query_string,headers,body,raw_request,notes
```

4. Mục tiêu ban đầu:

```text
normal hard negatives: 1,000 - 3,000 rows
```

5. Không thêm vào test thủ công như dữ liệu train nếu mục tiêu là kiểm tra generalization. Nên giữ một phần làm held-out app test.

## 7. Ưu tiên 5: Calibration risk_score

### Vấn đề

Hiện tại:

```text
risk_score = P(label=1) * 10
```

Nhưng dataset training đang có tỷ lệ khoảng:

```text
normal: 70%
attack: 30%
```

Trong traffic thật, request attack thường thấp hơn rất nhiều. Vì vậy `predict_proba` của Decision Tree không nên được hiểu là xác suất thật ngoài đời.

### Cách sửa

Thêm validation set riêng và calibration:

```text
CalibratedClassifierCV(method="isotonic")
CalibratedClassifierCV(method="sigmoid")
```

`sigmoid` tương ứng Platt scaling, thường ổn khi data không quá lớn. `isotonic` linh hoạt hơn nhưng dễ overfit nếu validation set nhỏ.

### Threshold tuning

Không cố định một threshold duy nhất ngay từ đầu. Report theo nhiều threshold:

```text
threshold 3.0
threshold 5.0
threshold 7.0
threshold 8.0
```

Với security monitoring:

- Muốn ít miss attack: chọn threshold thấp hơn, recall cao hơn.
- Muốn ít false positive: chọn threshold cao hơn, precision cao hơn.

### Việc cần làm

1. Split thành:

```text
train
validation
test
```

2. Train Decision Tree trên train.
3. Calibrate probability trên validation.
4. Test cuối cùng trên test.
5. Notebook hiển thị:

```text
precision/recall/f1 theo nhiều threshold
calibration curve
risk band distribution
```

## 8. Thay đổi file dự kiến

### File mới

```text
src/request_canonicalizer.py
scripts/pipeline/deduplicate_requests.py
scripts/pipeline/evaluate_splits.py
scripts/data_sources/process_juice_shop_normal.py
scripts/data_sources/process_crapi_normal.py
data/reports/duplicate_report.csv
data/reports/label_conflict_report.csv
```

### File cần sửa

```text
src/feature_extractor.py
scripts/pipeline/extract_features.py
scripts/pipeline/merge_dataset.py
notebooks/train_decision_tree.ipynb
docs/data_processing_to_training.md
```

## 9. Thứ tự triển khai khuyến nghị

### Phase 1: Canonicalization và feature V2

Mục tiêu:

```text
model không miss payload encode/obfuscate đơn giản
```

Deliverable:

```text
src/request_canonicalizer.py
feature_extractor.py dùng cả raw + decoded signals
features.csv có thêm canonicalization features
```

### Phase 2: Deduplication và leakage report

Mục tiêu:

```text
giảm benchmark ảo do trùng dữ liệu
```

Deliverable:

```text
deduplicated requests_dataset.csv
duplicate_report.csv
label_conflict_report.csv
```

### Phase 3: Benchmark lại

Mục tiêu:

```text
biết model học attack pattern thật hay học dataset artifact
```

Deliverable:

```text
random stratified benchmark
source-aware benchmark
leave-one-source-out benchmark
per-source metric table
```

### Phase 4: Bổ sung hard negatives normal thật

Mục tiêu:

```text
giảm false positive với request normal có query/id/url/callback/tenant
```

Deliverable:

```text
1,000 - 3,000 normal hard-negative rows
manual test normal GET/query giảm risk rõ rệt
openappsec_legitimate false positive rate giảm
```

### Phase 5: Calibration và threshold report

Mục tiêu:

```text
risk_score dễ diễn giải hơn và threshold có cơ sở hơn
```

Deliverable:

```text
calibrated model
threshold table
risk band report
```

## 10. Tiêu chí đánh giá V2

Không chỉ nhìn accuracy. Nên báo cáo:

```text
precision
recall
f1
false positive rate
false negative rate
confusion matrix
per-source metrics
threshold metrics
```

Tiêu chí quan trọng nhất cho bài toán này:

- False positive rate trên normal traffic thật phải giảm.
- Recall trên attack obvious không được giảm quá mạnh.
- Kết quả source-aware và leave-one-source-out không được thấp quá xa random split.
- Manual test chỉ dùng để minh họa điểm mạnh/yếu, không dùng làm benchmark chính.

## 11. Kết luận

Hướng update V2 đúng không phải là thêm rule thủ công vào scoring, mà là sửa pipeline dữ liệu:

```text
canonicalize tốt hơn
deduplicate trước khi split
split nghiêm ngặt hơn
thêm hard negatives từ traffic normal thật
calibrate score và tune threshold
```

Sau V2, đề tài vẫn nằm trong phạm vi học có giám sát và Decision Tree, nhưng có pipeline dữ liệu chặt chẽ hơn, giảm overfitting và giải thích được rõ hơn khi trình bày với giảng viên.
