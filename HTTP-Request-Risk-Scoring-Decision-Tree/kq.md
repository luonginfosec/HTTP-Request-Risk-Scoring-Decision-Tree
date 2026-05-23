# Kết quả training và ý nghĩa

File này tổng hợp các kết quả chính từ notebook `notebooks/train_decision_tree.ipynb` và giải thích ý nghĩa trong bài toán chấm điểm rủi ro HTTP request.

## 1. Dữ liệu dùng để training

Notebook load dữ liệu từ:

```text
data/processed/features.csv
```

Thông tin dữ liệu:

| Hạng mục | Giá trị |
|---|---:|
| Tổng số dòng | 10,332 |
| Tổng số cột | 72 |
| Metadata columns | 4 |
| Feature columns dùng để train | 68 |
| Normal request, label `0` | 6,810 |
| Attack request, label `1` | 3,522 |

Tỷ lệ label:

| Label | Ý nghĩa | Số dòng | Tỷ lệ |
|---|---|---:|---:|
| `0` | Normal | 6,810 | 65.91% |
| `1` | Attack / suspicious | 3,522 | 34.09% |

Phân bố theo nguồn dữ liệu:

| Source | Số dòng | Ý nghĩa |
|---|---:|---|
| `openappsec_legitimate` | 3,000 | Request bình thường từ OpenAppSec legitimate traffic |
| `modsec_learn_legitimate` | 2,990 | Request bình thường từ ModSec-Learn |
| `csic_2010` | 1,483 | Dữ liệu CSIC gồm cả normal và anomalous |
| `openappsec_malicious` | 1,053 | Request tấn công từ OpenAppSec malicious |
| `modsec_learn_sqli` | 789 | SQL injection payloads |
| `exploitdb` | 513 | Request tấn công từ ExploitDB/local collector |
| `owasp_modsecurity` | 504 | Request tấn công từ OWASP ModSecurity audit logs |

## 2. Cách chia train/test

Notebook dùng `train_test_split`:

```python
train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y,
)
```

Ý nghĩa:

| Thành phần | Số dòng |
|---|---:|
| Train set | 8,265 |
| Test set hold-out | 2,067 |
| Normal trong test set | 1,362 |
| Attack trong test set | 705 |

`stratify=y` giúp giữ tỷ lệ normal/attack ở train set và test set tương đối giống nhau. Test set hold-out là phần quan trọng nhất để đánh giá vì model không được train trực tiếp trên phần này.

## 3. Cấu hình model

Notebook train hai model:

| Model | Cấu hình | Vai trò |
|---|---|---|
| Decision Tree | `max_depth=8`, `min_samples_leaf=20`, `random_state=42` | Baseline, dễ giải thích |
| Random Forest | `n_estimators=200`, `min_samples_leaf=5`, `class_weight="balanced_subsample"`, `n_jobs=-1`, `random_state=42` | Model active hiện tại |

Ngưỡng phân loại:

```text
risk_score = P(attack) * 10
```

```text
risk_score >= 5.0 -> attack
risk_score < 5.0  -> normal
```

## 4. Ý nghĩa các metric

| Metric | Ý nghĩa |
|---|---|
| Accuracy | Tỷ lệ dự đoán đúng trên toàn bộ test set |
| Precision của attack | Trong các request bị báo attack, có bao nhiêu request thật sự là attack |
| Recall của attack | Trong các attack thật, model phát hiện được bao nhiêu |
| F1-score | Trung bình điều hòa giữa precision và recall |
| ROC-AUC | Khả năng xếp điểm attack cao hơn normal trên nhiều threshold |
| Average Precision | Chất lượng xếp hạng attack theo Precision-Recall curve |
| False Positive | Normal bị báo nhầm thành attack |
| False Negative | Attack bị bỏ sót thành normal |

Trong bài toán security, `False Negative` thường nguy hiểm hơn vì hệ thống bỏ lọt request tấn công. Tuy nhiên `False Positive` cũng quan trọng vì nếu quá nhiều request bình thường bị chặn, hệ thống sẽ khó dùng thực tế.

## 5. Kết quả trên hold-out test set

### Bảng metric chính

| Model | Accuracy | ROC-AUC | Average Precision | Pred normal | Pred attack |
|---|---:|---:|---:|---:|---:|
| Decision Tree | 94.53% | 0.9836 | 0.9736 | 1,425 | 642 |
| Random Forest | 94.10% | 0.9897 | 0.9818 | 1,342 | 725 |

### Confusion matrix chi tiết

| Model | True Normal -> Pred Normal | True Normal -> Pred Attack | True Attack -> Pred Normal | True Attack -> Pred Attack |
|---|---:|---:|---:|---:|
| Decision Tree | 1,337 | 25 | 88 | 617 |
| Random Forest | 1,291 | 71 | 51 | 654 |

Diễn giải:

| Model | Attack precision | Attack recall | False positive rate | False negative rate |
|---|---:|---:|---:|---:|
| Decision Tree | 96.11% | 87.52% | 1.84% | 12.48% |
| Random Forest | 90.21% | 92.77% | 5.21% | 7.23% |

## 6. Nhận xét về Decision Tree

Decision Tree có:

```text
Accuracy = 94.53%
ROC-AUC = 0.9836
Average Precision = 0.9736
```

Điểm mạnh:

| Điểm | Ý nghĩa |
|---|---|
| Accuracy cao hơn Random Forest một chút | Trên split hiện tại, Decision Tree dự đoán đúng tổng thể nhiều hơn |
| False positive thấp | Chỉ 25 normal request bị báo nhầm attack |
| Dễ giải thích | Có thể lần theo nhánh cây để hiểu vì sao model dự đoán attack/normal |

Điểm yếu:

| Điểm | Ý nghĩa |
|---|---|
| False negative cao hơn | Bỏ sót 88 attack, nhiều hơn Random Forest |
| Attack recall thấp hơn | Chỉ phát hiện 87.52% attack trong test set |
| Phụ thuộc vào một cây duy nhất | Dữ liệu thay đổi có thể làm cấu trúc cây thay đổi mạnh |

Kết luận: Decision Tree phù hợp làm baseline và giải thích mô hình, nhưng chưa phải lựa chọn tốt nhất nếu ưu tiên phát hiện attack.

## 7. Nhận xét về Random Forest

Random Forest có:

```text
Accuracy = 94.10%
ROC-AUC = 0.9897
Average Precision = 0.9818
```

So với Decision Tree:

| So sánh | Kết quả |
|---|---|
| Attack phát hiện đúng | 654, cao hơn Decision Tree 37 request |
| Attack bị bỏ sót | 51, thấp hơn Decision Tree 37 request |
| Normal bị báo nhầm attack | 71, cao hơn Decision Tree 46 request |
| ROC-AUC | Cao hơn |
| Average Precision | Cao hơn |

Ý nghĩa:

Random Forest chấp nhận nhiều false positive hơn để giảm false negative. Với bài toán security, trade-off này hợp lý hơn vì bỏ sót attack thường nguy hiểm hơn báo nhầm một request normal.

Vì vậy notebook chọn:

```python
ACTIVE_MODEL_NAME = "random_forest"
```

## 8. Feature importance của Random Forest

Top 15 feature quan trọng nhất:

| Feature | Importance | Ý nghĩa |
|---|---:|---|
| `num_params` | 0.151236 | Số lượng parameter trong query/body là tín hiệu mạnh |
| `has_numeric_value` | 0.108040 | Giá trị số xuất hiện nhiều trong cả normal và attack, giúp tách pattern |
| `raw_encoded_ratio` | 0.098616 | Tỷ lệ ký tự encoded cao có thể liên quan payload obfuscation |
| `has_referer_header` | 0.081989 | Header referer giúp phân biệt traffic web bình thường và request bất thường |
| `has_recursive_decoded_url` | 0.074553 | URL sau khi decode nhiều vòng là tín hiệu quan trọng |
| `has_url_value` | 0.059252 | Parameter chứa URL có thể liên quan redirect, SSRF hoặc callback |
| `path_depth` | 0.052972 | Độ sâu path giúp phân biệt endpoint bình thường và payload traversal |
| `decoded_changes_value` | 0.042568 | Giá trị thay đổi sau decode cho thấy có encoding |
| `has_recursive_decoded_sqli` | 0.039899 | Dấu hiệu SQL injection sau decode nhiều vòng |
| `has_base64_like_value` | 0.033119 | Chuỗi giống base64 có thể là payload encode |
| `has_origin_header` | 0.031651 | Origin header liên quan traffic browser/CORS |
| `has_encoded_value` | 0.028782 | Có URL encoding hoặc dạng encoded khác |
| `has_cookie_header` | 0.021867 | Cookie header giúp nhận diện traffic session bình thường |
| `has_query` | 0.016637 | Request có query string hay không |
| `has_special_chars` | 0.016493 | Ký tự đặc biệt thường xuất hiện trong payload attack |

Lưu ý: feature importance không có nghĩa là feature đó luôn gây ra attack. Nó chỉ cho biết model thường dùng feature đó để chia dữ liệu trong các cây.

## 9. Kết quả riêng trên CSIC trong test set

Notebook lọc riêng source:

```text
csic_2010
```

Kết quả:

| Hạng mục | Giá trị |
|---|---:|
| Số dòng CSIC trong test set | 304 |
| Accuracy | 72.70% |

Confusion matrix:

| Thực tế | Pred normal | Pred attack |
|---|---:|---:|
| True normal | 110 | 55 |
| True attack | 28 | 111 |

Breakdown theo `notes`:

| Notes | Label | Pred label | Count |
|---|---:|---:|---:|
| `csic_normal` | 0 | 0 | 110 |
| `csic_anomalous` | 1 | 1 | 103 |
| `csic_normal` | 0 | 1 | 55 |
| `csic_anomalous` | 1 | 0 | 28 |
| `csic_xss` | 1 | 1 | 3 |
| `csic_sqli` | 1 | 1 | 2 |
| `csic_traversal` | 1 | 1 | 2 |
| `csic_crlf` | 1 | 1 | 1 |

Ý nghĩa:

CSIC là phần khó hơn so với overall test set. Accuracy chỉ 72.70%, thấp hơn nhiều so với 94.10% overall của Random Forest. Model vẫn phát hiện được phần lớn attack CSIC, nhưng false positive trên `csic_normal` khá cao: 55 normal request bị báo attack.

Điều này cho thấy model có thể đang nhạy với một số pattern query/path trong CSIC normal. Khi đưa vào thực tế, cần theo dõi false positive theo từng nguồn traffic, không chỉ nhìn metric tổng.

## 10. Kết quả test Burp XML `samplectf.xml`

Notebook convert:

```text
data/raw/samplectf.xml
```

thành:

```text
data/processed/samplectf_requests.csv
```

Kết quả test:

| Hạng mục | Giá trị |
|---|---:|
| Số request | 6 |
| Mode | `raw_request` |
| Label gán cho file | `0` normal |
| Threshold | 5.0 |
| Accuracy | 50.00% |

Classification report:

| Class | Precision | Recall | F1-score | Support |
|---|---:|---:|---:|---:|
| Normal | 1.0000 | 0.5000 | 0.6667 | 6 |
| Attack | 0.0000 | 0.0000 | 0.0000 | 0 |

Confusion matrix:

| Thực tế | Pred normal | Pred attack |
|---|---:|---:|
| True normal | 3 | 3 |
| True attack | 0 | 0 |

Các request có điểm cao nhất:

| ID | URL / Path | Risk score | Predicted | Nhận xét |
|---|---|---:|---|---|
| `burp_external_000001` | `/somepath?file=%252E%252E...` | 9.33 | attack | Có double encoding giống traversal, bị model chấm rất nguy hiểm |
| `burp_external_000006` | `https://www.google.com/warmup.html` | 8.36 | attack | False positive rõ ràng hơn, cần xem lại feature/header/context |
| `burp_external_000005` | `/` trên localhost | 7.18 | attack | False positive trên request đơn giản |
| `burp_external_000004` | `/app.js` | 3.30 | normal | Được chấm bình thường |
| `burp_external_000003` | `/favicon.ico` | 3.30 | normal | Được chấm bình thường |
| `burp_external_000002` | `/api/coolbeans` | 2.86 | normal | Được chấm bình thường |

Threshold analysis:

| Threshold | Accuracy | Pred normal | Pred attack |
|---:|---:|---:|---:|
| 3.0 | 16.67% | 1 | 5 |
| 4.0 | 50.00% | 3 | 3 |
| 5.0 | 50.00% | 3 | 3 |
| 6.0 | 50.00% | 3 | 3 |
| 7.0 | 50.00% | 3 | 3 |
| 8.0 | 66.67% | 4 | 2 |

Ý nghĩa:

Vì file này được gán toàn bộ label `0`, mọi request bị báo `attack` đều được tính là false positive. Tuy nhiên request đầu tiên chứa payload double-encoded traversal rất đáng nghi, nên việc model báo attack là hợp lý về mặt bảo mật dù label đang là normal.

Hai false positive còn lại cho thấy model vẫn có thể chấm điểm cao với một số normal request ngoài phân phối training. Đây là lý do cần external benchmark normal đa dạng hơn.

## 11. Kết quả test lại toàn bộ `features.csv`

Notebook cũng chạy:

```python
test_csv("features.csv")
```

Kết quả:

| Hạng mục | Giá trị |
|---|---:|
| Số dòng | 10,332 |
| Mode | `feature` |
| Model | `random_forest` |
| Threshold | 5.0 |
| Accuracy | 94.91% |

Classification report:

| Class | Precision | Recall | F1-score | Support |
|---|---:|---:|---:|---:|
| Normal | 0.9685 | 0.9537 | 0.9611 | 6,810 |
| Attack | 0.9131 | 0.9401 | 0.9264 | 3,522 |
| Accuracy |  |  | 0.9491 | 10,332 |
| Macro avg | 0.9408 | 0.9469 | 0.9437 | 10,332 |
| Weighted avg | 0.9496 | 0.9491 | 0.9493 | 10,332 |

Confusion matrix:

| Thực tế | Pred normal | Pred attack |
|---|---:|---:|
| True normal | 6,495 | 315 |
| True attack | 211 | 3,311 |

Threshold analysis:

| Threshold | Accuracy | Pred normal | Pred attack |
|---:|---:|---:|---:|
| 3.0 | 89.80% | 5,808 | 4,524 |
| 4.0 | 92.83% | 6,273 | 4,059 |
| 5.0 | 94.91% | 6,706 | 3,626 |
| 6.0 | 95.79% | 7,091 | 3,241 |
| 7.0 | 94.13% | 7,315 | 3,017 |
| 8.0 | 92.61% | 7,482 | 2,850 |

Ý nghĩa:

Kết quả trên toàn bộ `features.csv` không phải là đánh giá khách quan như hold-out test set, vì file này bao gồm cả dữ liệu đã dùng để train. Nó hữu ích để xem model chấm điểm toàn bộ dataset như thế nào, nhưng không nên dùng làm kết luận chính về khả năng tổng quát hóa.

Threshold `6.0` cho accuracy cao nhất trên toàn bộ `features.csv`, nhưng nếu tăng threshold thì số request bị báo attack giảm. Điều này có thể làm giảm false positive, nhưng cũng có nguy cơ bỏ sót attack. Vì vậy threshold cần được chọn theo mục tiêu vận hành:

| Mục tiêu | Nên làm |
|---|---|
| Ưu tiên bắt nhiều attack | Giữ threshold thấp hơn, ví dụ 5.0 |
| Ưu tiên giảm false positive | Tăng threshold, ví dụ 6.0 hoặc cao hơn |
| Muốn dùng thực tế | Cần benchmark thêm trên traffic normal ngoài training |

## 12. Kết luận chung

Kết quả training cho thấy cả Decision Tree và Random Forest đều học được tín hiệu phân biệt normal/attack từ 68 feature thủ công.

Decision Tree có accuracy cao hơn một chút và ít false positive hơn, nhưng bỏ sót nhiều attack hơn. Random Forest có ROC-AUC và Average Precision cao hơn, đồng thời giảm số attack bị bỏ sót từ 88 xuống 51 trên hold-out test set.

Với bài toán HTTP request risk scoring, Random Forest phù hợp hơn làm model active vì:

```text
1. Phát hiện attack tốt hơn.
2. False negative thấp hơn.
3. ROC-AUC và Average Precision cao hơn.
4. Ổn định hơn một Decision Tree đơn lẻ.
```

Tuy nhiên, kết quả CSIC và Burp XML cho thấy model vẫn có false positive trên traffic normal ngoài phân phối training. Vì vậy khi báo cáo, cần nhấn mạnh rằng model hiện tại là một hệ thống risk scoring hỗ trợ phát hiện request đáng nghi, chưa nên xem là bộ chặn tuyệt đối nếu chưa calibrate threshold và kiểm thử thêm trên traffic thực tế.

## 13. Hướng cải thiện sau training

Các việc nên làm tiếp:

```text
1. Bổ sung thêm normal traffic thật để giảm false positive.
2. Đánh giá riêng theo từng source, từng attack family và từng endpoint type.
3. Dùng grouped split theo endpoint_shape_hash hoặc payload_family_hash để giảm leakage.
4. Tuning threshold theo mục tiêu: giảm false negative hoặc giảm false positive.
5. Calibrate xác suất để risk_score phản ánh rủi ro thực tế tốt hơn.
6. Theo dõi riêng QLDT/Burp normal logs như external benchmark.
7. Lưu model cuối bằng joblib sau khi chọn threshold và cấu hình ổn định.
```
