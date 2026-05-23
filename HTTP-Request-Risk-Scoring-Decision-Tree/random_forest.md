# Các đoạn triển khai Random Forest và ý nghĩa code

Tài liệu này chỉ ra các đoạn Random Forest đã được triển khai trong notebook:

```text
notebooks/train_decision_tree.ipynb
```

Random Forest trong project được dùng làm model active để chấm điểm rủi ro HTTP request.

## 1. Import Random Forest

Đoạn code:

```python
from sklearn.ensemble import RandomForestClassifier
```

Ý nghĩa:

| Thành phần | Ý nghĩa |
|---|---|
| `sklearn.ensemble` | Module chứa các thuật toán ensemble trong scikit-learn |
| `RandomForestClassifier` | Thuật toán Random Forest dùng cho bài toán phân loại |

Trong project này, bài toán phân loại là:

```text
0 = normal
1 = attack / suspicious
```

Random Forest là tập hợp nhiều Decision Tree. Thay vì chỉ dùng một cây quyết định, model train nhiều cây và tổng hợp dự đoán của các cây đó để đưa ra kết quả ổn định hơn.

## 2. Khai báo cấu hình Random Forest

Đoạn code:

```python
MODEL_CONFIGS = {
    'decision_tree': DecisionTreeClassifier(max_depth=8, min_samples_leaf=20, random_state=42),
    'random_forest': RandomForestClassifier(
        n_estimators=200,
        min_samples_leaf=5,
        class_weight='balanced_subsample',
        n_jobs=-1,
        random_state=42,
    ),
}
```

Ý nghĩa:

| Dòng code | Ý nghĩa |
|---|---|
| `MODEL_CONFIGS = {...}` | Tạo dictionary chứa các model cần train và so sánh |
| `'decision_tree': ...` | Giữ Decision Tree làm baseline |
| `'random_forest': RandomForestClassifier(...)` | Thêm Random Forest vào danh sách model |

Ý nghĩa các tham số Random Forest:

| Tham số | Ý nghĩa |
|---|---|
| `n_estimators=200` | Random Forest sẽ train 200 cây quyết định |
| `min_samples_leaf=5` | Mỗi lá cây phải có ít nhất 5 sample, giúp giảm overfit |
| `class_weight='balanced_subsample'` | Cân bằng trọng số class trong từng bootstrap sample |
| `n_jobs=-1` | Dùng tối đa CPU cores để train nhanh hơn |
| `random_state=42` | Cố định random seed để kết quả có thể tái lập |

Vì sao cần `class_weight='balanced_subsample'`:

```text
Dataset có 6,810 normal và 3,522 attack.
Tỷ lệ normal nhiều hơn attack.
```

Nếu không cân bằng, model có thể thiên về class normal. Tham số này giúp Random Forest chú ý hơn đến class attack trong quá trình train.

## 3. Tạo nơi lưu model và kết quả dự đoán

Đoạn code:

```python
fitted_models = {}
evaluation_rows = []
model_predictions = {}
```

Ý nghĩa:

| Biến | Ý nghĩa |
|---|---|
| `fitted_models` | Lưu model đã train xong |
| `evaluation_rows` | Lưu metric đánh giá từng model |
| `model_predictions` | Lưu `risk_score` và label dự đoán của từng model |

Sau khi chạy xong, Random Forest được lưu trong:

```python
fitted_models['random_forest']
```

## 4. Train Random Forest

Đoạn code:

```python
for model_name, estimator in MODEL_CONFIGS.items():
    estimator.fit(X_train, y_train)
```

Ý nghĩa:

| Thành phần | Ý nghĩa |
|---|---|
| `for model_name, estimator in MODEL_CONFIGS.items()` | Lặp qua từng model trong dictionary |
| `model_name` | Tên model, ví dụ `decision_tree` hoặc `random_forest` |
| `estimator` | Object model scikit-learn |
| `estimator.fit(X_train, y_train)` | Train model bằng dữ liệu training |

Khi vòng lặp chạy đến:

```python
model_name = 'random_forest'
```

thì lệnh:

```python
estimator.fit(X_train, y_train)
```

sẽ train Random Forest trên tập training.

Dữ liệu đưa vào:

| Biến | Ý nghĩa |
|---|---|
| `X_train` | Các feature đã trích xuất từ HTTP request |
| `y_train` | Label thật: `0` normal, `1` attack |

## 5. Random Forest dự đoán xác suất attack

Đoạn code:

```python
scores = estimator.predict_proba(X_test)[:, 1] * 10
```

Ý nghĩa:

| Thành phần | Ý nghĩa |
|---|---|
| `predict_proba(X_test)` | Dự đoán xác suất cho từng class |
| `[:, 1]` | Lấy xác suất class `1`, tức attack |
| `* 10` | Đổi xác suất attack thành điểm rủi ro từ 0 đến 10 |

Ví dụ:

```text
P(attack) = 0.82
risk_score = 0.82 * 10 = 8.2
```

Trong project, output chính không chỉ là normal/attack mà là:

```text
risk_score = P(attack) * 10
```

Điểm càng cao thì request càng đáng nghi.

## 6. Phân loại bằng threshold

Đoạn code:

```python
preds = (scores >= THRESHOLD).astype(int)
```

Ý nghĩa:

| Thành phần | Ý nghĩa |
|---|---|
| `scores >= THRESHOLD` | So sánh điểm rủi ro với ngưỡng |
| `THRESHOLD = 5.0` | Ngưỡng mặc định |
| `.astype(int)` | Đổi `True/False` thành `1/0` |

Quy tắc phân loại:

```text
risk_score >= 5.0 -> pred_label = 1 -> attack
risk_score < 5.0  -> pred_label = 0 -> normal
```

Ví dụ:

| Risk score | Kết quả |
|---:|---|
| 2.86 | normal |
| 4.99 | normal |
| 5.00 | attack |
| 9.33 | attack |

## 7. Lưu Random Forest đã train và kết quả dự đoán

Đoạn code:

```python
fitted_models[model_name] = estimator
model_predictions[model_name] = {'risk_score': scores, 'pred_label': preds}
```

Ý nghĩa:

| Dòng code | Ý nghĩa |
|---|---|
| `fitted_models[model_name] = estimator` | Lưu model đã train |
| `model_predictions[model_name] = ...` | Lưu điểm rủi ro và label dự đoán |

Với Random Forest, dữ liệu được lưu tương đương:

```python
fitted_models['random_forest'] = random_forest_model_da_train
model_predictions['random_forest'] = {
    'risk_score': scores,
    'pred_label': preds,
}
```

Mục đích là để sau đó có thể:

```text
1. So sánh Decision Tree và Random Forest.
2. Chọn Random Forest làm model chính.
3. Dùng lại Random Forest cho feature importance và test file ngoài.
```

## 8. Đánh giá Random Forest bằng metric

Đoạn code:

```python
evaluation_rows.append({
    'model': model_name,
    'accuracy_pct': round(accuracy_score(y_test, preds) * 100, 2),
    'roc_auc': round(roc_auc_score(y_test, scores / 10), 4),
    'avg_precision': round(average_precision_score(y_test, scores / 10), 4),
    'pred_normal': int((preds == 0).sum()),
    'pred_attack': int((preds == 1).sum()),
})
```

Ý nghĩa:

| Metric | Ý nghĩa |
|---|---|
| `accuracy_pct` | Tỷ lệ dự đoán đúng |
| `roc_auc` | Khả năng xếp attack cao điểm hơn normal trên nhiều threshold |
| `avg_precision` | Chất lượng phát hiện attack theo Precision-Recall curve |
| `pred_normal` | Số request được dự đoán normal |
| `pred_attack` | Số request được dự đoán attack |

Kết quả Random Forest trong notebook:

| Model | Accuracy | ROC-AUC | Average Precision | Pred normal | Pred attack |
|---|---:|---:|---:|---:|---:|
| Random Forest | 94.10% | 0.9897 | 0.9818 | 1,342 | 725 |

Ý nghĩa:

Random Forest có Accuracy thấp hơn Decision Tree một chút, nhưng ROC-AUC và Average Precision cao hơn. Với bài toán security, điều này quan trọng vì ta quan tâm khả năng xếp hạng và phát hiện request nguy hiểm, không chỉ tỷ lệ đúng tại một threshold cố định.

## 9. Hiển thị confusion matrix

Đoạn code:

```python
display(pd.DataFrame(
    confusion_matrix(y_test, preds, labels=[0, 1]),
    index=['true_normal', 'true_attack'],
    columns=['pred_normal', 'pred_attack'],
))
```

Ý nghĩa:

| Thành phần | Ý nghĩa |
|---|---|
| `confusion_matrix(...)` | Tạo ma trận nhầm lẫn |
| `labels=[0, 1]` | Cố định thứ tự class: normal trước, attack sau |
| `true_normal` | Request thật sự normal |
| `true_attack` | Request thật sự attack |
| `pred_normal` | Model dự đoán normal |
| `pred_attack` | Model dự đoán attack |

Confusion matrix của Random Forest:

| Thực tế | Pred normal | Pred attack |
|---|---:|---:|
| True normal | 1,291 | 71 |
| True attack | 51 | 654 |

Diễn giải:

| Ô | Ý nghĩa |
|---|---|
| `1291` | Normal được dự đoán đúng |
| `71` | Normal bị báo nhầm attack, false positive |
| `51` | Attack bị bỏ sót, false negative |
| `654` | Attack được phát hiện đúng |

## 10. Chọn Random Forest làm active model

Đoạn code:

```python
ACTIVE_MODEL_NAME = 'random_forest'
model = fitted_models[ACTIVE_MODEL_NAME]
```

Ý nghĩa:

| Dòng code | Ý nghĩa |
|---|---|
| `ACTIVE_MODEL_NAME = 'random_forest'` | Chọn Random Forest làm model chính |
| `model = fitted_models[ACTIVE_MODEL_NAME]` | Lấy Random Forest đã train ra biến `model` |

Từ đoạn này trở đi, biến:

```python
model
```

chính là Random Forest.

Điều đó có nghĩa là các bước sau đều dùng Random Forest mặc định:

```text
1. Tính risk_score trên test set.
2. Xem feature importance.
3. Test CSIC benchmark.
4. Test Burp XML.
5. Test CSV ngoài bằng test_csv().
```

## 11. Tính lại risk score bằng active model

Đoạn code:

```python
y_prob = model.predict_proba(X_test)[:, 1]
risk_score = y_prob * 10
y_pred = (risk_score >= THRESHOLD).astype(int)
```

Ý nghĩa:

| Dòng code | Ý nghĩa |
|---|---|
| `y_prob = model.predict_proba(X_test)[:, 1]` | Random Forest dự đoán xác suất attack |
| `risk_score = y_prob * 10` | Đổi xác suất thành điểm rủi ro |
| `y_pred = ...` | Chuyển điểm rủi ro thành label dự đoán |

Đây là phần cốt lõi của hệ thống risk scoring:

```text
HTTP request -> feature -> Random Forest -> P(attack) -> risk_score
```

## 12. In tên model active và accuracy

Đoạn code:

```python
print(f'Active model: {ACTIVE_MODEL_NAME}')
print(f'Accuracy: {accuracy_score(y_test, y_pred) * 100:.2f}%')
```

Ý nghĩa:

| Dòng code | Ý nghĩa |
|---|---|
| `Active model: random_forest` | Xác nhận model đang dùng là Random Forest |
| `Accuracy: ...` | In tỷ lệ dự đoán đúng của Random Forest trên test set |

Kết quả:

```text
Active model: random_forest
Accuracy: 94.10%
```

## 13. Chuẩn bị lưu model bằng joblib

Đoạn code:

```python
Path('models').mkdir(exist_ok=True)
# joblib.dump(
#     {'model': model, 'model_name': ACTIVE_MODEL_NAME, 'feature_columns': feature_cols, 'threshold': THRESHOLD},
#     f'models/{ACTIVE_MODEL_NAME}.joblib',
# )
```

Ý nghĩa:

| Dòng code | Ý nghĩa |
|---|---|
| `Path('models').mkdir(exist_ok=True)` | Tạo thư mục `models` nếu chưa có |
| `joblib.dump(...)` | Lưu model ra file để dùng lại |
| `model` | Random Forest đã train |
| `model_name` | Tên model: `random_forest` |
| `feature_columns` | Danh sách feature cần đúng thứ tự khi predict |
| `threshold` | Ngưỡng phân loại hiện tại |

Hiện tại phần `joblib.dump` đang bị comment, nghĩa là notebook chưa lưu model ra file. Nếu bỏ comment, model sẽ được lưu tại:

```text
models/random_forest.joblib
```

## 14. Lấy feature importance của Random Forest

Đoạn code:

```python
importance = pd.DataFrame({
    'feature': feature_cols,
    'importance': model.feature_importances_,
}).sort_values('importance', ascending=False)
print(f'Feature importance for active model: {ACTIVE_MODEL_NAME}')
display(importance.head(15))
```

Ý nghĩa:

| Dòng code | Ý nghĩa |
|---|---|
| `model.feature_importances_` | Lấy độ quan trọng của từng feature trong Random Forest |
| `pd.DataFrame(...)` | Tạo bảng feature và importance |
| `.sort_values(..., ascending=False)` | Sắp xếp feature quan trọng nhất lên đầu |
| `importance.head(15)` | Hiển thị 15 feature quan trọng nhất |

Top feature trong notebook:

| Feature | Importance | Ý nghĩa |
|---|---:|---|
| `num_params` | 0.151236 | Số lượng parameter là tín hiệu mạnh |
| `has_numeric_value` | 0.108040 | Giá trị số giúp tách pattern normal/attack |
| `raw_encoded_ratio` | 0.098616 | Tỷ lệ encoded cao có thể liên quan payload obfuscation |
| `has_referer_header` | 0.081989 | Header referer giúp nhận diện traffic web bình thường |
| `has_recursive_decoded_url` | 0.074553 | URL sau decode nhiều vòng là tín hiệu quan trọng |
| `has_recursive_decoded_sqli` | 0.039899 | Dấu hiệu SQLi sau decode nhiều vòng |

Lưu ý:

```text
Feature importance không có nghĩa feature đó luôn là attack.
Nó chỉ cho biết Random Forest thường dùng feature đó để chia dữ liệu.
```

## 15. Dùng Random Forest để chấm điểm feature CSV

Đoạn code:

```python
def _score_feature_dataset(data, estimator=None):
    estimator = _selected_model(estimator)
    X_ext = data.reindex(columns=feature_cols, fill_value=0)
    scores = estimator.predict_proba(X_ext)[:, 1] * 10
    out = data[_visible_columns(data)].copy()
    out['risk_score'] = scores.round(2)
    return out
```

Ý nghĩa:

| Dòng code | Ý nghĩa |
|---|---|
| `_selected_model(estimator)` | Nếu không truyền model khác, dùng active model là Random Forest |
| `data.reindex(columns=feature_cols, fill_value=0)` | Sắp xếp/điền feature đúng theo danh sách đã train |
| `predict_proba(X_ext)[:, 1] * 10` | Tính risk score bằng Random Forest |
| `scores.round(2)` | Làm tròn risk score 2 chữ số |

Hàm này dùng khi input CSV đã có đủ feature columns, ví dụ:

```text
data/processed/features.csv
```

## 16. Dùng Random Forest để chấm điểm raw request CSV

Đoạn code:

```python
def _score_raw_request_dataset(data, estimator=None):
    estimator = _selected_model(estimator)
    feature_rows = []
    for item in data.fillna('').to_dict('records'):
        req = {key: str(value) for key, value in item.items()}
        features = extract_features(req)
        feature_rows.append({col: features.get(col, 0) for col in feature_cols})
    X_ext = pd.DataFrame(feature_rows).reindex(columns=feature_cols, fill_value=0)
    scores = estimator.predict_proba(X_ext)[:, 1] * 10
    out = data[_visible_columns(data)].copy()
    out['risk_score'] = scores.round(2)
    return out
```

Ý nghĩa:

| Bước | Ý nghĩa |
|---|---|
| `data.fillna('').to_dict('records')` | Chuyển từng dòng request thành dictionary |
| `extract_features(req)` | Trích xuất 68 feature từ request thô |
| `feature_rows.append(...)` | Gom feature của từng request |
| `pd.DataFrame(feature_rows)` | Tạo bảng feature mới |
| `predict_proba(...)[:, 1] * 10` | Random Forest chấm risk score |

Hàm này dùng cho CSV request thô, ví dụ:

```text
samplectf_requests.csv
qldt_ptit_normal_requests.csv
```

## 17. Hàm `test_csv()` dùng Random Forest mặc định

Đoạn code:

```python
def test_csv(filename, threshold=THRESHOLD, top_n=30, estimator=None, model_name=None):
    selected_model = _selected_model(estimator)
    selected_name = model_name or globals().get('ACTIVE_MODEL_NAME', 'custom_model')
    path = PROJECT_ROOT / filename
    data = pd.read_csv(path)
    mode = 'feature' if set(feature_cols).issubset(data.columns) else 'raw_request'
    result = _score_feature_dataset(data, selected_model) if mode == 'feature' else _score_raw_request_dataset(data, selected_model)
    result['pred_label'] = (result['risk_score'] >= threshold).astype(int)
    result['predicted'] = result['pred_label'].map({0: 'normal', 1: 'attack'})
```

Ý nghĩa:

| Dòng code | Ý nghĩa |
|---|---|
| `selected_model = _selected_model(estimator)` | Nếu không truyền model khác, dùng Random Forest active |
| `selected_name = ... ACTIVE_MODEL_NAME ...` | Tên model hiển thị là `random_forest` |
| `pd.read_csv(path)` | Đọc file cần test |
| `mode = 'feature' if ... else 'raw_request'` | Tự nhận biết CSV đã có feature hay còn là request thô |
| `_score_feature_dataset(...)` | Chấm điểm CSV feature |
| `_score_raw_request_dataset(...)` | Extract feature rồi chấm điểm request thô |
| `pred_label` | Phân loại theo threshold |
| `predicted` | Đổi `0/1` thành `normal/attack` |

Đây là hàm giúp dùng Random Forest để test nhiều loại file ngoài notebook.

## 18. Đánh giá threshold trong `test_csv()`

Đoạn code:

```python
threshold_rows = []
for value in [3.0, 4.0, 5.0, 6.0, 7.0, 8.0]:
    pred = (result['risk_score'] >= value).astype(int)
    threshold_rows.append({
        'threshold': value,
        'accuracy': round(accuracy_score(y_true, pred) * 100, 2),
        'pred_normal': int((pred == 0).sum()),
        'pred_attack': int((pred == 1).sum()),
    })
display(pd.DataFrame(threshold_rows))
```

Ý nghĩa:

Đoạn này không train lại Random Forest. Nó dùng `risk_score` đã được Random Forest tính trước đó, rồi thử nhiều threshold khác nhau.

| Threshold thấp | Threshold cao |
|---|---|
| Bắt nhiều attack hơn | Báo attack ít hơn |
| Dễ tăng false positive | Dễ tăng false negative |
| Phù hợp khi ưu tiên an toàn | Phù hợp khi muốn giảm cảnh báo nhầm |

## 19. Dùng Random Forest để test Burp XML

Đoạn code:

```python
burp_xml_result = test_csv(BURP_OUTPUT_CSV, threshold=THRESHOLD, top_n=30)
```

Ý nghĩa:

Trước đó notebook convert Burp XML thành CSV:

```python
count = convert_burp_xml_to_csv(...)
```

Sau đó gọi:

```python
test_csv(...)
```

Vì `test_csv()` mặc định dùng active model, nên file Burp XML sau khi convert được chấm điểm bằng Random Forest.

Kết quả với `samplectf.xml`:

| Hạng mục | Giá trị |
|---|---:|
| Số request | 6 |
| Threshold | 5.0 |
| Accuracy | 50.00% |
| Pred normal | 3 |
| Pred attack | 3 |

Request có điểm cao nhất:

```text
/somepath?file=%252E%252E...
risk_score = 9.33
predicted = attack
```

Ý nghĩa: request này có double encoding giống path traversal nên Random Forest chấm điểm rất cao.

## 20. Dùng Random Forest để test toàn bộ `features.csv`

Đoạn code:

```python
TEST_FILE = 'features.csv'
external_result = test_csv(TEST_FILE, threshold=THRESHOLD, top_n=30)
```

Ý nghĩa:

Đoạn này dùng Random Forest active để chấm lại toàn bộ file:

```text
data/processed/features.csv
```

Kết quả:

| Hạng mục | Giá trị |
|---|---:|
| Rows | 10,332 |
| Mode | feature |
| Model | random_forest |
| Threshold | 5.0 |
| Accuracy | 94.91% |

Lưu ý:

```text
Kết quả này không phải đánh giá khách quan như hold-out test set,
vì features.csv bao gồm cả dữ liệu đã dùng để train.
```

Nó chủ yếu dùng để xem Random Forest chấm điểm toàn bộ dataset như thế nào.

## 21. Tóm tắt luồng Random Forest trong project

Luồng triển khai:

```text
Import RandomForestClassifier
  -> khai báo random_forest trong MODEL_CONFIGS
  -> train bằng estimator.fit(X_train, y_train)
  -> dự đoán P(attack) bằng predict_proba
  -> đổi thành risk_score = P(attack) * 10
  -> phân loại bằng threshold 5.0
  -> lưu vào fitted_models
  -> chọn ACTIVE_MODEL_NAME = "random_forest"
  -> dùng Random Forest cho feature importance, CSIC, Burp XML và test_csv()
```

Vai trò cuối cùng của Random Forest:

```text
Random Forest là model active hiện tại.
Nó nhận feature HTTP request, dự đoán xác suất attack,
rồi chuyển xác suất đó thành risk_score trên thang 0 đến 10.
```

## 22. Vì sao Random Forest được chọn

Kết quả so sánh trên hold-out test set:

| Model | Accuracy | ROC-AUC | Average Precision | False Negative |
|---|---:|---:|---:|---:|
| Decision Tree | 94.53% | 0.9836 | 0.9736 | 88 |
| Random Forest | 94.10% | 0.9897 | 0.9818 | 51 |

Decision Tree có accuracy cao hơn nhẹ, nhưng Random Forest:

```text
1. Có ROC-AUC cao hơn.
2. Có Average Precision cao hơn.
3. Bỏ sót attack ít hơn.
4. Ổn định hơn vì dùng nhiều cây.
```

Với bài toán security, giảm false negative là rất quan trọng vì false negative nghĩa là request tấn công bị bỏ lọt. Vì vậy Random Forest phù hợp hơn để làm model active.
