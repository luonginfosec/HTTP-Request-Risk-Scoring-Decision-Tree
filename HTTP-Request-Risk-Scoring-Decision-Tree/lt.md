# Giải thích Decision Tree và Random Forest trong bài

## 1. Bối cảnh trong project

Project này dùng học máy có giám sát để phân loại HTTP request thành hai nhóm:

```text
0 = normal
1 = attack / suspicious
```

Mỗi request ban đầu gồm các thông tin như:

```text
method, url, path, query_string, headers, body
```

Trước khi đưa vào model, project chuyển request thành các feature dạng số, ví dụ:

```text
has_query
num_params
has_encoded_value
has_recursive_decoded_sqli
has_recursive_decoded_xss
has_private_ip_value
has_authorization_header
has_json_body
has_url_param_and_private_ip
```

Sau đó model dự đoán xác suất request là attack:

```text
P(attack)
```

Điểm rủi ro được tính:

```text
risk_score = P(attack) * 10
```

Nếu:

```text
risk_score >= 5.0
```

thì request được phân loại là `attack`. Ngược lại là `normal`.

Trong notebook, project đang dùng hai thuật toán:

```text
Decision Tree Classifier
Random Forest Classifier
```

Decision Tree đóng vai trò model baseline. Random Forest là model active hiện tại.

## 2. Decision Tree là gì?

Decision Tree, hay cây quyết định, là thuật toán học máy hoạt động giống một sơ đồ hỏi đáp.

Model sẽ học ra một cây gồm nhiều câu hỏi dạng:

```text
Feature này có bằng 1 không?
Feature này có lớn hơn một ngưỡng không?
Request có dấu hiệu SQLi không?
Request có query string không?
Request có encoded payload không?
```

Mỗi câu hỏi chia dữ liệu thành các nhánh nhỏ hơn. Đi từ gốc cây xuống lá cây, model đưa ra dự đoán cuối cùng.

Ví dụ đơn giản:

```text
has_recursive_decoded_sqli?
├── yes -> attack
└── no
    └── has_recursive_decoded_xss?
        ├── yes -> attack
        └── no
            └── has_query?
                ├── yes -> kiểm tra tiếp
                └── no -> normal
```

Trong thực tế, cây được học tự động từ dữ liệu, không phải viết tay.

## 3. Decision Tree học như thế nào?

Decision Tree tìm cách chia dữ liệu sao cho mỗi nhánh sau khi chia càng "thuần" càng tốt.

Ví dụ, nếu một feature chia dữ liệu thành:

```text
Nhánh trái: hầu hết là normal
Nhánh phải: hầu hết là attack
```

thì feature đó là một feature tốt để split.

Các tiêu chí split thường dùng:

```text
Gini impurity
Entropy / Information Gain
```

Trong scikit-learn, `DecisionTreeClassifier` mặc định dùng Gini impurity.

Ý tưởng của Gini:

```text
Gini thấp  -> node càng thuần
Gini cao   -> node còn lẫn nhiều class
```

Ví dụ:

```text
Node A: 100 normal, 0 attack   -> rất thuần
Node B: 50 normal, 50 attack   -> lẫn nhiều
```

Decision Tree sẽ ưu tiên split làm các node con trở nên thuần hơn.

## 4. Decision Tree trong bài này

Trong notebook, model Decision Tree được cấu hình:

```python
DecisionTreeClassifier(
    max_depth=8,
    min_samples_leaf=20,
    random_state=42,
)
```

Ý nghĩa:

| Tham số | Ý nghĩa |
|---|---|
| `max_depth=8` | Cây sâu tối đa 8 tầng |
| `min_samples_leaf=20` | Mỗi lá phải có ít nhất 20 sample |
| `random_state=42` | Giúp kết quả có thể tái lập |

Hai tham số quan trọng là `max_depth` và `min_samples_leaf`.

Nếu cây quá sâu, model có thể học thuộc dữ liệu training và overfit. Nếu cây quá nông, model có thể quá đơn giản và underfit.

Trong bài này, `max_depth=8` giúp cây đủ mạnh để học các pattern như SQLi, XSS, traversal, encoded payload, nhưng vẫn hạn chế overfit.

## 5. Decision Tree dự đoán risk score như thế nào?

Khi request đi tới một lá cây, lá đó chứa tỷ lệ normal/attack từ dữ liệu training.

Ví dụ một lá có:

```text
20 normal
80 attack
```

thì:

```text
P(attack) = 80 / (20 + 80) = 0.8
risk_score = 0.8 * 10 = 8.0
```

Nếu một request có `risk_score = 8.0`, nó bị phân loại là attack vì:

```text
8.0 >= 5.0
```

Trong code, việc này được thực hiện bằng:

```python
y_prob = model.predict_proba(X_test)[:, 1]
risk_score = y_prob * 10
y_pred = (risk_score >= THRESHOLD).astype(int)
```

## 6. Ưu điểm của Decision Tree

Decision Tree có các ưu điểm:

```text
1. Dễ hiểu và dễ giải thích.
2. Phù hợp với feature dạng số 0/1 như trong project.
3. Không cần scale dữ liệu.
4. Có thể xem feature importance.
5. Train nhanh.
```

Với bài toán HTTP request risk scoring, Decision Tree dễ giải thích vì ta có thể nói model dựa vào các dấu hiệu như:

```text
has_recursive_decoded_sqli
has_recursive_decoded_xss
has_encoded_value
has_url_param_and_private_ip
has_special_chars
```

## 7. Nhược điểm của Decision Tree

Decision Tree cũng có nhược điểm:

```text
1. Dễ overfit nếu cây quá sâu.
2. Chỉ cần dữ liệu thay đổi nhẹ, cấu trúc cây có thể thay đổi nhiều.
3. Một cây đơn lẻ có thể dự đoán thiếu ổn định.
4. Có thể học nhầm pattern nếu training data bị lệch.
```

Ví dụ trong project, nếu dữ liệu attack có nhiều request dạng:

```text
GET /something?id=...
```

nhưng dữ liệu normal lại thiếu các request business flow như:

```text
/product?id=123
/document?id=123
/order?id=456
```

thì cây có thể học nhầm rằng:

```text
GET + query + id parameter = nguy hiểm
```

Đây là vấn đề dữ liệu, không chỉ là vấn đề thuật toán.

## 8. Random Forest là gì?

Random Forest là thuật toán ensemble, tức là kết hợp nhiều model nhỏ để tạo thành một model mạnh hơn.

Random Forest gồm nhiều Decision Tree.

Thay vì chỉ train một cây, Random Forest train nhiều cây khác nhau:

```text
Tree 1
Tree 2
Tree 3
...
Tree N
```

Mỗi cây đưa ra dự đoán riêng. Random Forest tổng hợp các dự đoán đó để ra kết quả cuối cùng.

Với bài toán classification:

```text
Decision Tree đơn lẻ -> một cây dự đoán
Random Forest        -> nhiều cây cùng bỏ phiếu
```

## 9. Random Forest tạo nhiều cây khác nhau bằng cách nào?

Random Forest tạo sự khác nhau giữa các cây bằng hai kỹ thuật chính.

### 9.1. Bootstrap sampling

Mỗi cây được train trên một mẫu dữ liệu khác nhau, lấy ngẫu nhiên từ tập training.

Ví dụ training set có 10,000 dòng. Tree 1 có thể học trên một mẫu bootstrap khác Tree 2.

Điều này làm các cây không giống hệt nhau.

### 9.2. Random feature selection

Khi split node, mỗi cây không phải lúc nào cũng xem toàn bộ feature. Nó chỉ xem một tập feature ngẫu nhiên.

Ví dụ project có 68 feature. Ở một split, cây có thể chỉ xét một nhóm feature con.

Điều này giúp các cây đa dạng hơn, giảm phụ thuộc vào một vài feature mạnh.

## 10. Random Forest dự đoán như thế nào?

Với classification, mỗi cây dự đoán xác suất hoặc class.

Random Forest lấy trung bình xác suất từ nhiều cây:

```text
P_final(attack) = trung bình P_tree_i(attack)
```

Ví dụ:

```text
Tree 1: P(attack) = 0.90
Tree 2: P(attack) = 0.70
Tree 3: P(attack) = 0.80
Tree 4: P(attack) = 0.60
Tree 5: P(attack) = 1.00
```

Thì:

```text
P_final(attack) = (0.90 + 0.70 + 0.80 + 0.60 + 1.00) / 5
                = 0.80
```

Và:

```text
risk_score = 0.80 * 10 = 8.0
```

## 11. Random Forest trong bài này

Trong notebook, Random Forest được cấu hình:

```python
RandomForestClassifier(
    n_estimators=200,
    min_samples_leaf=5,
    class_weight="balanced_subsample",
    n_jobs=-1,
    random_state=42,
)
```

Ý nghĩa:

| Tham số | Ý nghĩa |
|---|---|
| `n_estimators=200` | Train 200 cây quyết định |
| `min_samples_leaf=5` | Mỗi lá có ít nhất 5 sample |
| `class_weight="balanced_subsample"` | Cân bằng trọng số class trong từng bootstrap sample |
| `n_jobs=-1` | Dùng tối đa CPU cores để train nhanh hơn |
| `random_state=42` | Giúp kết quả có thể tái lập |

Random Forest đang là active model:

```python
ACTIVE_MODEL_NAME = "random_forest"
model = fitted_models[ACTIVE_MODEL_NAME]
```

Điều đó có nghĩa là các bước sau trong notebook như feature importance, CSIC benchmark, Burp XML test, `test_csv()` sẽ dùng Random Forest mặc định.

## 12. Vì sao Random Forest phù hợp với bài này?

Bài toán HTTP request risk scoring có nhiều feature nhị phân và tương tác feature.

Ví dụ một feature đơn lẻ có thể chưa đủ:

```text
has_url_param = 1
```

Chưa chắc là attack, vì normal request cũng có redirect/callback URL.

Nhưng tổ hợp:

```text
has_url_param = 1
has_private_ip_value = 1
```

có thể đáng nghi hơn vì giống SSRF.

Random Forest phù hợp vì:

```text
1. Học được quan hệ phi tuyến giữa nhiều feature.
2. Ổn định hơn một Decision Tree đơn lẻ.
3. Giảm overfit nhờ trung bình nhiều cây.
4. Vẫn giải thích được tương đối bằng feature importance.
5. Không cần scale feature.
```

## 13. So sánh Decision Tree và Random Forest

| Tiêu chí | Decision Tree | Random Forest |
|---|---|---|
| Số lượng cây | 1 cây | Nhiều cây |
| Độ dễ giải thích | Rất dễ | Khó hơn nhưng vẫn xem được feature importance |
| Overfit | Dễ hơn | Ít hơn |
| Tốc độ train | Nhanh | Chậm hơn |
| Độ ổn định | Thấp hơn | Cao hơn |
| Độ chính xác tổng quát | Có thể thấp hơn | Thường tốt hơn |
| Phù hợp làm baseline | Rất phù hợp | Phù hợp làm model chính |

Trong bài này:

```text
Decision Tree = baseline dễ giải thích
Random Forest = model active ổn định hơn
```

## 14. Kết quả trong project

Kết quả kiểm tra gần nhất trên hold-out split:

| Model | Accuracy | ROC-AUC | Average Precision |
|---|---:|---:|---:|
| Decision Tree | 94.53% | 0.9836 | 0.9736 |
| Random Forest | 94.10% | 0.9897 | 0.9818 |

Decision Tree có accuracy cao hơn một chút trong split này.

Tuy nhiên Random Forest có:

```text
ROC-AUC cao hơn
Average Precision cao hơn
```

Với bài toán security, ROC-AUC và Average Precision quan trọng vì ta quan tâm khả năng xếp hạng request nguy hiểm và phát hiện attack ở nhiều threshold khác nhau, không chỉ accuracy tại một ngưỡng cố định.

Vì vậy notebook chọn Random Forest làm model active.

## 15. Ý nghĩa các metric

### Accuracy

Accuracy đo tỷ lệ dự đoán đúng:

```text
accuracy = số dự đoán đúng / tổng số mẫu
```

Nhược điểm: nếu dữ liệu lệch class, accuracy có thể gây hiểu nhầm.

### ROC-AUC

ROC-AUC đo khả năng model xếp attack cao hơn normal trên nhiều threshold.

ROC-AUC càng gần 1 càng tốt.

### Average Precision

Average Precision liên quan đến Precision-Recall curve. Metric này hữu ích khi quan tâm class attack.

Trong security, nếu attack ít hơn normal, Average Precision thường đáng chú ý hơn accuracy.

### Confusion matrix

Confusion matrix cho biết:

```text
true_normal  -> pred_normal / pred_attack
true_attack  -> pred_normal / pred_attack
```

Trong bài toán này:

```text
false positive = normal bị báo attack
false negative = attack bị bỏ sót
```

False negative thường nguy hiểm hơn vì hệ thống bỏ lọt request tấn công.

False positive cũng quan trọng vì nếu quá nhiều normal request bị báo attack, hệ thống khó dùng thực tế.

## 16. Minh họa với một HTTP request

Giả sử request:

```http
GET /search?q=%27%20OR%201%3D1-- HTTP/1.1
Host: example.com
```

Sau canonicalization:

```text
%27%20OR%201%3D1--
```

được decode thành:

```text
' OR 1=1--
```

Feature có thể bật:

```text
method_get = 1
has_query = 1
num_params = 1
has_encoded_value = 1
decoded_changes_value = 1
has_special_chars = 1
has_recursive_decoded_sqli = 1
```

Decision Tree có thể đi theo nhánh có SQLi và dự đoán attack.

Random Forest sẽ để nhiều cây cùng đánh giá. Nếu đa số cây thấy pattern nguy hiểm, xác suất `P(attack)` sẽ cao.

## 17. Vai trò trong báo cáo bài làm

Có thể trình bày ngắn gọn như sau:

```text
Trong bài, nhóm sử dụng Decision Tree làm mô hình baseline vì thuật toán này dễ giải thích,
phù hợp với các feature thủ công dạng nhị phân được trích xuất từ HTTP request.
Sau đó nhóm tích hợp Random Forest để cải thiện độ ổn định và khả năng tổng quát hóa.
Random Forest kết hợp nhiều Decision Tree được huấn luyện trên các mẫu dữ liệu và tập feature
khác nhau, từ đó giảm overfitting so với một cây đơn lẻ.
Điểm rủi ro cuối cùng được tính từ xác suất model dự đoán request thuộc class attack:
risk_score = P(attack) * 10.
```

## 18. Kết luận

Decision Tree và Random Forest đều phù hợp với project vì dữ liệu đầu vào đã được biến đổi thành feature rõ ràng, dễ học bằng tree-based model.

Decision Tree giúp giải thích logic phân loại một cách trực quan.

Random Forest cải thiện tính ổn định bằng cách kết hợp nhiều cây, giảm rủi ro phụ thuộc vào một cây đơn lẻ.

Trong project hiện tại:

```text
Decision Tree: baseline
Random Forest: active model
```

Hai thuật toán này giúp hệ thống chấm điểm HTTP request theo xác suất tấn công, sau đó quy đổi thành `risk_score` trên thang điểm 0 đến 10.
