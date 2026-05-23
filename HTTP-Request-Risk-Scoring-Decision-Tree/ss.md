# So sánh trước và sau khi có Random Forest

Trong project này, giai đoạn trước dùng `DecisionTreeClassifier` làm mô hình chính/baseline. Sau khi bổ sung `RandomForestClassifier`, Random Forest được chọn làm `active model` để chấm điểm rủi ro HTTP request.

## Bảng so sánh tổng quan

| Tiêu chí | Trước khi có Random Forest | Sau khi có Random Forest |
|---|---|---|
| Mô hình sử dụng | Decision Tree | Random Forest |
| Vai trò trong project | Baseline, dễ giải thích logic phân loại | Model active hiện tại, dùng cho các bước đánh giá và kiểm thử |
| Cách hoạt động | Một cây quyết định duy nhất phân nhánh theo feature | Nhiều cây quyết định cùng dự đoán, sau đó lấy trung bình/xử lý theo ensemble |
| Cấu hình chính | `max_depth=8`, `min_samples_leaf=20`, `random_state=42` | `n_estimators=200`, `min_samples_leaf=5`, `class_weight="balanced_subsample"`, `n_jobs=-1`, `random_state=42` |
| Độ ổn định | Thấp hơn vì phụ thuộc vào một cây duy nhất | Cao hơn vì tổng hợp kết quả từ nhiều cây |
| Nguy cơ overfit | Cao hơn nếu cây học quá sát dữ liệu training | Thấp hơn nhờ bootstrap sampling và random feature selection |
| Khả năng tổng quát hóa | Tốt, nhưng dễ bị ảnh hưởng bởi dữ liệu nhiễu hoặc lệch | Tốt hơn, ít phụ thuộc vào một vài pattern riêng lẻ |
| Khả năng giải thích | Rất dễ giải thích vì có thể lần theo từng nhánh cây | Khó giải thích hơn Decision Tree, nhưng vẫn xem được feature importance |
| Tốc độ train | Nhanh hơn | Chậm hơn do train nhiều cây, nhưng dùng `n_jobs=-1` để tận dụng nhiều CPU cores |
| Cách tính `risk_score` | `risk_score = P(attack) * 10` | Không đổi: `risk_score = P(attack) * 10` |
| Ngưỡng phân loại | `risk_score >= 5.0` thì là attack | Không đổi: `risk_score >= 5.0` thì là attack |
| Phù hợp nhất để | Làm baseline và giải thích mô hình | Làm model chính để cải thiện độ ổn định và khả năng phát hiện attack |

## Bảng so sánh kết quả

| Model | Accuracy | ROC-AUC | Average Precision | Nhận xét |
|---|---:|---:|---:|---|
| Decision Tree | 94.53% | 0.9836 | 0.9736 | Accuracy cao hơn nhẹ trong hold-out split này |
| Random Forest | 94.10% | 0.9897 | 0.9818 | ROC-AUC và Average Precision tốt hơn, phù hợp hơn cho bài toán security |

## Kết luận

Sau khi bổ sung Random Forest, hệ thống không thay đổi cách tính điểm rủi ro, nhưng mô hình dự đoán trở nên ổn định hơn. Random Forest có accuracy thấp hơn Decision Tree một chút trong split hiện tại, nhưng có ROC-AUC và Average Precision cao hơn, nghĩa là khả năng xếp hạng và phát hiện request nguy hiểm tốt hơn trên nhiều ngưỡng khác nhau.

Vì bài toán HTTP request risk scoring ưu tiên phát hiện attack và giảm bỏ sót request nguy hiểm, Random Forest phù hợp hơn để làm model active, còn Decision Tree vẫn hữu ích để làm baseline và giải thích logic phân loại.
