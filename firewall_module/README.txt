Yêu cầu:
- Python 3.9 trở lên
- Các gói Python cần thiết:
	-pandas
	-numpy
	-scikit-learn
	-joblib
Cài đặt nhanh bằng pip:
pip install pandas numpy scikit-learn joblib

Cách sử dung:
Huấn luyện:
python main.py --mode train --input path/to/train_data.csv

Test/Phát hiện Anomaly:
python main.py --mode test --input path/to/test_data.csv

Cấu hình model:
Các tham số mô hình và đường dẫn output được định nghĩa trong config.py:

MODEL_PARAMS       # Tham số Isolation Forest
MODEL_PATH         # Đường dẫn lưu model đã huấn luyện
THRESHOLD_PATH     # Đường dẫn lưu threshold anomaly
ANOMALY_OUTPUT     # CSV anomaly output (tùy chọn)
BEHAVIOR_OUTPUT    # JSON báo cáo output
TAIL_PERCENTILE    # Percentile dùng để xác định anomaly threshold cấp flow

Có thể thay đổi MODEL_PARAMS hoặc TAIL_PERCENTILE tùy nhu cầu