# Module Phân tích Web Server Log

Module này là một thành phần cốt lõi của hệ thống APT Hunter, chịu trách nhiệm phân tích các tệp nhật ký (Access Log, Error Log) sinh ra từ các máy chủ Web (như Apache, Nginx). Mục tiêu của module là phát hiện các nỗ lực xâm nhập ban đầu (Initial Access), rà quét lỗ hổng và hành vi rò rỉ dữ liệu thuộc các chiến dịch tấn công tàng hình APT (Low-and-Slow).

## Kiến trúc Đa tầng

Module áp dụng triết lý phòng thủ chiều sâu (Defense-in-depth) thông qua một đường ống xử lý (Pipeline) tuyến tính gồm 5 tầng phân tích:

* **Tầng 0 (Bóc tách dữ liệu - Parser):** Đọc và nhận diện tự động đa định dạng nhật ký, trích xuất các trường dữ liệu và đồng bộ hóa thành một trục thời gian (Timeline) liền mạch.
* **Tầng 1 (Bộ lọc Quyết định - WAF tĩnh):** Phát hiện tức thời các kỹ thuật tấn công bề mặt (SQLi, XSS, Path Traversal, OS Command Injection, SSRF, Protocol Manipulation) bằng công cụ tự phát triển Hybrid Normalized-CRS.
* **Tầng 2 & 3 (Học máy Hành vi - Behavioural ML):**
  * **Sessionizer:** Nhóm các request thành các phiên truy cập (Session) độc lập dựa trên IP và thời gian (Timeout), trích xuất Vector đặc trưng 20 chiều.
  * **Mô hình Thống kê (Statistical ML):** Kết hợp thuật toán Isolation Forest và One-Class SVM để chấm điểm các dấu hiệu bất thường về mặt tài nguyên và khối lượng tải.
  * **Mô hình Chuỗi (Sequential ML):** Sử dụng thuật toán Time-Aware Markov Chain để phân tích sự dị biệt về logic điều hướng và thứ tự truy cập.
* **Tầng 4 (Tương quan Dữ liệu & Tham vấn LLM):** * **Correlator:** Gộp nhóm các cảnh báo theo thực thể IP (Entity Consolidation) và nén dữ liệu lặp lại (Run-Length Encoding) để giảm thiểu cảnh báo giả.
  * **LLM Advisor:** Kết nối với các API của mô hình ngôn ngữ lớn thông qua kỹ thuật Multi-Anchor Blast Radius để phân giải nguyên nhân gốc rễ (Root-cause) và phân loại cảnh báo.

## Cấu trúc Thư mục Module

```text
webserver_module_AIT/
│
├── parser/                 # Tầng 0: Chứa các lớp đọc và chuẩn hóa log
├── filter_layer/           # Tầng 1: Bộ luật WAF tĩnh và các tệp kiểm thử (testing/)
├── behaviour_layer/        # Tầng 2 & 3: Gom nhóm phiên (Sessionizer) và ML Hành vi
├── final_layer/            # Tầng 4: Tương quan dữ liệu (Correlator) và LLM Advisor
├── data_management/        # Quản lý Profile (Hồ sơ dữ liệu) người dùng tải lên
│
├── module_data/            # Nơi lưu trữ dữ liệu thô, model và kết quả phân tích
├── view.py                 # Mã nguồn giao diện Streamlit hiển thị riêng cho Web Server
├── backend_bridge.py       # Tệp cầu nối xử lý logic giữa giao diện và các tầng phân tích
│
└── evaluate_*.py           # Các tệp kịch bản kiểm thử tĩnh (Dùng cho báo cáo học thuật)
```

## Hướng dẫn Chạy Độc lập

Module này được thiết kế để nhúng vào giao diện trung tâm của dự án. Tuy nhiên, để phục vụ mục đích kiểm thử độc lập, có thể khởi chạy riêng giao diện của module Web Server:

1. Đảm bảo đã kích hoạt môi trường ảo và cài đặt đầy đủ các thư viện yêu cầu.
2. Đảm bảo tệp cơ sở dữ liệu `GeoLite2-City.mmdb` đã có sẵn tại thư mục gốc của dự án.
3. Thực thi lệnh sau từ thư mục gốc của dự án:
```bash
streamlit run webserver_module_AIT/view.py
```

## Chạy Kiểm thử Đánh giá (Evaluation)

Hệ thống đi kèm các kịch bản kiểm thử tự động, hỗ trợ xuất ra các chỉ số đánh giá học thuật (Recall, False Positive Rate, Ablation Study).

**1. Đánh giá Tầng 1 (WAF tĩnh):**
Di chuyển vào thư mục testing để thực thi các tệp đánh giá quy tắc phát hiện:
```bash
cd webserver_module_AIT/filter_layer/testing
python sqli_detector_test.py
python xss_test.py
```

**2. Đánh giá Tầng Hành vi & Tương quan (ML & Correlator):**
Yêu cầu: Đã thực thi luồng phân tích qua giao diện WebApp để sinh ra các tệp kết quả (CSV, NDJSON) trong thư mục `results`.

Để tránh rò rỉ dữ liệu (Data Leakage) khi đánh giá Machine Learning, cần tuân thủ quy trình sau trên giao diện:
- Sử dụng tệp log sạch (Benign traffic) $\rightarrow$ Chạy chế độ **Train Baseline**.
- Sử dụng tệp log chứa tấn công $\rightarrow$ Chạy chế độ **Detect**.

Sau khi có tệp kết quả, sử dụng các lệnh sau để lấy số liệu:
```bash
cd webserver_module_AIT
python evaluate_layer1.py
python evaluate_webserver_module.py
python sequential_test.py
```