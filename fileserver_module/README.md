# 📘 HƯỚNG DẪN SỬ DỤNG HỆ THỐNG UEBA  
# Phân Tích Hành Vi Người Dùng & Nhận Dạng Tấn Công APT trên Máy Chủ Tệp Tin

---

## 📋 MỤC LỤC

1. [Tổng quan hệ thống](#1-tổng-quan-hệ-thống)
2. [Yêu cầu cài đặt](#2-yêu-cầu-cài-đặt)
3. [Hướng dẫn chạy từng bước](#3-hướng-dẫn-chạy-từng-bước)
4. [Kiến trúc & Thiết kế chi tiết](#4-kiến-trúc--thiết-kế-chi-tiết)
5. [Chi tiết từng Module](#5-chi-tiết-từng-module)
6. [Giải thích thuật toán Isolation Forest](#6-giải-thích-thuật-toán-isolation-forest)
7. [Kết quả kiểm thử](#7-kết-quả-kiểm-thử)
8. [Câu hỏi phản biện thường gặp & Gợi ý trả lời](#8-câu-hỏi-phản-biện-thường-gặp--gợi-ý-trả-lời)

---

## 1. TỔNG QUAN HỆ THỐNG

### 1.1. Mục tiêu

Xây dựng hệ thống **UEBA (User and Entity Behavior Analytics)** phát hiện tấn công **APT (Advanced Persistent Threat)** trên Windows File Server bằng phân tích hành vi bất thường, sử dụng **Machine Learning** (Isolation Forest).

### 1.2. Vấn đề giải quyết

- Tấn công APT sử dụng kỹ thuật **Living off the Land (LotL)**: dùng công cụ hợp lệ của hệ điều hành (PowerShell, certutil, wmic...) → **Antivirus/IDS/IPS không phát hiện được**.
- Kẻ tấn công sử dụng **tài khoản hợp lệ** sau khi đánh cắp credential → không có malware signature.
- Giải pháp: **Phân tích hành vi** — phát hiện bất thường dựa trên mẫu hoạt động, không dựa trên signature.

### 1.3. Phạm vi

- **Input**: Windows Security Event Log (`.evtx`, `.json`, `.csv`)
- **13 Event IDs** phủ toàn bộ **kill-chain** của APT
- **25 đặc trưng hành vi** trên 6 chiều phân tích
- **Output**: Điểm rủi ro bất thường 0–100 cho từng người dùng theo cửa sổ thời gian

---

## 2. YÊU CẦU CÀI ĐẶT

### 2.1. Phần cứng / Hệ điều hành

- **Windows 10/11** hoặc **Windows Server 2016+**
- **Python 3.9+** (khuyến nghị Python 3.12)
- Quyền **Administrator** (để đọc Security log)

### 2.2. Cài đặt thư viện

```powershell
# Mở PowerShell và chạy:
cd C:\Users\laptopJP.vn\Desktop\APT-opus
pip install -r requirements.txt
```

**Nội dung `requirements.txt`:**

| Thư viện | Phiên bản | Mục đích |
|---|---|---|
| `pandas` | ≥ 1.5 | Xử lý dữ liệu dạng bảng, groupby theo thời gian |
| `numpy` | ≥ 1.21 | Tính toán số học, hàm sin/cos cho encoding thời gian |
| `scikit-learn` | ≥ 1.0 | Thuật toán Isolation Forest + StandardScaler |
| `python-evtx` | (tùy chọn) | Đọc file `.evtx` nhị phân nếu cần |
| `lxml` | (tùy chọn) | Parse XML trong file `.evtx` |

### 2.3. Cấu hình Audit Policy (trên máy cần giám sát)

```powershell
# Chạy với quyền Administrator
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
```

Sau đó cấu hình **SACL** (System Access Control List) trên thư mục cần giám sát:
- Chuột phải thư mục → Properties → Security → Advanced → Auditing
- Add → Everyone → Tích: Read, Write, Delete, Change Permissions

---

## 3. HƯỚNG DẪN CHẠY TỪNG BƯỚC

### Bước 1: Thu thập log (Nghiệp vụ thực tế)

```powershell
# Mở PowerShell với quyền Administrator
cd C:\Users\laptopJP.vn\Desktop\APT-opus

# Thu thập tất cả 13 Event IDs trong 7 ngày gần nhất
python collect_logs.py --days 7 --output collected_logs.json

# Nếu chưa bật Audit Policy, thêm flag --enable-audit:
python collect_logs.py --enable-audit --days 7 --output collected_logs.json

# Nếu muốn xuất CSV thay vì JSON:
python collect_logs.py --days 7 --output collected_logs.csv
```

**Kết quả**: File `collected_logs.json` chứa tất cả event.


Nếu bạn chưa có dữ liệu log thực tế từ hệ thống, bạn có thể tạo một tệp log giả lập lớn (bao gồm cả hành vi bình thường và các kịch bản tấn công APT) để thử nghiệm:

```powershell
# Chạy script để tạo tệp mock_logs_large.json
python generate_mock_logs.py
```


### Bước 2: Chạy phân tích UEBA

```powershell
# Chế độ tự động (auto-detect time window):
python main.py --file collected_logs.json

# Chỉ định cửa sổ thời gian cụ thể:
python main.py --file collected_logs.json --window 5min

# Điều chỉnh ngưỡng phát hiện (contamination):
python main.py --file collected_logs.json --contamination 0.03
```

### Bước 3: Đọc kết quả

Pipeline sẽ in ra màn hình Console các đầu ra tuần tự (Output) được chia thành 4 phần chính, cung cấp cái nhìn chi tiết cho SOC Analyst:

1. **STEP 1 — Parsing Log File**:
   *   Số lượng event parse thành công, phân bố các múi thời gian.
   *   Thống kê Event theo danh mục (File Access, Auth, Process, Persistence, Anti-Forensics) với Event ID tương ứng.
   *   Phân rã tỉ lệ Access Type (Đọc, Ghi, Xóa, v.v.).
   *   Cảnh báo số lượng event chứa các tiến trình nguy hiểm (LOLBin).
2. **STEP 2 — Feature Extraction**:
   *   Thông báo Window Time tối ưu được chọn (có thể tự động điều chỉnh nếu log bị ngắn).
   *   Tạo ra Ma trận Nặc danh Hành vi (Feature Vectors) và in ra 5 mẫu thử (vd: tổng số thao tác đọc, tổng số lần fail logon, số process tạo ra...).
3. **STEP 3 — Individual User Baseline Analysis (Isolation Forest)**:
   *   Phân rã ML model theo từng User (Train / Test split).
   *   **Output quan trọng nhất**: In ra điểm rủi ro bất thường (Anomaly Risk Score) từ 0-100.
   *   Nếu phát hiện bất thường an ninh, log sẽ cảnh báo cụ thể (🚨 Top Anomalous Windows).
   *   Đưa ra các phân tích sai lệch (Feature Deviation Analysis) để giải thích **lý do tại sao ML cho rằng thao tác này là bất thường** (Z-score vượt xa bao nhiêu so với baseline huấn luyện).
4. **PIPELINE SUMMARY**: Báo cáo tổng quan tóm tắt cả chu trình, cảnh báo tỉ lệ rủi ro chung hoặc an toàn bình thường.

### Bước 4: Chạy kiểm thử tự động

```powershell
python test_pipeline.py
# Kết quả mong đợi: 79/79 passed ✅
```

---

## 4. KIẾN TRÚC & THIẾT KẾ CHI TIẾT

### 4.1. Sơ đồ kiến trúc

```
┌─────────────────────────────────────────────────────────────┐
│                    WINDOWS FILE SERVER                       │
│  Security.evtx → 13 Event IDs (4624, 4663, 4688, 1102...)  │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌───────────────────────────────────────────────────────────┐
│  Module 1: collect_logs.py                                │
│  ┌─────────────────┐  ┌──────────────────┐                │
│  │ PowerShell       │  │ Python win32evtlog│               │
│  │ Get-WinEvent     │  │ (fallback)        │               │
│  └────────┬────────┘  └────────┬─────────┘                │
│           └─────────┬──────────┘                           │
│                     ▼                                      │
│            collected_logs.json / .csv                      │
└───────────────────────┬───────────────────────────────────┘
                        │
                        ▼
┌───────────────────────────────────────────────────────────┐
│  Module 2: file_server_log_parser.py                      │
│  • Đọc .evtx / .json / .csv                              │
│  • AccessMask bitwise decoding                            │
│  • LOLBin detection (34 binary patterns)                  │
│  • Standardize → DataFrame (13 Event IDs)                 │
└───────────────────────┬───────────────────────────────────┘
                        │
                        ▼
┌───────────────────────────────────────────────────────────┐
│  Module 3: ueba_feature_extractor.py                      │
│  • Tumbling time-window aggregation (GroupBy)              │
│  • 25 đặc trưng × 6 chiều hành vi                        │
│  └→ Volume, Context, Temporal, Auth, Process, Forensics   │
└───────────────────────┬───────────────────────────────────┘
                        │
                        ▼
┌───────────────────────────────────────────────────────────┐
│  Module 4: individual_baseline_model.py                   │
│  • StandardScaler normalization                           │
│  • Isolation Forest (200 trees, contamination=0.05)       │
│  • Anomaly Risk Score: 0–100                              │
│  • Feature Deviation Analysis (giải thích kết quả)        │
└───────────────────────┬───────────────────────────────────┘
                        │
                        ▼
┌───────────────────────────────────────────────────────────┐
│  Module 5: main.py                                        │
│  • Orchestration pipeline                                 │
│  • Auto-detect time window                                │
│  • Per-user analysis & risk scoring                       │
│  • Console output for SOC analyst                         │
└───────────────────────────────────────────────────────────┘
```

### 4.2. Luồng dữ liệu (Data Flow)

```
Raw Logs (.evtx/.json/.csv)
    │
    ▼ [Parser]
Standardized DataFrame (1 row = 1 event)
    │  Columns: TimeCreated, EventID, EventCategory,
    │           SubjectUserName, ObjectName, ProcessName,
    │           IpAddress, AccessMask, is_read, is_lolbin...
    │
    ▼ [Feature Extractor]
Feature Matrix (1 row = 1 user × 1 time_window)
    │  Columns: 25 numeric features
    │  Example: total_read_ops=120, failed_logon=0,
    │           off_hour_ratio=0.0, lolbin_count=0...
    │
    ▼ [Isolation Forest]
Risk Scores (1 row = 1 user × 1 time_window)
    │  anomaly_score: 0–100
    │  is_anomaly: True/False
    │
    ▼ [Output]
Console report + Feature deviation analysis
```

---

## 5. CHI TIẾT TỪNG MODULE

### 5.1. `collect_logs.py` — Thu thập Windows Event Log

**Mục đích**: Truy xuất Event Log từ hệ điều hành Windows và xuất ra file JSON/CSV.

**Cơ chế hoạt động**:
1. Tạo script PowerShell sử dụng `Get-WinEvent` với `FilterHashtable`
2. Query chỉ các Event ID cần thiết (tối ưu tại API level)
3. Parse XML của từng event để trích xuất các trường dữ liệu
4. Xuất ra JSON/CSV với encoding UTF-8

**Tham số quan trọng**:
| Tham số | Mặc định | Ý nghĩa |
|---|---|---|
| `--days` | 7 | Số ngày log thu thập |
| `--output` | collected_logs.json | Đường dẫn file xuất |
| `--enable-audit` | Off | Tự động bật Audit Policy |
| `--setup-audit` | Off | Hướng dẫn cấu hình SACL |

---

### 5.2. `file_server_log_parser.py` — Phân tích Log

**Mục đích**: Đọc file log và chuẩn hóa thành DataFrame thống nhất.

#### 13 Event IDs được xử lý:

| Event ID | Tên | Pha APT | Ý nghĩa cho an ninh |
|---|---|---|---|
| **4624** | Successful Logon | Lateral Movement | Phát hiện di chuyển ngang qua LogonType 3/10 |
| **4625** | Failed Logon | Initial Access | Tấn công brute-force / password spraying |
| **4648** | Explicit Credential | Credential Access | Phát hiện Pass-the-Hash, RunAs abuse |
| **4656** | Handle Requested | Reconnaissance | Yêu cầu truy cập trước khi đọc/ghi |
| **4658** | Handle Closed | — | Theo dõi session hoàn chỉnh |
| **4660** | Object Deleted | Anti-Forensics | Xóa bằng chứng, dọn dẹp công cụ |
| **4663** | Object Access | Data Staging | **Core**: đọc/ghi/xóa file — staging data |
| **4688** | Process Created | Execution | Phát hiện LOLBin (PowerShell, certutil...) |
| **4698** | Scheduled Task | Persistence | Tạo tác vụ lên lịch để duy trì access |
| **5140** | Share Accessed | Lateral Movement | Truy cập chia sẻ mạng (session level) |
| **5145** | File Share Detail | Lateral Movement | **Core**: truy cập file qua SMB |
| **7045** | Service Installed | Persistence | Cài đặt service để duy trì access |
| **1102** | Log Cleared | Anti-Forensics | Xóa audit log — **dấu hiệu nghiêm trọng** |

#### AccessMask Bitwise Decoding:

Windows biểu diễn quyền truy cập file dưới dạng **bitmask** — một giá trị hex chứa nhiều quyền đồng thời.

```
Ví dụ: AccessMask = 0x12019F

Binary:  0001 0010 0000 0001 1001 1111
                                    ├─ Bit 0 (0x1):  ReadData      ✅
                                   ├── Bit 1 (0x2):  WriteData     ✅
                                  ├─── Bit 2 (0x4):  AppendData    ✅
                                 ├──── Bit 3 (0x8):  ReadEA        ✅
                                ├───── Bit 4 (0x10): WriteEA       ✅
                        ...
         ├──── Bit 16 (0x10000): DELETE                             ✅

Giải mã bằng phép AND bitwise:
  0x12019F & 0x1     = 0x1     ≠ 0 → ReadData  = True
  0x12019F & 0x2     = 0x2     ≠ 0 → WriteData = True
  0x12019F & 0x10000 = 0x10000 ≠ 0 → DELETE    = True
  0x12019F & 0x40000 = 0x0     = 0 → WRITE_DAC = False
```

> **Tại sao không dùng string matching?** Vì `"0x1"` là substring của `"0x10000"` — string matching sẽ cho kết quả sai. Bitwise AND là phương pháp **duy nhất chính xác**.

#### LOLBin Detection (Living off the Land Binaries):

Hệ thống nhận diện **34 binary** phổ biến bị kẻ tấn công lạm dụng:

```
powershell.exe, cmd.exe, wscript.exe, cscript.exe, mshta.exe,
wmic.exe, certutil.exe, bitsadmin.exe, schtasks.exe, sc.exe,
net.exe, psexec.exe, rundll32.exe, regsvr32.exe, msiexec.exe,
curl.exe, 7z.exe, rar.exe, procdump.exe, ntdsutil.exe, ...
```

Khi phát hiện process nào trong danh sách này → gán flag `is_lolbin = True`.

---

### 5.3. `ueba_feature_extractor.py` — Trích xuất Đặc trưng

**Mục đích**: Chuyển đổi event-level data thành feature vectors theo cửa sổ thời gian.

#### Cơ chế Tumbling Time Window:

```
Timeline:  |---1h---|---1h---|---1h---|---1h---|
Event:     eeeeee   eeeee    eeeeeeee  eeee    
Feature:   [vec_1]  [vec_2]  [vec_3]   [vec_4] 

Mỗi vector = 25 đặc trưng cho 1 user trong 1 cửa sổ thời gian
```

#### 25 Đặc trưng × 6 Chiều:

**Chiều 1: Volume / Velocity (Khối lượng & Tốc độ)**

| Feature | Mô tả | Ý nghĩa APT |
|---|---|---|
| `total_read_operations` | Tổng lần đọc file | Đọc hàng loạt = data staging |
| `total_write_operations` | Tổng lần ghi file | Ghi bất thường = payload drop |
| `total_delete_operations` | Tổng lần xóa | Xóa hàng loạt = anti-forensics |
| `total_events` | Tổng event trong window | Đặc trưng cho mức độ hoạt động |
| `read_write_ratio` | Tỷ lệ đọc/ghi | Đọc nhiều hơn ghi = thu thập dữ liệu |

**Chiều 2: Variety / Context (Đa dạng & Ngữ cảnh)**

| Feature | Mô tả | Ý nghĩa APT |
|---|---|---|
| `distinct_files_accessed` | Số file khác nhau | Truy cập nhiều file = quét dò |
| `distinct_processes_used` | Số process khác nhau | Nhiều tool = lateral movement |
| `admin_share_access_count` | Truy cập admin share (C$, ADMIN$) | Admin share = lateral movement |
| `lolbin_event_count` | Số event liên quan LOLBin | LOLBin = kỹ thuật LotL |

**Chiều 3: Spatio-Temporal (Không gian & Thời gian)**

| Feature | Mô tả | Ý nghĩa APT |
|---|---|---|
| `off_hour_activity_ratio` | Tỷ lệ hoạt động ngoài giờ | APT thường hoạt động ngoài giờ |
| `hour_sin`, `hour_cos` | Mã hóa vòng tròn giờ | Tránh vấn đề 23h → 0h (khoảng cách 1, không phải 23) |

**Chiều 4: Authentication (Xác thực)**

| Feature | Mô tả | Ý nghĩa APT |
|---|---|---|
| `successful_logon_count` | Số lần đăng nhập thành công | Lateral movement |
| `failed_logon_count` | Số lần đăng nhập thất bại | Brute-force / password spraying |
| `failed_logon_ratio` | Tỷ lệ thất bại | Ratio cao = tấn công |
| `distinct_logon_source_ips` | Số IP nguồn khác nhau | Nhiều IP = credential sharing |
| `explicit_credential_count` | Sử dụng credential rõ ràng (4648) | Pass-the-Hash |

**Chiều 5: Process Execution (Thực thi tiến trình)**

| Feature | Mô tả | Ý nghĩa APT |
|---|---|---|
| `new_process_count` | Số tiến trình mới | Nhiều process = trinh sát/thực thi |
| `suspicious_process_count` | Tiến trình đáng ngờ (LOLBin) | Sử dụng công cụ hệ thống |
| `distinct_parent_processes` | Số parent process khác nhau | Đa dạng = process injection |

**Chiều 6: Persistence & Anti-Forensics (Duy trì & Chống Forensics)**

| Feature | Mô tả | Ý nghĩa APT |
|---|---|---|
| `scheduled_task_created_count` | Tạo scheduled task | Persistence mechanism |
| `service_installed_count` | Cài service mới | Persistence mechanism |
| `audit_log_cleared_count` | Xóa audit log | **Dấu hiệu rất nghiêm trọng** |
| `object_deleted_count` | Xóa object (file) | Dọn dẹp bằng chứng |
| `share_session_count` | Phiên truy cập share | Network enumeration |
| `distinct_shares_accessed` | Số share khác nhau | Quét dò chia sẻ mạng |

---

### 5.4. `individual_baseline_model.py` — Phát hiện Bất thường

**Mục đích**: Học mô hình baseline cho từng user, phát hiện hành vi lệch khỏi baseline.

**Quy trình**:
1. **StandardScaler**: Chuẩn hóa 25 đặc trưng về cùng thang đo (mean=0, std=1)
2. **Isolation Forest**: Huấn luyện trên dữ liệu lịch sử
3. **Risk Score**: Chuyển raw score → thang 0–100
4. **Feature Importance**: Phân tích z-deviation để giải thích

---

### 5.5. `generate_mock_logs.py` — Khởi tạo Dữ liệu Giả lập (Mock Logs)

**Mục đích**: Tự động sinh ra khối lượng lớn dữ liệu log giả lập (mock data) mô phỏng lại hệ thống, qua đó phục vụ quá trình phát triển, kiểm thử, và đánh giá hiệu năng của thuật toán phát hiện (UEBA) khi chưa có log hoạt động thật.

**Cơ chế hoạt động**:
1. **Mô phỏng hành vi bình thường**: Tạo ngẫu nhiên hàng chục nghìn log (Event 4663, 4624, 4688, 5140) lặp lại đều đặn trong giờ hành chính cho các user để tạo ra baseline sạch.
2. **Mô phỏng tấn công APT**: Bơm một chuỗi các event của kịch bản tấn công hoàn chỉnh (Brute-force → Logon → Pass-the-Hash → LOLBin → Data Staging → Xóa Log) cho một user (đã bị chiếm quyền) vào thời điểm ngoài giờ hành chính (2h sáng).
3. Tổng hợp, sắp xếp lượng event khổng lồ đó theo thời gian thực và ghi vào file đầu ra `mock_logs_large.json`.

---

### 5.6. `test_pipeline.py` — Kiểm thử Tự động (Automated Test Pipeline)

**Mục đích**: Chạy kiểm tra tổng thể (End-to-End) tính chính xác của toàn bộ quy trình, đảm bảo hệ thống bắt sóng được tấn công và code không bị bug.

**Cơ chế hoạt động**: Tập lệnh này thực thi 5 bài tổ hợp kiểm thử (Test Suite) chạy tự động:
1. **AccessMask Decoding**: Check việc phân tách quyền truy cập Bitwise AND của tool Parser.
2. **Feature Extraction**: Đảm bảo Tool trích xuất đầy đủ 25 đặc tính đúng với event log.
3. **Attack Chain Features**: Xác nhận dữ liệu sinh ra bởi kịch bản tấn công (từ *generate_mock_logs*) vọt lên vượt ngưỡng được bắt lại ở các Feature (vd. số lượng LOLbin chạy, số tài khoản failed logon, off-hour v.v).
4. **Machine Learning Model**: Huấn luyện Model bằng tệp "Sạch", sau đó feed tệp "Tấn công" vào Model nhằm kiểm định chắc chắn Anomaly Score đối với APT Attack là điểm rất cao (Max >= 80 điểm) và cao hơn hẳn mức bình quân.
5. **Edge Cases & Error Handling**: Ném vào các trường hợp dị thường (không có file đọc, DF rỗng, dataset không đủ) xem hệ thống có log ra Exception tử tế hay làm App bị crash.

---

### 5.7. `main.py` — File Thực thi Trung tâm (Orchestration Pipeline)

**Mục đích**: Đây là entry point (điểm đầu vào) điều phối toàn bộ luồng hoạt động của hệ thống phân tích hành vi người dùng (UEBA - Phase 1), liên kết tất cả module lẻ tẻ từ khâu đọc log thô cho đến khi hiển thị cảnh báo rủi ro cuối cùng lên Console để phục vụ nhóm SOC Analyst.

**Cơ chế hoạt động**:
1. **Tiếp nhận dữ liệu**: Nhận đường dẫn file log thô qua lệnh chạy (CLI argument `--file`) hoặc nhận nhập trực tiếp từ người dùng. Hỗ trợ đa định dạng `.evtx` nguyên gốc, json (qua ConvertTo-Json) hoặc `.csv`.
2. **Kích hoạt Parser**: Khởi tạo cấu hình và gọi tới `FileServerLogParser` để parse khối lượng dữ liệu khổng lồ nhằm trích chiết Event ID quan trọng, dịch mã AccessMask và đánh cờ cho LOLBin.
3. **Tự động tinh chỉnh Window**: Thu thập thông tin tổng quá mức thời gian của log đầu vào. Nếu span quá ngắn cho một cửa sổ 1 giờ để học ML (Machine learning), main.py chủ động giảm fallback (từ `1h` → `15min`, `5min`, `2min`...) sao cho vừa đủ vector để huấn luyện.
4. **Nhồi nặn Đặc trưng**: Khởi chạy `UEBAFeatureExtractor` để dịch log thô thành bản đồ ma trận (Matrix) của tất cả người dùng trong tập tham chiếu.
5. **Huấn luyện và Check Anomaly**: Cấp phát vòng lặp cho từng User (tách biệt theo Baseline từng cá nhân). Nếu dữ liệu lớn, sẽ cắt ra 80% train / 20% test, còn nếu sát mức tối thiểu sẽ chuyển qua "Single-batch mode", train toàn bộ và score toàn bộ. Tại đây, gọi tới `IndividualBaselineModel` để chấm điểm và phát hiện hành vi vọt lên khỏi đường đồ thị nền. Đồng thời, tự giải thích (Feature Deviation) do feature nào tăng đột ngột theo phương pháp z-core. 
6. **Tổng kết chu trình**: Tập hợp, in và hiển thị Console trực quan, rõ ràng kết quả cuối cùng một cách sinh động, bao gồm tất tần tật từ khâu Parsing đến Machine Learning, đặc biệt xoáy sâu vào "Anomalous Activity" (Cảnh báo các cuộc tấn công chưa định hình).

---

## 6. GIẢI THÍCH THUẬT TOÁN ISOLATION FOREST

### 6.1. Tại sao chọn Isolation Forest?

| Tiêu chí | Z-Score | LOF | Isolation Forest ✅ |
|---|---|---|---|
| Giả định phân phối | Gaussian | Không | **Không** |
| Xử lý đa chiều (25 features) | Kém | TB | **Tốt** |
| Độ phức tạp | O(n) | O(n²) | **O(n·log(n))** |
| Giải thích được | Có | Khó | **Có (path length)** |
| Hoạt động tốt với ít dữ liệu | Kém | Kém | **Tốt** |

### 6.2. Nguyên lý Isolation Forest

**Ý tưởng cốt lõi**: Điểm bất thường (anomaly) **"ít và khác biệt"** → dễ bị **cô lập** bằng phép chia ngẫu nhiên.

```
       Cây quyết định ngẫu nhiên (1 trong 200 cây):

       Bước 1: Chọn ngẫu nhiên 1 feature (vd: total_read)
       Bước 2: Chọn ngẫu nhiên 1 ngưỡng (vd: 500)
       Bước 3: Chia: < 500 (trái) | >= 500 (phải)
       Bước 4: Lặp lại cho đến khi mỗi điểm bị cô lập

       Điểm BÌNH THƯỜNG:  Cần nhiều bước chia → path length DÀI
       Điểm BẤT THƯỜNG:   Cần ít bước chia    → path length NGẮN

       Path length trung bình qua 200 cây → Anomaly Score
```

### 6.3. Score Normalization (0–100)

```python
# Raw decision_function: cao = bình thường, thấp = bất thường
# Đảo ngược và scale:

anomaly_score = (score_max - raw_score) / (score_max - score_min) × 100

# score_max = điểm bình thường nhất trong training → map thành 0
# score_min = điểm bất thường nhất trong training → map thành ~95
# Ngoài phạm vi training → clip tại 0 hoặc 100
```

### 6.4. Tham số quan trọng

| Tham số | Giá trị | Giải thích |
|---|---|---|
| `n_estimators` | 200 | Số cây trong rừng. Nhiều hơn → ổn định hơn |
| `contamination` | 0.05 | Tỷ lệ bất thường kỳ vọng (5% training data) |
| `max_samples` | auto | Số mẫu cho mỗi cây (auto = min(256, n_samples)) |
| `random_state` | 42 | Seed cho reproducibility |

---

## 7. KẾT QUẢ KIỂM THỬ

### 7.1. Automated Tests: 79/79 ✅

| Bộ test | Số test | Nội dung |
|---|---|---|
| AccessMask Decoding | 16 | Kiểm tra bitwise AND, edge cases |
| Feature Extraction | 35 | Kiểm tra 25 đặc trưng, off-hour ratio |
| Attack Chain Detection | 12 | Mô phỏng chuỗi tấn công APT đầy đủ |
| Isolation Forest | 11 | Normal vs Attack scoring |
| Edge Cases | 5 | Empty data, error handling |

### 7.2. Mô phỏng chuỗi tấn công (Test Suite 3)

Bộ test tạo dữ liệu mô phỏng **7 pha tấn công APT**:

```
Pha 1: Brute-force     → 15 failed logon từ IP 185.220.101.42
Pha 2: Truy cập        → 1 successful logon (sau brute-force thành công)
Pha 3: Credential abuse → 3 explicit credential (Pass-the-Hash)
Pha 4: LOLBin execution → powershell.exe, certutil.exe, wmic.exe
Pha 5: Data staging     → 50 file read qua admin share (C$)
Pha 6: Persistence      → 1 scheduled task + 1 service
Pha 7: Anti-forensics   → 1 audit log cleared + 5 file deleted
```

**Kết quả phát hiện**:
- `failed_logon_count = 15` ✅ Đúng
- `failed_logon_ratio = 0.94` ✅ Đúng (15/16)
- `explicit_credential_count = 3` ✅ Đúng
- `suspicious_process_count > 0` ✅ Phát hiện LOLBin
- `scheduled_task = 1`, `service_installed = 1` ✅
- `audit_log_cleared = 1`, `object_deleted = 5` ✅
- `off_hour_ratio = 1.0` ✅ (tấn công lúc 2h sáng)
- **Attack score (89.0) >> Normal score (39.4)** ✅

### 7.3. Real Data Validation

Chạy trên log thực (16,792 events, 4 users):
- Auto-adjusted window: 1h → 2min
- Phát hiện 358 LOLBin events (phát hiện thực!)
- Normal desktop activity → No anomalies ✅

---

## 8. CÂU HỎI PHẢN BIỆN THƯỜNG GẶP & GỢI Ý TRẢ LỜI

### Q1: "Tại sao chọn Isolation Forest thay vì Deep Learning?"

**Trả lời**: 
- Deep Learning (LSTM, Autoencoder) cần **hàng triệu mẫu** huấn luyện — trong thực tế, một user chỉ có vài trăm đến vài nghìn time-window vectors.
- Isolation Forest hoạt động tốt với **small datasets** (chỉ cần ≥ 5 mẫu).
- Không cần GPU, không cần infrastructure phức tạp → **phù hợp triển khai thực tế trong SOC**.
- Quan trọng nhất: Isolation Forest có **tính giải thích cao** (explainability) — SOC analyst cần biết *tại sao* cảnh báo được đưa ra, không chỉ biết *có* cảnh báo.

### Q2: "Hệ thống có phát hiện được zero-day attack không?"

**Trả lời**: 
- **Có**, vì hệ thống không dựa trên signature mà dựa trên **behavioral anomaly**. Ngay cả zero-day cũng phải thể hiện qua hành vi: đọc nhiều file bất thường, sử dụng LOLBin, hoạt động ngoài giờ, v.v.
- Tuy nhiên, nếu kẻ tấn công hoạt động **giống hệt** pattern bình thường của user → khó phát hiện. Đây là giới hạn cố hữu của phương pháp UEBA.

### Q3: "False positive rate là bao nhiêu?"

**Trả lời**: 
- Với `contamination=0.05`, model kỳ vọng ~5% training data là anomaly.
- Trong test: Normal data → 4/70 windows flagged (5.7%) — đúng với contamination.
- Attack data → 100% detection rate (1/1 flagged).
- Thực tế: Admin có thể **điều chỉnh contamination** (0.01 → bảo thủ hơn, 0.1 → nhạy hơn).

### Q4: "AccessMask decoding tại sao phải dùng bitwise AND?"

**Trả lời**: 
- Vì AccessMask là **bitmask** — một giá trị hex chứa **nhiều quyền đồng thời**.
- Ví dụ: `0x10003` = ReadData (0x1) | WriteData (0x2) | DELETE (0x10000).
- Nếu dùng string matching: "0x1" match `"0x10003"` → **sai** (nghĩ là chỉ có Read).
- Bitwise AND: `0x10003 & 0x1 = 1 ≠ 0` → ReadData=True — **đúng**.

### Q5: "Tại sao mã hóa thời gian bằng sin/cos?"

**Trả lời**: 
- Giờ là đại lượng **tuần hoàn**: 23h → 0h khoảng cách là 1 giờ, không phải 23 giờ.
- Encoding tuyến tính (hour=0,1,...,23) → model nghĩ 23h cách 0h rất xa.
- Sin/Cos encoding: `hour_sin = sin(2π × hour/24)`, `hour_cos = cos(2π × hour/24)` → 23h và 0h **gần nhau** trên mặt phẳng sin/cos.

### Q6: "Contamination = 0.05 lấy từ đâu?"

**Trả lời**: 
- 0.05 là giá trị phổ biến trong literature (ngầm định 5% dữ liệu huấn luyện có thể chứa noise/anomaly).
- Thực tế có thể điều chỉnh: SOC team theo dõi false positive rate và tăng/giảm contamination.
- 0.01 nếu muốn ít cảnh báo hơn (ít false positive, nhưng có thể miss attack).
- 0.10 nếu muốn nhạy hơn (nhiều cảnh báo, nhiều false positive hơn).

### Q7: "Làm sao scale system lên enterprise?"

**Trả lời**: 
- **Horizontal scaling**: Mỗi user train model riêng → có thể parallel trên nhiều core/machine.
- **Scheduled collection**: Chạy `collect_logs.py` theo cron job / Task Scheduler.
- **Database integration**: Thay file JSON bằng Elasticsearch hoặc SIEM.
- **Dashboard**: Tích hợp với Grafana hoặc web dashboard (Phase tiếp theo).
- **SIEM integration**: Export kết quả dạng JSON → feed vào Splunk/ELK.

### Q8: "StandardScaler tại sao quan trọng?"

**Trả lời**: 
- `total_read_operations` có thể từ 0 đến 10,000+ nhưng `off_hour_ratio` chỉ từ 0 đến 1.
- Không scale → Isolation Forest sẽ **chỉ chia theo total_read** (feature có magnitude lớn) → bỏ qua các feature nhỏ nhưng quan trọng.
- StandardScaler: `x_scaled = (x - mean) / std` → tất cả features có mean=0, std=1 → Isolation Forest chia đều trên tất cả dimensions.

---

## 📁 CẤU TRÚC THƯ MỤC DỰ ÁN

```
APT-opus/
├── collect_logs.py           # Thu thập Windows Event Log
├── file_server_log_parser.py # Phân tích & chuẩn hóa log
├── ueba_feature_extractor.py # Trích xuất đặc trưng hành vi
├── individual_baseline_model.py  # Isolation Forest model
├── main.py                   # Entry point — chạy pipeline
├── test_pipeline.py          # Khung kiểm thử tự động hệ thống toàn diện
├── generate_mock_logs.py     # Script tạo lượng lớn dữ liệu log giả lập
├── requirements.txt          # Thư viện Python
├── collected_logs.json       # Log đã thu thập (output)
└── collect_events.ps1        # PowerShell script (auto-generated)
```
