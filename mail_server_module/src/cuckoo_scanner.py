import requests
import time
import os

# Cấu hình địa chỉ API của máy chủ Cuckoo Sandbox
# Nếu Cuckoo cài trên cùng máy với script này thì dùng localhost
CUCKOO_API_URL = "http://localhost:8090"

def submit_to_cuckoo(file_path):
    """Gửi file vào Cuckoo Sandbox để phân tích"""
    print(f"[*] Đang đẩy file '{os.path.basename(file_path)}' vào Cuckoo Sandbox...")
    submit_url = f"{CUCKOO_API_URL}/tasks/create/file"
    
    try:
        with open(file_path, "rb") as sample:
            files = {"file": (os.path.basename(file_path), sample)}
            response = requests.post(submit_url, files=files)
            
        if response.status_code == 200:
            task_id = response.json().get("task_id")
            print(f"    [+] Gửi thành công! Cuckoo Task ID: {task_id}")
            return task_id
        else:
            print(f"    [!] Lỗi khi gửi file: HTTP {response.status_code}")
            return None
    except requests.exceptions.ConnectionError:
        print("    [!] Không thể kết nối đến Cuckoo API. Hãy đảm bảo Cuckoo Server đang chạy (cổng 8090).")
        return None
    except Exception as e:
        print(f"    [!] Lỗi hệ thống: {str(e)}")
        return None

def wait_for_cuckoo_report(task_id, timeout_minutes=5):
    """Chờ Cuckoo phân tích xong (thường mất 2-3 phút cho 1 máy ảo chạy)"""
    print(f"[*] Đang chờ Cuckoo phân tích hành vi (Task {task_id})...")
    status_url = f"{CUCKOO_API_URL}/tasks/view/{task_id}"
    report_url = f"{CUCKOO_API_URL}/tasks/report/{task_id}"
    
    start_time = time.time()
    
    while True:
        # Kiểm tra xem đã quá thời gian chờ (timeout) chưa
        if time.time() - start_time > (timeout_minutes * 60):
            return {"status": "Error", "message": "Quá thời gian chờ Sandbox phân tích."}
            
        try:
            status_res = requests.get(status_url)
            if status_res.status_code == 200:
                status = status_res.json().get("task", {}).get("status")
                
                if status == "reported":
                    print("    [+] Phân tích hoàn tất! Đang tải báo cáo...")
                    # Khi trạng thái là reported, tiến hành lấy bản báo cáo JSON
                    report_res = requests.get(report_url)
                    report_data = report_res.json()
                    
                    # Lấy điểm rủi ro (Score từ 0 đến 10)
                    score = report_data.get("info", {}).get("score", 0)
                    
                    return {
                        "status": "Malicious" if score >= 4.0 else "Clean/Suspicious",
                        "engine": "Cuckoo Sandbox (Dynamic)",
                        "cuckoo_score": score,
                        "message": f"Điểm hành vi: {score}/10. Tham khảo báo cáo chi tiết trên giao diện Cuckoo."
                    }
                
                elif status == "failed":
                    return {"status": "Error", "message": "Cuckoo phân tích thất bại (Lỗi máy ảo/Mạng)."}
                
            # Đợi 15 giây trước khi hỏi lại trạng thái
            time.sleep(15)
            
        except Exception as e:
            return {"status": "Error", "message": f"Lỗi khi lấy báo cáo: {str(e)}"}

# Test độc lập
if __name__ == "__main__":
    # Thay bằng đường dẫn file thực tế trong thư mục quarantine của bạn
    test_file = "../data/quarantine_attachments/sample.pdf"
    if os.path.exists(test_file):
        task_id = submit_to_cuckoo(test_file)
        if task_id:
            report = wait_for_cuckoo_report(task_id)
            print(report)